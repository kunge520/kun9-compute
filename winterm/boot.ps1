# Windows VM boot script: the RDP listener and sshd for Cloudflare's browser-rendered desktop and
# terminal, self-configuring from repo secrets.
# 2026-10-14: ttyd is gone. Two browser surfaces remain, both Cloudflare-native: clientless RDP (the
# listener below) and clientless SSH (sshd, reached through the tunnel ingress ssh.kun9.ccwu.cc ->
# ssh://localhost:22). Both take the same fixed password; SSH's account is named after the owner's
# email prefix because the browser forces that username. The named tunnel is here for both: the
# Access RDP app can only dial a private IP this tunnel routes to, and the SSH ingress is served by
# the same connector.
# Kept out of the workflow YAML on purpose: GitHub refuses to parse a step whose run block is
# over the 21000-character expression limit (measured: Exceeded max expression length 21000),
# which kills the run before any job exists and names the workflow only by its path.
#
# Windows browser RDP inside a GitHub-hosted VM, on the PUBLIC repo on purpose: standard
# GitHub-hosted runners are free for public repositories for every OS (docs: "The use of standard
# GitHub-hosted runners is free: In public repositories"), and the 2x/10x multipliers only apply to
# PRIVATE repo minutes -- so a 6 h Windows session costs nothing here but would eat 720 of the 2000
# monthly minutes in kun9-fleet.
#
# Hard-won rules encoded here:
# - publish state as a COMMIT, not a log line: the job-log endpoint returns BlobNotFound while the
#   step runs, so logs can only be read after the session is already over.
# - start the daemon and sleep in the SAME step: a step boundary is where Actions reaps orphans.
# - cloudflared's URL does not reach shell-redirected stdout on Windows; use --logfile.
# - cloudflared global flags (--logfile, --protocol) must come BEFORE `run`: after it the process
#   exits instantly with "Incorrect Usage", which from the outside looks exactly like a bad tunnel
#   token. --log-level is a root flag and is not accepted by `tunnel` either.
# - git identity must be set before ANY commit, including the failure path.
# - the browser shows "Code 4 / WSA 10013 permission denied" when the connector dials this VM's own
#   tunnel address: that hairpin is refused at the socket layer. The desktop answers on a fixed
#   loopback alias (10.1.0.9) instead, which the local stack delivers without entering the tunnel.
# - the browser shows "Code 2" when the credential does not work. Two traps: this image ships no
#   account named `administrator` (its RID-500 account is `runneradmin`), and a refused `net user`
#   set leaves the account passwordless. Renaming runneradmin is NOT the fix -- it takes the name the
#   job runs under and every later Get-Net* call answers nothing -- so a separate account is created,
#   with the password-complexity policy relaxed only if the plain set fails.
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$work = $PWD.Path
$ref = $env:GITHUB_REF_NAME
$CTL = 'https://ctl.kun9.ccwu.cc'
git config user.name winterm
git config user.email winterm@users.noreply.github.com

$tok = (Get-Content trigger.winterm -Raw) -split '\s+'
$MIN = 0; [void][int]::TryParse($tok[0], [ref]$MIN)
if ($MIN -lt 5) { $MIN = 5 }
if ($MIN -gt 350) { $MIN = 350 }
$SECS = $MIN * 60

function Tail([string]$f, [int]$n) {
  if (Test-Path $f) { return (((Get-Content $f -Tail $n -EA SilentlyContinue) -join ' | ') -replace "`r", '') }
  return ''
}
function Rdp-Diag {
  # Read-only facts about the built-in RDP listener. The browser-RDP path needs a private IP the
  # connector can dial plus the settings the image already has, so measure before changing keys.
  try {
    $l = @(Get-NetTCPConnection -State Listen -LocalPort 3389 -EA SilentlyContinue | ForEach-Object { '' + $_.LocalAddress })
    $ts = (Get-Service TermService -EA SilentlyContinue).Status
    $deny = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -EA SilentlyContinue).fDenyTSConnections
    $ws = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
    $nla = (Get-ItemProperty -Path $ws -Name UserAuthentication -EA SilentlyContinue).UserAuthentication
    $sec = (Get-ItemProperty -Path $ws -Name SecurityLayer -EA SilentlyContinue).SecurityLayer
    $prt = (Get-ItemProperty -Path $ws -Name PortNumber -EA SilentlyContinue).PortNumber
    $ips = @(Get-NetIPAddress -AddressFamily IPv4 -EA SilentlyContinue | Where-Object { $_.IPAddress -notlike '169.*' -and $_.IPAddress -ne '127.0.0.1' } | ForEach-Object { $_.IPAddress })
    return ('ts=' + $ts + ' listen3389=' + ($l -join '+') + ' deny=' + $deny + ' nla=' + $nla + ' sec=' + $sec + ' port=' + $prt + ' ips=' + ($ips -join '+'))
  } catch { return 'diag-failed: ' + $_.Exception.Message }
}
function Probe-Port([string]$ip, [int]$port) {
  # Reproduces the connector's own connect() so the heartbeat says whether the refusal is this
  # host's socket layer or something cloudflared does differently.
  if (-not $ip) { return 'skip' }
  try {
    $c = New-Object Net.Sockets.TcpClient
    $iar = $c.BeginConnect($ip, $port, $null, $null)
    if (-not $iar.AsyncWaitHandle.WaitOne(4000)) { $c.Close(); return 'timeout' }
    $c.EndConnect($iar); $c.Close()
    return 'ok'
  } catch {
    $e = $_.Exception
    if ($e.InnerException) { $e = $e.InnerException }
    return 'err:' + $e.SocketErrorCode
  }
}
function VnetIp {
  # The fallback address Access dials if the loopback alias cannot be made: whatever this machine
  # currently holds inside the tunnel's virtual network. Handed out per boot, so read it, never
  # remember it.
  try {
    foreach ($n in @(Get-NetAdapter -EA SilentlyContinue | Where-Object { ("$($_.Name) $($_.InterfaceDescription)") -match 'loudflare|WARP' })) {
      $a = @(Get-NetIPAddress -InterfaceIndex $n.ifIndex -AddressFamily IPv4 -EA SilentlyContinue | ForEach-Object { $_.IPAddress })
      if ($a.Count) { return $a[0] }
    }
    $b = @(Get-NetIPAddress -AddressFamily IPv4 -EA SilentlyContinue | Where-Object { $_.IPAddress -like '10.1.0.*' } | ForEach-Object { $_.IPAddress })
    if ($b.Count) { return $b[0] }
  } catch { }
  return ''
}
function Test-Logon([string]$nm, [string]$pw, [int]$type = 2) {
  # The browser can only say "the server rejected your username or password", which cannot tell a
  # wrong password from an account set that silently failed. Ask Windows directly with the same
  # credential the form sends, so the heartbeat names the real reason (1326 bad password, 1327 no
  # password allowed over the network, 1331 disabled, 1909 locked). Type 2 is an interactive logon
  # (what the RDP form exercises); type 3 is a network logon, which is what sshd's password auth
  # goes through -- so the SSH account is checked with 3 before the browser is ever trusted to it.
  try {
    Add-Type -Namespace WM -Name Logon -EA SilentlyContinue -MemberDefinition @'
[DllImport("advapi32.dll",SetLastError=true,CharSet=CharSet.Unicode)] public static extern bool LogonUser(string u,string d,string p,int t,int pr,out System.IntPtr tok);
[DllImport("kernel32.dll",SetLastError=true)] public static extern bool CloseHandle(System.IntPtr h);
'@
    $tok = [IntPtr]::Zero
    if ([WM.Logon]::LogonUser($nm, '.', $pw, $type, 0, [ref]$tok)) {
      [void][WM.Logon]::CloseHandle($tok)
      return 'ok'
    }
    return 'err=' + [Runtime.InteropServices.Marshal]::GetLastWin32Error()
  } catch { return 'ex=' + $_.Exception.Message }
}
function Add-RdpAlias {
  # The desktop has to answer on an address the connector can actually dial. Dialing this machine's
  # own tunnel address (the 10.1.0.x the cloudflared adapter holds) is refused at the socket layer --
  # that adapter does not hairpin -- and the browser shows that as "WSA 10013 permission denied". An
  # address on the loopback adapter is delivered by the local stack instead, so the dial never enters
  # the tunnel. Fixed, not per-boot, so the Access target stops going stale.
  $alias = '10.1.0.9'
  try {
    $have = @(Get-NetIPAddress -IPAddress $alias -AddressFamily IPv4 -EA SilentlyContinue).Count
    if (-not $have) {
      $lo = (Get-NetIPAddress -IPAddress '127.0.0.1' -AddressFamily IPv4 -EA SilentlyContinue).InterfaceIndex
      if ($lo) { New-NetIPAddress -InterfaceIndex $lo -IPAddress $alias -PrefixLength 32 -EA SilentlyContinue | Out-Null }
    }
    if (-not @(Get-NetIPAddress -IPAddress $alias -AddressFamily IPv4 -EA SilentlyContinue).Count) {
      & netsh interface ipv4 add address 'Loopback Pseudo-Interface 1' $alias 255.255.255.255 2>&1 | Out-Null
    }
    # Dialing is the check that matters: the WMI-only existence test can flake on a boot where the
    # CIM providers are still settling, while the socket is what the connector actually uses.
    $d = Probe-Port $alias 3389
    $script:RDPIP = if ($d -eq 'ok') { $alias } else { VnetIp }
    return ('alias=' + $alias + ' ' + $d)
  } catch { $script:RDPIP = VnetIp; return 'alias-failed: ' + $_.Exception.Message }
}
function Set-Account([string]$nm, [string]$pw) {
  # A local account the browser forms can log in with. A short numeric credential is refused by the
  # image's complexity policy, and a refused create or set leaves the account with no usable
  # password -- which the browser can only report as a plain credential rejection. So retry once
  # with the policy relaxed.
  $log = @()
  if (-not @(Get-LocalUser -Name $nm -EA SilentlyContinue).Count) {
    & net user $nm $pw /add 2>&1 | Out-Null
    $log += ('add=' + $LASTEXITCODE)
  }
  & net user $nm $pw 2>&1 | Out-Null
  $log += ('set=' + $LASTEXITCODE)
  if ($LASTEXITCODE -ne 0) {
    & net accounts /minpwlen:0 2>&1 | Out-Null
    $cfg = 'C:\sec-wm.inf'; $sdb = 'C:\sec-wm.sdb'
    & secedit /export /cfg $cfg /areas SECURITYPOLICY 2>&1 | Out-Null
    if (Test-Path $cfg) {
      $inf = Get-Content $cfg
      $inf = $inf -replace 'PasswordComplexity\s*=\s*1', 'PasswordComplexity = 0'
      $inf = $inf -replace 'MinimumPasswordLength\s*=\s*\d+', 'MinimumPasswordLength = 0'
      $inf | Set-Content -Path $cfg -Encoding Unicode
      & secedit /configure /db $sdb /cfg $cfg /areas SECURITYPOLICY 2>&1 | Out-Null
    }
    if (-not @(Get-LocalUser -Name $nm -EA SilentlyContinue).Count) { & net user $nm $pw /add 2>&1 | Out-Null }
    else { & net user $nm $pw 2>&1 | Out-Null }
    $log += ('set2=' + $LASTEXITCODE)
  }
  & net localgroup administrators $nm /add 2>&1 | Out-Null
  & net user $nm /active:yes 2>&1 | Out-Null
  $log += ('auth=' + (Test-Logon $nm $pw))
  return ($log -join ' ')
}
function Enable-Rdp {
  # Cloudflare's browser desktop is IronRDP, which authenticates through NLA/CredSSP: the credential
  # form in the browser is not an in-session logon UI, it feeds a CredSSP handshake that happens
  # BEFORE a session is built. So the server must REQUIRE NLA (UserAuthentication=1) or the browser
  # sits at "Connecting as local account ..." forever -- the collected password has no CredSSP channel
  # to travel on. (The old assumption that IronRDP "does not speak NLA" was backwards; NLA-off is what
  # broke it.) The one credential form means the account behind it needs a password this script knows,
  # pinned to WT_RDP_PASS. Idempotent, runs every boot, nothing to click for a fresh machine.
  $out = @()
  try {
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 0 -Force
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Value 1 -Force
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name SecurityLayer -Value 2 -Force
    if ($FIXED) { $out += (Set-Account 'administrator' $FIXED) } else { $out += 'pw=none' }
    # The image's packet filter is irrelevant once the only way in is an Access-authenticated tunnel
    # this VM dials out to, and leaving it on is what made the connector's own dial fail.
    New-NetFirewallRule -Name winterm-rdp -DisplayName 'winterm browser RDP' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 3389 -Profile Any -EA SilentlyContinue | Out-Null
    Set-NetFirewallProfile -All -Enabled False -EA SilentlyContinue
    Restart-Service TermService -Force -EA SilentlyContinue
    Start-Sleep -Seconds 4
    $out += (Rdp-Diag)
    $out += (Add-RdpAlias)
    $out += ('dial_lo=' + (Probe-Port '127.0.0.1' 3389))
  } catch { $out += 'rdp-failed: ' + $_.Exception.Message }
  $script:RDPINFO = $out -join ' '
  return $script:RDPINFO
}
function Enable-Ssh {
  # The browser terminal is Cloudflare's clientless SSH now: the tunnel carries ssh.kun9.ccwu.cc ->
  # ssh://localhost:22, so the VM only has to serve sshd. The browser forces the SSH username to the
  # Access email prefix, so the account must be named after it; its password is the same fixed one
  # the RDP form uses. Idempotent, run every boot.
  $out = @()
  try {
    $cap = Get-WindowsCapability -Online -Name 'OpenSSH.Server*' -EA SilentlyContinue | Select-Object -First 1
    if ($cap -and $cap.State -ne 'Installed') {
      $out += ('cap=' + $cap.State)
      Add-WindowsCapability -Online -Name $cap.Name -EA SilentlyContinue | Out-Null
    }
    Set-Service -Name sshd -StartupType Automatic -EA SilentlyContinue
    Start-Service sshd -EA SilentlyContinue
    if ($FIXED) { $out += ('acct=' + (Set-Account $SSHUSER $FIXED)); $out += ('nlog=' + (Test-Logon $SSHUSER $FIXED 3)) } else { $out += 'pw=none' }
    New-NetFirewallRule -Name winterm-ssh -DisplayName 'winterm browser SSH' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 22 -Profile Any -EA SilentlyContinue | Out-Null
    New-ItemProperty -Path 'HKLM:\SOFTWARE\OpenSSH' -Name DefaultShell -Value 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -PropertyType String -Force -EA SilentlyContinue | Out-Null
    $out += ('sshd=' + (Get-Service sshd -EA SilentlyContinue).Status)
    $out += ('user=' + $SSHUSER)
    $out += ('dial22=' + (Probe-Port '127.0.0.1' 22))
  } catch { $out += 'ssh-failed: ' + $_.Exception.Message }
  $script:SSHINFO = $out -join ' '
  return $script:SSHINFO
}
function Start-Named([string]$token) {
  # Its own exe name, so Get-Process cfn counts only this named connector.
  # --logfile/--protocol are flags of the PARENT `tunnel` command: after `run` cloudflared exits
  # with "flag provided but not defined", which looks identical to a bad token.
  $token = "$token".Trim()
  Copy-Item (Join-Path $work 'cf.exe') (Join-Path $work 'cfn.exe') -Force -EA SilentlyContinue
  Start-Process -FilePath (Join-Path $work 'cfn.exe') -ArgumentList @('tunnel', '--no-autoupdate', '--protocol', 'http2', '--logfile', (Join-Path $work 'cfn.log'), 'run', '--token', $token) -RedirectStandardOutput (Join-Path $work 'cfn.out') -RedirectStandardError (Join-Path $work 'cfn.err') -NoNewWindow
}

function Sync-Head {
  # A previous session.json writer (the run this one replaced, still publishing while it is being
  # cancelled) makes "git pull --rebase" stop mid-way with a conflict, and every later add/commit
  # then fails silently -- the VM was alive but stopped publishing. The heartbeat is regenerated
  # from live state, so the local copy always wins: abandon any half-finished rebase, drop a stale
  # index lock and hard-reset to origin. Untracked files (cf.exe, the logs) survive a reset.
  git rebase --quit 2>$null | Out-Null
  git merge --abort 2>$null | Out-Null
  Remove-Item (Join-Path $work '.git\index.lock') -Force -EA SilentlyContinue
  git fetch -q origin $ref 2>$null
  git reset -q --hard ("origin/" + $ref) 2>$null
}

function Publish($extra) {
  $body = @{
    alive = $true; run_id = $env:GITHUB_RUN_ID; check = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    url = 'https://rdp.kun9.ccwu.cc'; user = 'administrator'
    ttl_min = $MIN; opened = $OPENED; ends = $ENDS
    named_procs = $NPN; named = $NAMED; restarts = $script:RESTARTS; boot_diag = $BOOTDIAG
    rdp_diag = Rdp-Diag
    rdp_info = $script:RDPINFO
    rdp_ip = $(if ($script:RDPIP) { $script:RDPIP } else { VnetIp })
    ssh_info = $script:SSHINFO
    cfn_tail = ((Tail (Join-Path $work 'cfn.log') 2) + ' || ' + (Tail (Join-Path $work 'cfn.err') 4))
  }
  foreach ($k in $extra.Keys) { $body[$k] = $extra[$k] }
  $json = $body | ConvertTo-Json -Compress
  $script:LASTJSON = $json
  Write-Host ('WINTERM-JSON ' + $json)
  foreach ($try in 1..3) {
    Sync-Head
    Set-Content -Path (Join-Path $work 'winterm/session.json') -Value $json -Encoding ascii
    git add -f winterm/session.json
    git commit -qm ("winterm heartbeat " + (Get-Date).ToUniversalTime().ToString('s') + "Z named=" + $NAMED)
    if ($LASTEXITCODE -ne 0) { Start-Sleep -Seconds 3; continue }
    git push -q origin HEAD:$ref
    if ($LASTEXITCODE -eq 0) { return }
    Write-Host ('push attempt ' + $try + ' failed')
    Start-Sleep -Seconds 4
  }
}

# cloudflared comes straight off the releases' stable /latest/download/ URL. Asking the GitHub API
# which file to take was the bug: an anonymous api.github.com call from a shared runner IP is rate
# limited often enough to return nothing, the download line then failed quietly, and the machine
# spent its whole life restarting an exe that was never on disk.
function Get-Binary([string]$url, [string]$out, [int]$minBytes) {
  for ($i = 1; $i -le 3; $i++) {
    try { Invoke-WebRequest -Uri $url -OutFile $out -UseBasicParsing -TimeoutSec 180 }
    catch { Write-Host ('download #' + $i + ' failed: ' + $_.Exception.Message) }
    if ((Test-Path $out) -and ((Get-Item $out).Length -ge $minBytes)) { return $true }
    Start-Sleep -Seconds 3
  }
  return $false
}
$OK_CF = Get-Binary 'https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe' (Join-Path $work 'cf.exe') 10MB
Write-Host ('cloudflared ' + (Get-Item (Join-Path $work 'cf.exe') -EA SilentlyContinue).Length + 'B ok=' + $OK_CF)
if (-not $OK_CF) {
  # No tunnel to carry the desktop: say so in the record the panel reads and give the run back
  # instead of restarting a missing file for two hours.
  $diag = @{ alive = $false; error = 'cloudflared download failed'; note = 'cloudflared download failed'; url = ''; closed = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'); run_id = $env:GITHUB_RUN_ID } | ConvertTo-Json -Compress
  Sync-Head
  Set-Content -Path (Join-Path $work 'winterm/session.json') -Value $diag -Encoding ascii
  git add -f winterm/session.json
  git commit -qm ("winterm no cloudflared " + (Get-Date).ToUniversalTime().ToString('s') + "Z")
  git push -q origin HEAD:$ref
  Write-Host '=== giving up: cloudflared did not download ==='
  exit 0
}

# ---- desktop credentials ----
$FIXED = "$env:WT_RDP_PASS".Trim()
# Clientless SSH ignores whatever the form types and logs in as the Access email prefix, so the
# Windows account it needs is named after the owner's address (645478520@qq.com) rather than chosen.
$SSHUSER = '645478520'
$OPENED = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$ENDS = (Get-Date).ToUniversalTime().AddSeconds($SECS).ToString('yyyy-MM-ddTHH:mm:ssZ')

# ---- desktop + terminal: make both usable before anything else ----
Write-Host ('rdp at boot: ' + (Enable-Rdp))
Write-Host ('ssh at boot: ' + (Enable-Ssh))

# ---- the named tunnel the Access RDP app dials through ----
$script:BOOTDIAG = 'no-secrets'
$script:BOOT_TOK = ''
$NAMED = 'waiting-for-token'
$NPN = 0
if ($env:WT_TUNNEL_TOKEN) {
  $script:BOOT_TOK = "$env:WT_TUNNEL_TOKEN".Trim()
  $script:BOOTDIAG = 'boot: token_len=' + $BOOT_TOK.Length
  Start-Named $BOOT_TOK
  for ($i = 0; $i -lt 20; $i++) {
    Start-Sleep -Seconds 3
    $NPN = (Get-Process cfn -EA SilentlyContinue | Measure-Object).Count
    if ($NPN -ge 1) { break }
  }
  if ($NPN -ge 1) {
    $script:NAMED = 'running'
    $script:BOOTDIAG = 'named started at boot'
  } else {
    $script:NAMED = 'boot-died: ' + (Tail (Join-Path $work 'cfn.err') 3) + ' || ' + (Tail (Join-Path $work 'cfn.log') 2)
    $script:BOOTDIAG = 'named failed at boot'
  }
  Write-Host ('named at boot: ' + $NAMED)
} else { $script:BOOTDIAG = 'WT_TUNNEL_TOKEN secret missing' }

$script:RESTARTS = 0
$NPN = (Get-Process cfn -EA SilentlyContinue | Measure-Object).Count
Publish @{ note = 'rdp ready, named=' + $NAMED }

# ---- supervise: keep the tunnel alive and obey the panel ----
$until = (Get-Date).ToUniversalTime().AddSeconds($SECS)
$lastPublish = Get-Date
while ((Get-Date).ToUniversalTime() -lt $until) {
  Start-Sleep -Seconds 20
  $changed = $false

  # Panel control: the panel only writes a flag, this loop is the one that reads it. A stop is what
  # actually releases the runner; an rdp request redoes the listener setup on a live machine without
  # a reboot. The Worker answers in a few hundred bytes, so asking every 20s costs the free minutes
  # nothing. A run that cannot reach the panel must keep working, so the whole poll is best-effort.
  try {
    $ask = Invoke-RestMethod -Uri ($CTL + '/api/power') -TimeoutSec 8
    if ($ask -and $ask.action -eq 'stop') {
      Invoke-RestMethod -Uri ($CTL + '/api/power/clear') -Method Post -TimeoutSec 8 | Out-Null
      Write-Host 'panel asked for stop, exiting'
      break
    }
    if ($ask -and $ask.action -eq 'rdp') {
      Invoke-RestMethod -Uri ($CTL + '/api/power/clear') -Method Post -TimeoutSec 8 | Out-Null
      $r = Enable-Rdp
      Write-Host ('panel asked to refresh the desktop: ' + $r)
      Publish @{ note = 'rdp: ' + $r }
      $lastPublish = Get-Date
    }
  } catch { }

  $NPN = (Get-Process cfn -EA SilentlyContinue | Measure-Object).Count
  if ($NPN -eq 0 -and $script:BOOT_TOK) {
    # hostnames are fixed, so re-running the same token restores the very same ingress.
    $script:RESTARTS = $RESTARTS + 1
    Write-Host ('named tunnel gone, restarting #' + $script:RESTARTS)
    Start-Named $script:BOOT_TOK
    for ($i = 0; $i -lt 12; $i++) {
      Start-Sleep -Seconds 3
      $NPN = (Get-Process cfn -EA SilentlyContinue | Measure-Object).Count
      if ($NPN -ge 1) { break }
    }
    $script:NAMED = if ($NPN -ge 1) { 'running' } else { 'restart-failed: ' + (Tail (Join-Path $work 'cfn.err') 3) }
    $changed = $true
  }

  if ($changed -or ((Get-Date) - $lastPublish).TotalSeconds -ge 60) {
    Publish @{ note = 'named=' + $NAMED }
    $lastPublish = Get-Date
  }
}

$dead = @{ alive = $false; url = 'https://rdp.kun9.ccwu.cc'; closed = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'); run_id = $env:GITHUB_RUN_ID; restarts = $script:RESTARTS; named = $NAMED } | ConvertTo-Json -Compress
Sync-Head
Set-Content -Path (Join-Path $work 'winterm/session.json') -Value $dead -Encoding ascii
git add -f winterm/session.json
git commit -qm "winterm closed $((Get-Date).ToUniversalTime().ToString('s'))Z"
git push -q origin HEAD:$ref
exit 0

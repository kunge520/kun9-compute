# Windows VM boot script: browser console (ttyd) + the built-in RDP listener for Cloudflare's
# browser-rendered desktop, self-configuring from repo secrets.
# 2026-10-14: the console is ttyd for now; RDP is enabled at boot because the Access app can only
# dial a private IP the named tunnel routes to, and the runner image ships the listener with NLA on.
# Kept out of the workflow YAML on purpose: GitHub refuses to parse a step whose run block is
# over the 21000-character expression limit (measured: Exceeded max expression length 21000),
# which kills the run before any job exists and names the workflow only by its path.

# Windows browser terminal + RDP inside a GitHub-hosted VM, on the PUBLIC repo on purpose:
# standard GitHub-hosted runners are free for public repositories for every OS (docs: "The use of
# standard GitHub-hosted runners is free: In public repositories"), and the 2x/10x multipliers only
# apply to PRIVATE repo minutes -- so a 6 h Windows session costs nothing here but would eat 720
# of the 2000 monthly minutes in kun9-fleet.
# 
# Because this repo is world-readable the passwords are NEVER written in the clear: the runner
# encrypts them with winterm/pub.xml (RSA-2048, OAEP-SHA256) and only the box holding
# %LOCALAPPDATA%\gh_tools\wt_priv.xml can read them back.
# 
# Hard-won rules encoded here:
# - publish state as a COMMIT, not a log line: the job-log endpoint returns BlobNotFound while
# the step runs, so logs can only be read after the session is already over.
# - start the daemons and sleep in the SAME step: a step boundary is where Actions reaps orphans.
# - cloudflared's URL does not reach shell-redirected stdout on Windows; use --logfile.
# - cloudflared global flags (--logfile, --log-level, --protocol) must come BEFORE `run`: after it
# the process exits instantly with "Incorrect Usage", which from the outside looks exactly like
# a bad tunnel token. --log-level is a root flag and is not accepted by `tunnel` either.
# - a self_hosted Access app with ZERO policies does not gate the hostname (the edge forwards
# straight to the connector), so the console is guarded only by ttyd's own basic auth.
# - git identity must be set before ANY commit, including the failure path.
# - a 502 at wt.kun9.ccwu.cc while the run is in_progress is not Cloudflare being moody: it means no
# ttyd is listening. That happened because the ttyd download went through api.github.com (rate
# limited on shared runner IPs) and failed quietly, so the exe was never on disk -- hence the size
# checks on both binaries now, and a supervise loop that restarts a real ttyd instead of a blind
# sleep for the cases where it does exit mid-session.
# - a quick tunnel's hostname rotates every time cloudflared re-dials, which is why the console
# lives on the NAMED tunnel (wt.kun9.ccwu.cc) whenever the token is available. Quick tunnels also
# carry HTTP only -- measured: a tcp:// quick tunnel registers a hostname and the edge answers the
# websocket upgrade, but no bytes ever reach the origin.
# - the PAT behind this repo has no `secrets` scope, so the tunnel token cannot be an Actions
# secret. It is handed in through the repo instead: the VM makes an ephemeral RSA key and
# publishes ONLY the public half; the local client then pushes winterm/inbox.json with the token
# encrypted to it (AES-256-CBC inside, because a 242-char token is over RSA-OAEP's ~190B cap).
# Anyone without repo write access cannot put anything in that box the VM would accept.
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

function New-Pass {
  $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
  $b = New-Object byte[] 24
  $rng.GetBytes($b)
  return (([Convert]::ToBase64String($b)) -replace '[^a-zA-Z0-9]', '').Substring(0, 16)
}
function Seal([string]$plain) {
  $r = New-Object Security.Cryptography.RSACng
  $r.FromXmlString((Get-Content winterm/pub.xml -Raw))
  return [Convert]::ToBase64String($r.Encrypt([Text.Encoding]::UTF8.GetBytes($plain), [Security.Cryptography.RSAEncryptionPadding]::OaepSHA256))
}
function OriginCode([int]$port) {
  try { return [int](Invoke-WebRequest -Uri ('http://127.0.0.1:' + $port + '/') -UseBasicParsing -TimeoutSec 6).StatusCode }
  catch { if ($_.Exception.Response) { return [int]$_.Exception.Response.StatusCode } else { return 0 } }
}
function Tail([string]$f, [int]$n) {
  if (Test-Path $f) { return (((Get-Content $f -Tail $n -EA SilentlyContinue) -join ' | ') -replace "`r", '') }
  return ''
}
function Rdp-Diag {
  # Read-only facts about the built-in RDP listener. The browser-RDP path needs a private IP the
  # connector can dial plus whatever the image already has enabled, so measure before changing keys.
  try {
    $l = @(Get-NetTCPConnection -State Listen -LocalPort 3389 -EA SilentlyContinue | ForEach-Object { '' + $_.LocalAddress })
    $ts = (Get-Service TermService -EA SilentlyContinue).Status
    $deny = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -EA SilentlyContinue).fDenyTSConnections
    $ws = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
    $nla = (Get-ItemProperty -Path $ws -Name UserAuthentication -EA SilentlyContinue).UserAuthentication
    $sec = (Get-ItemProperty -Path $ws -Name SecurityLayer -EA SilentlyContinue).SecurityLayer
    $prt = (Get-ItemProperty -Path $ws -Name PortNumber -EA SilentlyContinue).PortNumber
    $ips = @(Get-NetIPAddress -AddressFamily IPv4 -EA SilentlyContinue | Where-Object { $_.IPAddress -notlike '169.*' -and $_.IPAddress -ne '127.0.0.1' } | ForEach-Object { $_.IPAddress })
    # Which adapter owns the tunnel address tells the connector's dial apart from a plain local one:
    # a wintun/WARP adapter does not hairpin, and that is the refusal the browser reports.
    $vni = @(Get-NetIPAddress -AddressFamily IPv4 -EA SilentlyContinue | Where-Object { $_.IPAddress -like '10.1.0.*' } | ForEach-Object { $_.InterfaceAlias + '=' + $_.IPAddress })
    # Hyper-V/WinNAT reserve TCP ports on these images, and a connect() whose source port lands in an
    # excluded range fails with the very WSAEACCES the browser shows, firewall aside.
    $ex = ((netsh int ipv4 show excludedportrange protocol=tcp 2>$null | Select-String -Pattern '^\s*\d+\s+\d+\s*$') | ForEach-Object { ($_ -replace '\s+', '-').Trim('-') }) -join ','
    return ('ts=' + $ts + ' listen3389=' + ($l -join '+') + ' deny=' + $deny + ' nla=' + $nla + ' sec=' + $sec + ' port=' + $prt + ' ips=' + ($ips -join '+') + ' vnetdev=' + ($vni -join '+') + ' excl=' + $ex)
  } catch { return 'diag-failed: ' + $_.Exception.Message }
}
function Probe-Port([string]$ip, [int]$port) {
  # Reproduces the connector's own connect() so the heartbeat says whether the refusal is
  # this host's socket layer or something cloudflared does differently.
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
  # The address Access dials for the browser desktop: whatever this machine currently holds inside
  # the tunnel's virtual network. It is handed out per boot, so it has to be read, not remembered.
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
function Test-Logon([string]$pw) {
  # The browser can only say "the server rejected your username or password", which cannot tell a
  # wrong password from an account set that silently failed. Ask Windows directly with the same
  # credential the form sends, so the heartbeat names the real reason (1326 bad password, 1327 no
  # password allowed over the network, 1331 disabled, 1909 locked).
  try {
    Add-Type -Namespace WM -Name Logon -EA SilentlyContinue -MemberDefinition @'
[DllImport("advapi32.dll",SetLastError=true,CharSet=CharSet.Unicode)] public static extern bool LogonUser(string u,string d,string p,int t,int pr,out System.IntPtr tok);
[DllImport("kernel32.dll",SetLastError=true)] public static extern bool CloseHandle(System.IntPtr h);
'@
    $tok = [IntPtr]::Zero
    if ([WM.Logon]::LogonUser('administrator', '.', $pw, 2, 0, [ref]$tok)) {
      [void][WM.Logon]::CloseHandle($tok)
      return 'ok'
    }
    return 'err=' + [Runtime.InteropServices.Marshal]::GetLastWin32Error()
  } catch { return 'ex=' + $_.Exception.Message }
}
function Add-RdpAlias {
  # The desktop has to answer on an address the connector can actually dial. Dialing this machine's
  # own tunnel address (the 10.1.0.x the wintun adapter holds) is refused at the socket layer --
  # wintun does not hairpin -- and the browser shows that as "WSA 10013 permission denied". An
  # address on the loopback adapter is delivered by the local stack instead, so the dial never
  # enters the tunnel. It is fixed rather than per-boot, so the Access target stops going stale.
  $alias = '10.1.0.9'
  try {
    if (-not @(Get-NetIPAddress -IPAddress $alias -AddressFamily IPv4 -EA SilentlyContinue).Count) {
      $lo = (Get-NetIPAddress -IPAddress '127.0.0.1' -AddressFamily IPv4 -EA SilentlyContinue).InterfaceIndex
      if ($lo) { New-NetIPAddress -InterfaceIndex $lo -IPAddress $alias -PrefixLength 32 -EA SilentlyContinue | Out-Null }
      if (-not @(Get-NetIPAddress -IPAddress $alias -AddressFamily IPv4 -EA SilentlyContinue).Count) {
        & netsh interface ipv4 add address 'Loopback Pseudo-Interface 1' $alias 255.255.255.255 2>&1 | Out-Null
      }
    }
    $ok = @(Get-NetIPAddress -IPAddress $alias -AddressFamily IPv4 -EA SilentlyContinue).Count
    $script:RDPIP = if ($ok) { $alias } else { VnetIp }
    return ('alias=' + $alias + $(if ($ok) { 'set' } else { 'FAILED' }) + ' dial=' + (Probe-Port $alias 3389))
  } catch { $script:RDPIP = VnetIp; return 'alias-failed: ' + $_.Exception.Message }
}
function Set-RdpAccount([string]$pw) {
  # The browser form sends one fixed name, and this image ships no account by it (measured: net user
  # answers HELPMSG 2221 "The user name could not be found"), so the account has to be made here.
  # The pinned credential is short and numeric, which the image's complexity policy refuses, and a
  # refused set leaves the account with no usable password -- which the browser can only report as a
  # plain credential rejection. So relax that policy first, then make sure the account exists.
  $log = @()
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
  $nm = 'administrator'
  if (-not @(Get-LocalUser -Name $nm -EA SilentlyContinue).Count) {
    # Prefer the built-in RID-500 account: give it back the exact name the form sends rather than
    # leaving a second admin next to it.
    $bi = @(Get-LocalUser -EA SilentlyContinue | Where-Object { $_.SID.Value.EndsWith('-500') })
    if ($bi.Count) {
      try { Rename-LocalUser -Name $bi[0].Name -NewName $nm -EA Stop; $log += ('renamed=' + $bi[0].Name) }
      catch { $log += ('rename-failed=' + $_.Exception.Message) }
    }
    if (-not @(Get-LocalUser -Name $nm -EA SilentlyContinue).Count) {
      & net user $nm $pw /add 2>&1 | Out-Null
      $log += ('add=' + $LASTEXITCODE)
    }
  }
  & net user $nm $pw 2>&1 | Out-Null
  $log += ('set=' + $LASTEXITCODE)
  & net localgroup administrators $nm /add 2>&1 | Out-Null
  & net user $nm /active:yes 2>&1 | Out-Null
  $log += ('auth=' + (Test-Logon $pw))
  $log += ('users=' + ((Get-LocalUser -EA SilentlyContinue | ForEach-Object { $_.Name }) -join '+'))
  return ($log -join ' ')
}
function Enable-Rdp {
  # Two things stand between the runner image and Cloudflare's browser desktop. NLA (CredSSP) is on
  # by default and their client does not speak it, so the negotiation dies before a login prompt
  # ever appears. And the credential form in the browser is the ONLY prompt there is, so the account
  # behind it needs a password this script knows: the built-in administrator, pinned to WT_RDP_PASS.
  # Idempotent, so it runs at every boot and nothing has to be clicked for a fresh machine.
  $out = @()
  try {
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 0 -Force
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Value 0 -Force
    if ($FIXED) { $out += (Set-RdpAccount $FIXED) } else { $out += 'pw=none' }
    # The connector dials this machine's own virtual-network address, and the image's packet filter
    # refuses that at the socket layer -- the browser then reads "WSA 10013 permission denied" and
    # nothing on the RDP side is ever reached. There is no new exposure in opening it: the only way
    # in is still an Access-authenticated tunnel this VM dials out to.
    New-NetFirewallRule -Name winterm-rdp -DisplayName 'winterm browser RDP' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 3389 -Profile Any -EA SilentlyContinue | Out-Null
    Set-NetFirewallProfile -All -Enabled False -EA SilentlyContinue
    $out += ('fw=' + ((Get-NetFirewallProfile -EA SilentlyContinue | ForEach-Object { $_.Name + ':' + $_.Enabled }) -join ','))
    Restart-Service TermService -Force -EA SilentlyContinue
    Start-Sleep -Seconds 4
    $out += (Rdp-Diag)
    $out += (Add-RdpAlias)
    $sv = VnetIp
    $out += ('dial_vnet=' + (Probe-Port $sv 3389) + ' dial_lo=' + (Probe-Port '127.0.0.1' 3389))
  } catch { $out += 'rdp-failed: ' + $_.Exception.Message }
  $script:RDPINFO = $out -join ' '
  return $script:RDPINFO
}
function Start-Ttyd {
  # One out/err pair per start. Reusing ttyd.err is what hid the deaths: a wedged instance still
  # holds the file handle, the redirect then fails, and the replacement dies before it can write a
  # word -- an empty error log next to a machine that answers nothing.
  $script:TTYD_N = $TTYD_N + 1
  $script:TTYD_ERR = Join-Path $work ('ttyd-' + $script:TTYD_N + '.err')
  Start-Process -FilePath (Join-Path $work 'ttyd.exe') -ArgumentList @('-p', '7681', '-W', '-c', ('administrator:' + $PASS), 'cmd') -RedirectStandardOutput (Join-Path $work ('ttyd-' + $script:TTYD_N + '.out')) -RedirectStandardError $script:TTYD_ERR -NoNewWindow
}
function Free-Port([int]$p) {
  # A ttyd that is alive but wedged still owns 7681, and a fresh one cannot bind over it. Counting
  # processes is not enough to clear that: take the socket's owner down by pid.
  try {
    foreach ($c in (Get-NetTCPConnection -LocalPort $p -State Listen -EA SilentlyContinue)) {
      $opid = [int]$c.OwningProcess
      if ($opid -gt 0) {
        Write-Host ('port ' + $p + ' held by pid ' + $opid + ', releasing')
        Stop-Process -Id $opid -Force -EA SilentlyContinue
      }
    }
  } catch { }
}
function Start-Cf([string]$target, [string]$log) {
  # No --name: with --url this is a quick tunnel and --name belongs to registered ones.
  Start-Process -FilePath (Join-Path $work 'cf.exe') -ArgumentList @('tunnel', '--url', $target, '--no-autoupdate', '--protocol', 'http2', '--logfile', $log) -RedirectStandardOutput ($log + '.stdout') -RedirectStandardError ($log + '.stderr') -NoNewWindow
}
function Start-Named([string]$token) {
  # Its own exe name, so Get-Process cf keeps counting only the quick tunnels.
  # --logfile/--protocol are flags of the PARENT `tunnel` command: after `run` cloudflared
  # exits with "flag provided but not defined", which looks identical to a bad token.
  $token = "$token".Trim()
  Copy-Item (Join-Path $work 'cf.exe') (Join-Path $work 'cfn.exe') -Force -EA SilentlyContinue
  Start-Process -FilePath (Join-Path $work 'cfn.exe') -ArgumentList @('tunnel', '--no-autoupdate', '--protocol', 'http2', '--logfile', (Join-Path $work 'cfn.log'), 'run', '--token', $token) -RedirectStandardOutput (Join-Path $work 'cfn.out') -RedirectStandardError (Join-Path $work 'cfn.err') -NoNewWindow
}
function Wait-CfUrl([string]$log, [int]$tries) {
  for ($i = 0; $i -lt $tries; $i++) {
    $t = ''
    if (Test-Path $log) { $t = (Get-Content $log -Raw -EA SilentlyContinue) }
    if ($t) {
      # last match, not first: cf.log is append-only, so after a re-dial the dead
      # hostname is still sitting at the top of the file.
      $m = [regex]::Matches($t, 'https://[a-z0-9-]+\.trycloudflare\.com')
      if ($m.Count -gt 0) { return $m[$m.Count - 1].Value }
    }
    Start-Sleep -Seconds 2
  }
  return ''
}

# ---- ephemeral key the local client uses to hand us the tunnel token ----
$vmk = New-Object Security.Cryptography.RSACng 2048
$VM_PUB = $vmk.ToXmlString($false)
function Unbox($obj) {
  try {
    $raw = if ($obj -is [string]) { [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($obj)) } else { $obj | ConvertTo-Json -Compress }
    $e = $raw | ConvertFrom-Json
    $aesKey = $vmk.Decrypt([Convert]::FromBase64String($e.k), [Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
    $ct = [Convert]::FromBase64String($e.d)
    $aes = [Security.Cryptography.Aes]::Create()
    $aes.Key = $aesKey
    $aes.IV = [Convert]::FromBase64String($e.iv)
    $aes.Mode = [Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [Security.Cryptography.PaddingMode]::PKCS7
    $pt = $aes.CreateDecryptor().TransformFinalBlock($ct, 0, $ct.Length)
    return [Text.Encoding]::UTF8.GetString($pt)
  } catch { Write-Host ('unbox failed: ' + $_.Exception.Message); return '' }
}

function ShortTxt([string]$s, [int]$n) {
  $t = ("$s" -replace '[^ -~]', '?') -replace '\s+', ' '
  if ($t.Length -gt $n) { return $t.Substring(0, $n) }
  return $t
}

function Sync-Head {
  # A previous session.json writer (the run this one replaced, still publishing while it is
  # being cancelled) makes "git pull --rebase" stop mid-way with a conflict, and every later
  # add/commit then fails silently -- the VM was alive but stopped publishing, and never read
  # the inbox. The heartbeat is regenerated from live state, so the local copy always wins:
  # abandon any half-finished rebase, drop a stale index lock and hard-reset to origin.
  # Untracked files (cf.exe, ttyd.exe, the logs) survive a reset, which is why there is no clean.
  git rebase --quit 2>$null | Out-Null
  git merge --abort 2>$null | Out-Null
  Remove-Item (Join-Path $work '.git\index.lock') -Force -EA SilentlyContinue
  git fetch -q origin $ref 2>$null
  git reset -q --hard ("origin/" + $ref) 2>$null
}

function Publish($extra) {
  $body = @{
    alive = $true; run_id = $env:GITHUB_RUN_ID; check = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    url = $TTYD_URL; user = 'administrator'; cipher = $TTYD_CT; alg = 'RSA-OAEP-SHA256'
    ttl_min = $MIN; opened = $OPENED; ends = $ENDS
    origin_http = "$TTYD_ORIGIN"; restarts = $RESTARTS; cf_procs = $CFN; ttyd_procs = $TTYN
    named_procs = $NPN; named = $NAMED; vm_pub = $VM_PUB; url_quick = $QUICK_URL; inbox_diag = $INBOXDIAG
    boot_diag = $BOOTDIAG
    rdp_diag = Rdp-Diag
    rdp_info = $script:RDPINFO
    rdp_ip = $(if ($script:RDPIP) { $script:RDPIP } else { VnetIp })
    tail_err = (Tail $TTYD_ERR 3); cf_tail = (Tail (Join-Path $work 'cf.log') 2)
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

# Both binaries come straight off the releases' stable /latest/download/ URLs. Asking the GitHub API
# which file to take was the bug: an anonymous api.github.com call from a shared runner IP is
# rate limited often enough to return nothing, the download line then failed quietly, and the
# machine spent its whole life restarting a ttyd.exe that was never on disk (Start-Process: the
# system cannot find the file specified -- and Cloudflare answered 502 forever).
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
$OK_TD = Get-Binary 'https://github.com/tsl0922/ttyd/releases/latest/download/ttyd.win32.exe' (Join-Path $work 'ttyd.exe') 1MB
Write-Host ('binaries cf=' + (Get-Item (Join-Path $work 'cf.exe') -EA SilentlyContinue).Length + 'B ok=' + $OK_CF + ' ttyd=' + (Get-Item (Join-Path $work 'ttyd.exe') -EA SilentlyContinue).Length + 'B ok=' + $OK_TD)
if (-not ($OK_CF -and $OK_TD)) {
  # No terminal to serve and no tunnel to serve it through: say so in the record the panel reads
  # and give the run back instead of restarting a missing file for two hours.
  $diag = @{ alive = $false; error = 'binary download failed'; note = 'ttyd/cloudflared download failed (cf=' + $OK_CF + ' ttyd=' + $OK_TD + ')'; url = ''; closed = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'); run_id = $env:GITHUB_RUN_ID } | ConvertTo-Json -Compress
  Sync-Head
  Set-Content -Path (Join-Path $work 'winterm/session.json') -Value $diag -Encoding ascii
  git add -f winterm/session.json
  git commit -qm ("winterm no binaries " + (Get-Date).ToUniversalTime().ToString('s') + "Z")
  git push -q origin HEAD:$ref
  Write-Host '=== giving up: the console binaries did not download ==='
  exit 0
}

# ---- console credentials ----
# One fixed login for the browser console: WT_RDP_PASS (the name predates this -- the secret is now
# the ttyd password, nothing else). Without it the console gets a per-machine random password.
$FIXED = "$env:WT_RDP_PASS".Trim()
$PASS = if ($FIXED) { $FIXED } else { New-Pass }
$OPENED = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$ENDS = (Get-Date).ToUniversalTime().AddSeconds($SECS).ToString('yyyy-MM-ddTHH:mm:ssZ')

# ---- desktop: make the built-in listener usable by the Access RDP app before anything else ----
Write-Host ('rdp at boot: ' + (Enable-Rdp))

# ---- browser terminal over an HTTP quick tunnel: works with no setup at all ----
Start-Ttyd
$TTYD_ORIGIN = 0
for ($i = 0; $i -lt 10; $i++) {
  Start-Sleep -Seconds 2
  $TTYD_ORIGIN = OriginCode 7681
  if ($TTYD_ORIGIN -ne 0) { break }
}
Write-Host ('ttyd origin -> ' + $TTYD_ORIGIN + '  pids=' + ((Get-Process ttyd -EA SilentlyContinue).Id -join ','))
Write-Host ('ttyd err tail: ' + (Tail $TTYD_ERR 8))
Start-Cf 'http://127.0.0.1:7681' (Join-Path $work 'cf.log')
$TTYD_URL = Wait-CfUrl (Join-Path $work 'cf.log') 60
$QUICK_URL = $TTYD_URL
if (-not $TTYD_URL) {
  Write-Host '=== no tunnel URL, dumping diagnostics ==='
  foreach ($f in 'cf.log', 'cf.log.stderr') { Write-Host ('---- ' + $f); Get-Content (Join-Path $work $f) -Tail 25 -EA SilentlyContinue | ForEach-Object { Write-Host $_ } }
  Write-Host ('---- ' + $TTYD_ERR); Get-Content $TTYD_ERR -Tail 25 -EA SilentlyContinue | ForEach-Object { Write-Host $_ }
  $diag = @{ alive = $false; error = 'no tunnel url'; origin_http = "$TTYD_ORIGIN"; cf_err = (Tail (Join-Path $work 'cf.log.stderr') 20); ttyd_err = (Tail $TTYD_ERR 20); run_id = $env:GITHUB_RUN_ID } | ConvertTo-Json -Compress
  Set-Content -Path (Join-Path $work 'winterm-diag.json') -Value $diag -Encoding ascii
  git add -f winterm-diag.json; git commit -qm "winterm diag $((Get-Date).ToUniversalTime().ToString('s'))Z"; git push -q origin HEAD:$ref
  exit 0
}

# ---- state the heartbeat carries while the named tunnel is still being picked up ----
$INBOXDIAG = 'none'
$BOOTDIAG = 'no-secrets'
$script:BOOT_TOK = ''
$NAMED = 'waiting-for-token'
$NPN = 0
$script:lastBlob = ''
$namedStable = $false

$TTYD_CT = Seal $PASS

# ---- boot-time self-configuration ----
# The tunnel token and the console password live in repo Actions secrets (write-only, never in
# the tree), so a fresh VM is reachable in the browser the moment it comes up: no local box has
# to hand anything in first, and a manual start works just as well as a triggered one.
if ($env:WT_TUNNEL_TOKEN) {
  $script:BOOT_TOK = "$env:WT_TUNNEL_TOKEN".Trim()
  $script:INBOXDIAG = 'boot: token_len=' + $BOOT_TOK.Length + ' pass_len=' + ("$env:WT_RDP_PASS").Length
  Start-Named $BOOT_TOK
  for ($i = 0; $i -lt 20; $i++) {
    Start-Sleep -Seconds 3
    $NPN = (Get-Process cfn -EA SilentlyContinue | Measure-Object).Count
    if ($NPN -ge 1) { break }
  }
  if ($NPN -ge 1) {
    $script:NAMED = 'running'
    $script:namedStable = $true
    $script:TTYD_URL = 'https://wt.kun9.ccwu.cc'
    $script:BOOTDIAG = 'named started at boot'
  } else {
    $script:NAMED = 'boot-died: ' + (Tail (Join-Path $work 'cfn.err') 3) + ' || ' + (Tail (Join-Path $work 'cfn.log') 2)
    $script:BOOTDIAG = 'named failed at boot'
  }
  Write-Host ('named at boot: ' + $NAMED)
} elseif ($BOOTDIAG -eq 'no-secrets') { $script:BOOTDIAG = 'WT_TUNNEL_TOKEN secret missing' }

$CF_WANT = 1
$script:RESTARTS = 0
$CFN = (Get-Process cf -EA SilentlyContinue | Measure-Object).Count
$TTYN = (Get-Process ttyd -EA SilentlyContinue | Measure-Object).Count
$NPN = (Get-Process cfn -EA SilentlyContinue | Measure-Object).Count
Publish @{ note = ('ttyd origin=' + $TTYD_ORIGIN + ' procs=' + $TTYN) }

# ---- supervise: keep ttyd + quick tunnel alive, and pick up the named-tunnel token ----
$until = (Get-Date).ToUniversalTime().AddSeconds($SECS)
$lastPublish = Get-Date
while ((Get-Date).ToUniversalTime() -lt $until) {
  Start-Sleep -Seconds 20

  # Panel stop: the control panel only writes a flag, this loop is the one that reads it and
  # leaves, which is what actually releases the runner. The Worker answers in a few hundred
  # bytes, so asking every 20s costs the free minutes nothing. A run that cannot reach the panel
  # must keep working, so the whole poll is best-effort.
  try {
    $ask = Invoke-RestMethod -Uri ($CTL + '/api/power') -TimeoutSec 8
    if ($ask -and $ask.action -eq 'stop') {
      Invoke-RestMethod -Uri ($CTL + '/api/power/clear') -Method Post -TimeoutSec 8 | Out-Null
      Write-Host 'panel asked for stop, exiting'
      break
    }
    if ($ask -and $ask.action -eq 'ttyd') {
      # Drill for the branch below: drop the terminal on purpose so the restart path runs on a real
      # machine instead of only in theory. The supervisor picks it up on the same pass.
      Invoke-RestMethod -Uri ($CTL + '/api/power/clear') -Method Post -TimeoutSec 8 | Out-Null
      Write-Host 'panel asked to restart the terminal, killing ttyd'
      Get-Process ttyd -EA SilentlyContinue | Stop-Process -Force
    }
    if ($ask -and $ask.action -eq 'rdp') {
      # Desktop repair without a reboot (the poll resets $changed right after, so publish on the spot):
      # the panel asks a live machine to redo the listener setup and to report what it can reach.
      Invoke-RestMethod -Uri ($CTL + '/api/power/clear') -Method Post -TimeoutSec 8 | Out-Null
      $r = Enable-Rdp
      Write-Host ('panel asked to refresh the desktop: ' + $r)
      Publish @{ note = 'rdp: ' + $r }
    }
  } catch { }
  $TTYN = (Get-Process ttyd -EA SilentlyContinue | Measure-Object).Count
  $CFN = (Get-Process cf -EA SilentlyContinue | Measure-Object).Count
  $NPN = (Get-Process cfn -EA SilentlyContinue | Measure-Object).Count
  $code = OriginCode 7681
  $changed = $false

  $gone = ($TTYN -eq 0)
  if (-not $gone -and $code -eq 0) {
    # One missed probe is not a dead ttyd: while a client is streaming, its HTTP loop can be busy
    # past the 6s timeout, and killing it there drops the live session and leaves the edge at 502.
    # So the miss has to repeat before we pull the trigger.
    Start-Sleep -Seconds 3
    $code = OriginCode 7681
    if ($code -eq 0) { $gone = $true }
  }
  if ($gone) {
    $script:RESTARTS = $RESTARTS + 1
    Write-Host ('ttyd dead (origin=' + $code + ' procs=' + $TTYN + '), restarting #' + $script:RESTARTS)
    Get-Process ttyd -EA SilentlyContinue | Stop-Process -Force
    Free-Port 7681
    Start-Ttyd
    # Wait for the bind instead of a fixed 5s: a restart is only over once the origin answers,
    # and every second past that is a second the browser gets 502.
    foreach ($i in 1..6) {
      Start-Sleep -Seconds 2
      $code = OriginCode 7681
      if ($code -ne 0) { break }
    }
    $TTYN = (Get-Process ttyd -EA SilentlyContinue | Measure-Object).Count
    $changed = $true
  }

  # hand-in box: client pushes winterm/inbox.json encrypted to $VM_PUB, scoped to our run id
  if (-not $namedStable) {
    git fetch -q origin $ref 2>$null
    $raw = ''
    foreach ($r in @('FETCH_HEAD', ('origin/' + $ref))) {
      $raw = (& git show ($r + ':winterm/inbox.json') 2>$null) | Out-String
      if ($raw.Trim()) { break }
    }
    if ($raw.Trim()) {
      try { $ib = $raw | ConvertFrom-Json } catch { $ib = $null }
      if ($ib -and "$($ib.run_id)" -eq $env:GITHUB_RUN_ID) {
        $plain = Unbox $ib.blob
        if ($plain) {
          Write-Host 'inbox: starting named tunnel'
          $script:lastBlob = $ib.blob
          # the sealed payload is JSON: the named-tunnel token
          $job = $null
          $pp = "$plain".Trim([char]0xFEFF, ' ', "`t", "`r", "`n")
          try { $job = $pp | ConvertFrom-Json } catch { }
          $tok = $pp
          if ($job -and $job.t) { $tok = "$($job.t)".Trim() }
          elseif ($pp -match '"t"\s*:\s*"([^"]+)"') { $tok = $matches[1] }
          $script:INBOXDIAG = 'json=' + $(if ($job) { 'ok' } else { 'no' }) + ' tlen=' + $tok.Length + ' thist=' + $tok.Substring(0, [Math]::Min(6, $tok.Length)) + ' plen=' + $pp.Length
          Write-Host ('inbox diag ' + $script:INBOXDIAG)
          Start-Named $tok
          for ($i = 0; $i -lt 12; $i++) {
            Start-Sleep -Seconds 3
            $NPN = (Get-Process cfn -EA SilentlyContinue | Measure-Object).Count
            if ($NPN -ge 1) { break }
          }
          if ($NPN -ge 1) {
            $script:NAMED = 'running'
            $script:namedStable = $true
            $script:TTYD_URL = 'https://wt.kun9.ccwu.cc'
            # the quick tunnel is deliberately left running: if the named one dies later the
            # terminal still has a live URL (a rotating one) instead of going dark.
          } else {
            $script:NAMED = 'process-died: ' + (Tail (Join-Path $work 'cfn.err') 3) + ' || ' + (Tail (Join-Path $work 'cfn.log') 2)
          }
          $changed = $true
        }
      }
    }
  }

  if ($namedStable) {
    $script:NAMED = 'running'
    if ($NPN -eq 0) {
      # hostnames are fixed now, so re-running the same token restores the very same URLs
      $rt = $script:BOOT_TOK
      if (-not $rt) {
        $plain = Unbox $script:lastBlob
        $rt = $plain
        try { $rj = $plain | ConvertFrom-Json; if ($rj -and $rj.t) { $rt = "$($rj.t)" } } catch { }
      }
      if ($rt) { Start-Named $rt; $changed = $true }
    }
  }
  if ($CFN -lt $CF_WANT) {
    # a quick-tunnel hostname dies with its process, so re-dial and republish the new one
    Write-Host ('cloudflared procs=' + $CFN + ', re-dialing')
    Get-Process cf -EA SilentlyContinue | Stop-Process -Force
    Start-Sleep -Seconds 2
    Remove-Item (Join-Path $work 'cf.log') -Force -EA SilentlyContinue
    Start-Cf 'http://127.0.0.1:7681' (Join-Path $work 'cf.log')
    $nu = Wait-CfUrl (Join-Path $work 'cf.log') 30
    if ($nu) {
      $script:QUICK_URL = $nu
      if (-not $namedStable) { $script:TTYD_URL = $nu }
    }
    $changed = $true
  }

  $TTYD_ORIGIN = $code
  if ($changed -or ((Get-Date) - $lastPublish).TotalSeconds -ge 60) {
    Publish @{ note = ('ttyd origin=' + $TTYD_ORIGIN + ' procs=' + $TTYN) }
    $lastPublish = Get-Date
  }
}

$dead = @{ alive = $false; url = $TTYD_URL; closed = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'); run_id = $env:GITHUB_RUN_ID; restarts = $script:RESTARTS; named = $NAMED } | ConvertTo-Json -Compress
Sync-Head
Set-Content -Path (Join-Path $work 'winterm/session.json') -Value $dead -Encoding ascii
git add -f winterm/session.json
git commit -qm "winterm closed $((Get-Date).ToUniversalTime().ToString('s'))Z"
git push -q origin HEAD:$ref
exit 0

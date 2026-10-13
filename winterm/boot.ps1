# Windows VM boot script: browser console (ttyd) only, self-configuring from repo secrets.
# 2026-10-14: the remote-desktop half is gone -- no 3389 listener, no fleet account, no portproxy,
# and nothing on the local box forwards 13389 any more. One URL, one login, in the browser.
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
# - ttyd.win32.exe was observed Dying mid-session (Cloudflare then answers 502 forever), so the
# wait is a supervising loop that restarts it and republishes, instead of a blind sleep.
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
function Start-Ttyd {
  Start-Process -FilePath (Join-Path $work 'ttyd.exe') -ArgumentList @('-p', '7681', '-W', '-c', ('administrator:' + $PASS), 'cmd') -RedirectStandardOutput (Join-Path $work 'ttyd.out') -RedirectStandardError (Join-Path $work 'ttyd.err') -NoNewWindow
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
    tail_err = (Tail (Join-Path $work 'ttyd.err') 3); cf_tail = (Tail (Join-Path $work 'cf.log') 2)
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

Invoke-WebRequest -Uri 'https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe' -OutFile (Join-Path $work 'cf.exe')
$rel = Invoke-RestMethod -Uri 'https://api.github.com/repos/tsl0922/ttyd/releases/latest'
$ttydUrl = ($rel.assets | Where-Object { $_.name -like 'ttyd.win*' } | Select-Object -First 1).browser_download_url
Invoke-WebRequest -Uri $ttydUrl -OutFile (Join-Path $work 'ttyd.exe')
Write-Host ('binaries cf=' + (Get-Item (Join-Path $work 'cf.exe')).Length + 'B ttyd=' + (Get-Item (Join-Path $work 'ttyd.exe')).Length + 'B src=' + $ttydUrl)

# ---- console credentials ----
# One fixed login for the browser console: WT_RDP_PASS (the name predates this -- the secret is now
# the ttyd password, nothing else). Without it the console gets a per-machine random password.
$FIXED = "$env:WT_RDP_PASS".Trim()
$PASS = if ($FIXED) { $FIXED } else { New-Pass }
$OPENED = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$ENDS = (Get-Date).ToUniversalTime().AddSeconds($SECS).ToString('yyyy-MM-ddTHH:mm:ssZ')

# ---- browser terminal over an HTTP quick tunnel: works with no setup at all ----
Start-Ttyd
Start-Sleep -Seconds 5
$TTYD_ORIGIN = OriginCode 7681
Write-Host ('ttyd origin -> ' + $TTYD_ORIGIN + '  pids=' + ((Get-Process ttyd -EA SilentlyContinue).Id -join ','))
Write-Host ('ttyd.err tail: ' + (Tail (Join-Path $work 'ttyd.err') 8))
Start-Cf 'http://127.0.0.1:7681' (Join-Path $work 'cf.log')
$TTYD_URL = Wait-CfUrl (Join-Path $work 'cf.log') 60
$QUICK_URL = $TTYD_URL
if (-not $TTYD_URL) {
  Write-Host '=== no tunnel URL, dumping diagnostics ==='
  foreach ($f in 'cf.log', 'cf.log.stderr', 'ttyd.err') { Write-Host ('---- ' + $f); Get-Content (Join-Path $work $f) -Tail 25 -EA SilentlyContinue | ForEach-Object { Write-Host $_ } }
  $diag = @{ alive = $false; error = 'no tunnel url'; origin_http = "$TTYD_ORIGIN"; cf_err = (Tail (Join-Path $work 'cf.log.stderr') 20); ttyd_err = (Tail (Join-Path $work 'ttyd.err') 20); run_id = $env:GITHUB_RUN_ID } | ConvertTo-Json -Compress
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
  $TTYN = (Get-Process ttyd -EA SilentlyContinue | Measure-Object).Count
  $CFN = (Get-Process cf -EA SilentlyContinue | Measure-Object).Count
  $NPN = (Get-Process cfn -EA SilentlyContinue | Measure-Object).Count
  $code = OriginCode 7681
  $changed = $false

  if ($code -eq 0 -or $TTYN -eq 0) {
    $script:RESTARTS = $RESTARTS + 1
    Write-Host ('ttyd dead (origin=' + $code + ' procs=' + $TTYN + '), restarting #' + $script:RESTARTS)
    Get-Process ttyd -EA SilentlyContinue | Stop-Process -Force
    Start-Ttyd
    Start-Sleep -Seconds 5
    $code = OriginCode 7681
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

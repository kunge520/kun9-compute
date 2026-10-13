param(
    [ValidateSet('start', 'stop', 'status', 'console')]
    [string]$Cmd = 'start',
    [int]$Minutes = 60,
    [int]$WaitSec = 420,
    # headless use: no browser window, no ttyd probe, and no secrets printed, because whatever
    # this run writes to stdout is meant to be pasted into a chat or saved to a log
    [switch]$NoGui
)
# Windows browser terminal inside a GitHub-hosted VM on the PUBLIC repo (unmetered), where the
# session password only ever exists as RSA-OAEP ciphertext; this box holds the private key.
$ErrorActionPreference = 'Stop'
$script:NOGUI = [bool]$NoGui
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
# Name the missing file instead of dying on a null-string API header: on a computer that has only the
# packed scripts, this is the first thing you hit, and pat.txt not being there looks like a network bug.
$need = @{ 'pat.txt' = 'the GitHub token'; 'wt_priv.xml' = 'the RSA private key that unseals session.json' }
foreach ($n in $need.Keys) {
    if (-not (Test-Path (Join-Path $env:LOCALAPPDATA ('gh_tools\' + $n)))) {
        Write-Host ('missing %LOCALAPPDATA%\gh_tools\' + $n + '  (' + $need[$n] + ') -- copy it from the old box, this script cannot work without it')
        exit 1
    }
}
$pat = (Get-Content (Join-Path $env:LOCALAPPDATA 'gh_tools\pat.txt') -Raw).Trim()
$privXml = (Get-Content (Join-Path $env:LOCALAPPDATA 'gh_tools\wt_priv.xml') -Raw).Trim()
$h = @{ Authorization = ('Bearer ' + $pat); Accept = 'application/vnd.github+json'; 'User-Agent' = 'fleet-ops' }
$api = 'https://api.github.com/repos/kunge520/kun9-compute'
$wf = 'winterm'
$sessPath = 'winterm/session.json'

function GetJ($u) {
    for ($i = 0; $i -lt 6; $i++) {
        try { return Invoke-RestMethod -Uri $u -Headers $h -TimeoutSec 45 } catch { Start-Sleep -Seconds 4 }
    }
    throw ('GET failed: ' + $u)
}
function RunsOf($wf) {
    return @((GetJ ($api + '/actions/runs?per_page=25')).workflow_runs | Where-Object { $_.name -eq $wf })
}
function GetRaw($u) {
    # curl, not Invoke-WebRequest: PS 5.1 hands back byte[] for application/json, which silently
    # defeats ConvertFrom-Json.
    for ($i = 0; $i -lt 8; $i++) {
        $c = (& curl.exe -4 -sS --ssl-no-revoke -m 45 -H ('Authorization: Bearer ' + $pat) -H 'Accept: application/vnd.github.raw+json' -H 'User-Agent: fleet-ops' $u) -join "`n"
        if ($c) { return ($c.TrimStart([char]0xFEFF)) }
        Start-Sleep -Seconds 3
    }
    return $null
}
function Unseal($b64) {
    $r = New-Object Security.Cryptography.RSACng
    $r.FromXmlString($privXml)
    $plain = $r.Decrypt([Convert]::FromBase64String($b64), [Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
    return [Text.Encoding]::UTF8.GetString($plain)
}
function Pack-to-VM([string]$pubXml, [string]$plain) {
    # RSA can only wrap ~190 bytes at OAEP-SHA256, and the tunnel token is longer, so the token
    # rides an AES-256-CBC blob whose key is what RSA actually encrypts.
    $r = New-Object Security.Cryptography.RSACng
    $r.FromXmlString($pubXml)
    $aes = [Security.Cryptography.Aes]::Create()
    $aes.KeySize = 256
    $aes.GenerateKey()
    $aes.GenerateIV()
    $aes.Mode = [Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [Security.Cryptography.PaddingMode]::PKCS7
    $pt = [Text.Encoding]::UTF8.GetBytes($plain)
    $ct = $aes.CreateEncryptor().TransformFinalBlock($pt, 0, $pt.Length)
    return @{
        k  = [Convert]::ToBase64String($r.Encrypt($aes.Key, [Security.Cryptography.RSAEncryptionPadding]::OaepSHA256))
        iv = [Convert]::ToBase64String($aes.IV)
        d  = [Convert]::ToBase64String($ct)
    }
}
function Show($s, $pass) {
    Write-Host ''
    Write-Host '================  WINDOWS VM  ================'
    Write-Host ('url        ' + $s.url)
    Write-Host ('user       ' + $s.user)
    if (-not $script:NOGUI) { Write-Host ('password   ' + $pass) } else { Write-Host 'password   (suppressed: -NoGui, safe to paste)' }
    Write-Host ('ttl        ' + $s.ttl_min + ' min, ends ' + $s.ends)
    Write-Host ('state      origin_http=' + $s.origin_http + '  restarts=' + $s.restarts + '  checked ' + $s.check)
    if ($s.named) { Write-Host ('tunnel     named=' + $s.named + '  procs=' + $s.named_procs + '  quick=' + $s.cf_procs) }
    if ($s.vm) { Write-Host ('vm         ' + $s.vm + '  cores=' + $s.cores + '  mem=' + $s.mem + '  free_disk=' + $s.free_disk) }
    Write-Host ('console    open it here: powershell -File %LOCALAPPDATA%\gh_tools\_winterm.ps1 -Cmd console')
    Write-Host ('cost       public repo = free hosted Windows runner, no minutes charged')
    Write-Host ('stop       powershell -File %LOCALAPPDATA%\gh_tools\_winterm.ps1 -Cmd stop')
    Write-Host '=============================================='
}
function Probe($s, $pass) {
    # From THIS box, i.e. from behind the GFW: 401 without creds, 200 + a ttyd page with them.
    # Two separate ways this looks dead while it is not:
    #  1. A quick-tunnel hostname does not exist until cloudflared registers it, and Windows DNS
    #     Client CACHES that NXDOMAIN -- so the first lookup poisons the next several. Bypass the
    #     cache by resolving through DoH and pinning the answer with curl --resolve.
    #  2. Cloudflare's own resolver can take ~3 minutes to serve the new record even though the
    #     tunnel is already registered, so give it real patience instead of 48 seconds.
    $hname = ($s.url -replace '^https://', '')
    $f = Join-Path $env:TEMP 'wt_probe.html'
    $no = '000'; $with = '000'; $html = ''; $ip = ''
    for ($i = 1; $i -le 14; $i++) {
        try {
            $d = Invoke-RestMethod -Uri ('https://cloudflare-dns.com/dns-query?name=' + $hname + '&type=A') -Headers @{ Accept = 'application/dns-json' } -TimeoutSec 25
            $ip = (@($d.Answer | Where-Object { $_.type -eq 1 })[0]).data
            if (-not $ip) { $ip = ('no-A(yet,status=' + $d.Status + ')') }
        } catch { $ip = 'doh-failed' }
        $pin = @()
        if ($ip -match '^\d+\.\d+\.\d+\.\d+$') { $pin = @('--resolve', ($hname + ':443:' + $ip)) }
        $a = @('-4', '-sS', '--ssl-no-revoke', '-m', '30') + $pin + @('-o', 'NUL', '-w', '%{http_code}', ($s.url + '/'))
        $no = (& curl.exe @a 2>$null) -join ''
        if ($no -match '^[1-5]\d\d$') {
            $b = @('-4', '-sS', '--ssl-no-revoke', '-m', '30') + $pin + @('-u', ($s.user + ':' + $pass), '-o', $f, '-w', '%{http_code} %{time_total}s %{size_download}B', ($s.url + '/'))
            $with = (& curl.exe @b 2>$null) -join ''
            if (Test-Path $f) { $html = Get-Content $f -Raw; Remove-Item $f -Force }
            break
        }
        Write-Host ('probe ' + $i + '/14: ip=' + $ip + ' http=' + $no + ' -- Cloudflare may not have published the record yet, waiting')
        Start-Sleep -Seconds 20
    }
    Write-Host ('probe      ip=' + $ip + '  no-auth=' + $no + '  with-auth=' + $with + '  ttyd_html=' + [bool]($html -match 'ttyd'))
}

function Invoke-Console($preset) {
    # Open the browser console. There is exactly one way to use the VM now: ttyd served over the
    # named tunnel (wt.kun9.ccwu.cc), which is a command window in the browser. The remote-desktop
    # half was dropped on 2026-10-14 -- nothing listens on 3389 on this box, no local port is
    # forwarded, no hosts entry is written, and the VM never enables Terminal Services at all.
    # The URL and its password ride session.json, the password sealed with the repo's RSA public
    # key, so a public repo still hands it only to the box holding wt_priv.xml.
    $raw = if ($preset) { $preset } else { GetRaw ($api + '/contents/' + $sessPath) }
    if (-not $raw) { Write-Host 'no session.json'; exit 1 }
    $s = if ($preset) { $preset } else { $raw | ConvertFrom-Json }
    if (-not $s.alive) { Write-Host ('session is not alive (closed=' + $s.closed + ')'); exit 1 }
    if (-not $s.url) { Write-Host ('no console url in this session: ' + $s.note); exit 1 }
    $cp = ''
    try { $cp = Unseal $s.cipher } catch { Write-Host 'cannot unseal the console password (wt_priv.xml missing or old?)'; exit 1 }
    # ttyd's basic auth is case-SENSITIVE (measured: administrator=200, Administrator=401), and the
    # VM is the one that started it, so the login printed here is the one the heartbeat carries --
    # not the one in wt_rdp_login.txt, whose first line is the old Windows account name.
    $lu = "$($s.user)"; if (-not $lu) { $lu = 'administrator' }

    # Normally boot.ps1 already started the named connector from the WT_TUNNEL_TOKEN secret. If this
    # VM came up without it, hand the token in through the repo: encrypt to the ephemeral key the VM
    # published, because the repository itself is public and anything plain in it is readable.
    if ($s.named -notlike 'running*') {
        $tokFile = Join-Path $env:LOCALAPPDATA 'gh_tools\wt_tunnel_token.txt'
        if (-not (Test-Path $tokFile)) { Write-Host ('no tunnel token at ' + $tokFile); exit 1 }
        $payload = @{ t = (Get-Content $tokFile -Raw).Trim() } | ConvertTo-Json -Compress
        $env2 = Pack-to-VM $s.vm_pub $payload
        $inbox = @{ run_id = $s.run_id; note = 'named tunnel token'; blob = $env2 } | ConvertTo-Json -Compress -Depth 6
        $body = @{ message = ('winterm inbox ' + $s.run_id); content = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($inbox)); branch = 'main' }
        try { $body.sha = (GetJ ($api + '/contents/winterm/inbox.json')).sha } catch { }
        try {
            Invoke-RestMethod -Uri ($api + '/contents/winterm/inbox.json') -Method Put -Headers $h -Body ([Text.Encoding]::UTF8.GetBytes(($body | ConvertTo-Json -Compress))) -TimeoutSec 60 | Out-Null
            Write-Host ('inbox pushed for run ' + $s.run_id + ' (the VM polls it every 20 s)')
        } catch { Write-Host ('inbox push failed: ' + $_.Exception.Message); exit 1 }
        for ($i = 1; $i -le 12; $i++) {
            Start-Sleep -Seconds 15
            $t = GetRaw ($api + '/contents/' + $sessPath)
            if ($t) { $s = $t | ConvertFrom-Json }
            Write-Host ('  ' + $i + '/12  named=' + $s.named)
            if ($s.named -like 'running*') { break }
        }
    }
    Write-Host ('named      ' + $s.named + '  procs=' + $s.named_procs + '  origin_http=' + $s.origin_http)
    Write-Host ('console    ' + $s.url + '   user=' + $lu + '   ends ' + $s.ends)
    Write-Host ('lapses     ' + $s.ends + '   auto-renew is removed on purpose; start a new machine when you need one')
    if ($script:NOGUI) { Write-Host 'browser    not opened (no-gui run)'; return }
    # ttyd asks for basic auth in the browser; the first answer is remembered by the browser itself,
    # so a re-open after that is one click.
    Start-Process $s.url
}
if ($Cmd -eq 'console') { Invoke-Console $null; exit }

if ($Cmd -eq 'status') {
    $raw = GetRaw ($api + '/contents/' + $sessPath)
    if ($raw) {
        try {
            $s = $raw | ConvertFrom-Json
            if ($s.alive) { $p = Unseal $s.cipher; Show $s $p; Probe $s $p } else { Write-Host ('dead  closed=' + $s.closed + '  run=' + $s.run_id) }
        } catch { Write-Host ('unparseable: ' + $raw) }
    } else { Write-Host 'no session.json published' }
    foreach ($r in (@(RunsOf $wf) | Select-Object -First 5)) {
        Write-Host ('#' + $r.run_number + '  ' + $r.created_at + '  ' + $r.status + ' ' + $r.conclusion + '  ' + $r.html_url)
    }
    $d = GetRaw ($api + '/contents/winterm-diag.json')
    if ($d) { Write-Host ('diag: ' + $d.Substring(0, [Math]::Min(400, $d.Length))) }
    exit
}

if ($Cmd -eq 'stop') {
    $live = @(RunsOf $wf | Where-Object { $_.status -in @('queued', 'in_progress') })
    if ($live.Count -eq 0) { Write-Host 'nothing running' }
    foreach ($r in $live) {
        try {
            Invoke-RestMethod -Uri ($api + '/actions/runs/' + $r.id + '/cancel') -Method Post -Headers $h -TimeoutSec 45 | Out-Null
            Write-Host ('cancelled run #' + $r.run_number)
        } catch { Write-Host ('cancel failed: ' + $_.Exception.Message) }
    }
    try {
        $cur = GetJ ($api + '/contents/' + $sessPath)
        $dead = '{"alive":false,"note":"closed by -Cmd stop","closed":"' + (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd''T''HH:mm:ssZ') + '"}'
        $body = @{ message = 'winterm stop'; content = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($dead)); sha = $cur.sha; branch = 'main' } | ConvertTo-Json -Compress
        Invoke-RestMethod -Uri ($api + '/contents/' + $sessPath) -Method Put -Headers $h -Body ([Text.Encoding]::UTF8.GetBytes($body)) -TimeoutSec 60 | Out-Null
        Write-Host 'session.json marked dead'
    } catch { Write-Host ('mark dead failed: ' + $_.Exception.Message) }
    # A computer still running an OLD kit may have the timer armed; stopping must leave nothing behind,
    # otherwise the machine comes back five minutes later and the stop button looks broken.
    if (Get-ScheduledTask -TaskName 'kun9_wt_renew' -EA SilentlyContinue) {
        Unregister-ScheduledTask -TaskName 'kun9_wt_renew' -Confirm:$false
        Write-Host 'auto-renew task removed as well  (the feature itself was retired on 2026-10-09)'
    }
    exit
}

# start
# one session at a time: two live VMs would both connect the same named tunnel, and cloudflared
# load-balances connections across connectors, so the console could land on the other machine's login.
foreach ($old in @(RunsOf $wf | Where-Object { $_.status -in @('queued', 'in_progress') })) {
    try {
        Invoke-RestMethod -Uri ($api + '/actions/runs/' + $old.id + '/cancel') -Method Post -Headers $h -TimeoutSec 45 | Out-Null
        Write-Host ('retiring previous run #' + $old.run_number)
    } catch { Write-Host ('cancel previous run failed: ' + $_.Exception.Message) }
    Start-Sleep -Seconds 3
}
$prev = 0
$m = @(RunsOf $wf).run_number | Measure-Object -Maximum
if ($m.Maximum) { $prev = [int]$m.Maximum }
Write-Host ('last ' + $wf + ' run_number = ' + $prev + '   requesting ' + $Minutes + ' minutes (public repo, unmetered)')

$tag = [guid]::NewGuid().ToString('N').Substring(0, 6)
$text = $Minutes.ToString() + ' ' + (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') + 'Z ' + $tag + "`n"
$sha = $null
try { $sha = (GetJ ($api + '/contents/trigger.winterm')).sha } catch { }
$body = @{ message = 'winterm ' + $text.Trim(); content = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($text)); branch = 'main' }
if ($sha) { $body.sha = $sha }
$put = $null
$json = $body | ConvertTo-Json -Compress -Depth 6
for ($i = 0; $i -lt 6; $i++) {
    try { $put = Invoke-RestMethod -Uri ($api + '/contents/trigger.winterm') -Method Put -Headers $h -Body ([Text.Encoding]::UTF8.GetBytes($json)) -TimeoutSec 60; break }
    catch { Write-Host ('push attempt ' + ($i + 1) + ': ' + $_.Exception.Message); Start-Sleep -Seconds 5 }
}
if (-not $put) { throw 'could not push trigger.winterm' }

$deadline = (Get-Date).AddSeconds($WaitSec)
$run = $null
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 12
    $new = @(RunsOf $wf | Where-Object { $_.run_number -gt $prev })
    if ($new.Count -gt 0) {
        $run = $new[0]
        Write-Host ('run #' + $run.run_number + '  ' + $run.status + ' ' + $run.conclusion)
        if ($run.status -eq 'completed') { break }
        if ($run.status -eq 'in_progress') { break }
    } else { Write-Host 'queued...' }
}
if (-not $run) { Write-Host 'TIMEOUT: the run never started'; exit 1 }
if ($run.status -eq 'completed' -and $run.conclusion -ne 'success') {
    Write-Host ('run ended ' + $run.conclusion + '  ' + $run.html_url)
    $d = GetRaw ($api + '/contents/winterm-diag.json')
    if ($d) { Write-Host $d }
    exit 1
}

$hit = $null
$d2 = (Get-Date).AddSeconds($WaitSec)
Write-Host ('waiting for the runner to commit ' + $sessPath + ' (run ' + $run.id + ') ...')
while ((Get-Date) -lt $d2) {
    Start-Sleep -Seconds 8
    $raw = GetRaw ($api + '/contents/' + $sessPath)
    if ($raw) {
        try {
            $s = $raw | ConvertFrom-Json
            # 'url' used to be a quick tunnel and the acceptance test matched on 'trycloudflare'. It is
            # wt.kun9.ccwu.cc now (the named tunnel, because the token is in the repo secrets and the
            # connector starts at boot), so matching on that string meant a perfectly good VM was never
            # accepted and -Cmd start sat until WaitSec expired. Any published url + our run id + alive
            # is what "the machine is up" means.
            if ($s.alive -and ('' + $s.run_id) -eq ('' + $run.id) -and ($s.url -or $s.url_quick)) { $hit = $s; break }
        } catch { }
    }
    $chk = @(RunsOf $wf | Where-Object { $_.id -eq $run.id })[0]
    if ($chk.status -eq 'completed') { Write-Host ('run ended ' + $chk.conclusion + '  ' + $chk.html_url); break }
}
if (-not $hit) {
    $d = GetRaw ($api + '/contents/winterm-diag.json')
    if ($d) { Write-Host ('diag: ' + $d) }
    Write-Host ('no session commit -- see ' + $run.html_url)
    exit 1
}
Show $hit (Unseal $hit.cipher)
# The console opens without a second command: hand the tunnel token in, wait for the named
# connector, then open the browser. This runs before the ttyd probe on purpose -- that probe
# retries a Cloudflare DNS publish for up to five minutes and nothing should wait behind it.
Invoke-Console $hit
if (-not $script:NOGUI) { Probe $hit (Unseal $hit.cipher) } else { Write-Host 'probe      ttyd probe skipped (no-gui run)' }

# Auto-renew is retired (2026-10-09, user order): a box that re-spawns a Windows runner every 6 h is
# "Actions as a free VPS", which is the shape GitHub's ToS suspends accounts for, and this computer is
# only powered on occasionally. -Cmd start must therefore NEVER arm a timer again -- and it removes a
# leftover one from an older kit, so an already-armed computer self-heals the moment it is used.
if (Get-ScheduledTask -TaskName 'kun9_wt_renew' -EA SilentlyContinue) {
    Unregister-ScheduledTask -TaskName 'kun9_wt_renew' -Confirm:$false
    Write-Host 'renew    kun9_wt_renew unregistered (feature removed, the machine now simply ends at the cap)'
}

param(
    # flip the scheduled task on or off (this is what the 4th shortcut in Desktop\github xuniji runs)
    [switch]$Toggle,
    # renew even if the current VM still has hours left
    [switch]$Force,
    # look but do not decide: prints what this tick would have seen and exits
    [switch]$Status,
    [int]$Minutes = 350,
    # how much life must be left for the VM to count as "fine"; below this a replacement is started
    [int]$LeadMin = 30,
    # a run that has been queued, or in_progress without an alive session, for longer than this is dead
    [int]$StallMin = 25,
    # a run this young is still booting or still waiting for the tunnel token, so its absence from
    # the edge means nothing yet
    [int]$BootGrace = 12,
    [int]$BridgePort = 13389,
    [string]$TunnelName = 'kun9-wt',
    [int]$WaitSec = 1200
)
# Keep rdp.kun9.ccwu.cc pointing at a live Windows VM forever.
#
# GitHub gives a hosted runner 6 h and no more, and the address/account/password are all fixed by
# the named tunnel + the repo secret, so "permanent" only needs one thing: start a replacement before
# the current one lapses. GitHub's own `schedule` trigger has never fired once for this account
# (measured over several days), so the timer has to live on a box instead of in a cron workflow --
# this box, as a scheduled task every 5 minutes. The decision is read from winterm/session.json,
# which the VM itself republishes on a ~62 s heartbeat, so a VM that wedges is replaced too.
$ErrorActionPreference = 'Continue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$dir = Join-Path $env:LOCALAPPDATA 'gh_tools'
$me = Join-Path $dir '_renew.ps1'
$wm = Join-Path $dir '_winterm.ps1'
$ps = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
$log = Join-Path $dir 'renew.log'
$Task = 'kun9_wt_renew'
$patFile = Join-Path $dir 'pat.txt'
if (-not (Test-Path $patFile)) {
    # a scheduled task has no console, so without this the only trace of "this box is missing its
    # secrets" would be an empty log and a string of 401s.
    Write-Host ('missing ' + $patFile + ' -- copy the gh_tools secret files onto this box first')
    try { ((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') + 'Z missing ' + $patFile) | Add-Content -Path $log -Encoding ascii } catch { }
    exit 1
}
$pat = (Get-Content $patFile -Raw).Trim()
$h = @{ Authorization = ('Bearer ' + $pat); Accept = 'application/vnd.github+json'; 'User-Agent' = 'fleet-ops' }
$api = 'https://api.github.com/repos/kunge520/kun9-compute'

function L($m) {
    # strip anything outside printable ASCII before it reaches the file: this function also logs the
    # child script's output, and a Chinese Windows error message there otherwise lands as mojibake.
    $c = (("" + $m) -replace '[^\x20-\x7e]', '?')
    Write-Host $c
    try { ((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') + 'Z ' + $c) | Add-Content -Path $log -Encoding ascii } catch { }
}
function Roll() {
    if ((Test-Path $log) -and ((Get-Item $log).Length -gt 120000)) {
        try { Set-Content -Path $log -Value (@(Get-Content $log -Tail 200) -join "`n") -Encoding ascii } catch { }
    }
}
function U([string]$s) {
    # session.json and the Actions API use two different ISO shapes; both are UTC.
    return [DateTime]::Parse($s, [Globalization.CultureInfo]::InvariantCulture,
        ([Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal))
}
function Reachable() {
    # "is this machine connectable" cannot be answered from session.json: the VM writes its own
    # heartbeat, and a wedged runner keeps republishing alive=true with hours still on the clock
    # (measured: run #25 said alive for 268 min while Cloudflare had zero connectors on kun9-wt).
    # So ask the edge. Two questions, both must say no before this counts as dead:
    #   x224  -- dial the local bridge and send an RDP negotiation request; a real Windows terminal
    #            server answers 03 00 .. d0. The CF edge accepts the WS upgrade even with nothing on
    #            the other side, so the reply bytes are the proof, not the TCP connect.
    #   tunnel -- the connector state Cloudflare itself holds.
    $cr = [byte[]]@(0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00)
    $x = 'no-answer'
    for ($i = 0; $i -lt 2; $i++) {
        try {
            $c = New-Object Net.Sockets.TcpClient
            $ar = $c.BeginConnect('127.0.0.1', $BridgePort, $null, $null)
            if ($ar.AsyncWaitHandle.WaitOne(15000)) {
                $c.EndConnect($ar); $st = $c.GetStream(); $st.ReadTimeout = 15000
                $st.Write($cr, 0, $cr.Length)
                $b = New-Object byte[] 64
                $n = $st.Read($b, 0, 64)
                $c.Close()
                if ($n -ge 4 -and $b[0] -eq 3 -and $b[1] -eq 0) { $x = 'rdp-ok'; break }
                $x = 'other'
            } else { $c.Close(); $x = 'connect-timeout' }
        } catch { $x = 'no-answer' }
        if ($x -eq 'rdp-ok') { break }
        Start-Sleep -Seconds 8
    }
    $t = 'cf-unknown'
    try {
        . (Join-Path $env:LOCALAPPDATA 'cf_tools\cfapi.ps1')
        $l = CF-GET ('/accounts/' + $script:CFAcct + '/cfd_tunnel')
        if ($l -and $l.success) {
            foreach ($q in @($l.result)) { if ('' + $q.name -eq $TunnelName) { $t = ('' + $q.status) } }
        }
    } catch { $t = 'cf-error' }
    return @{ x = $x; t = $t }
}
function Ensure-Bridge() {
    # the probe above dials the local bridge, so a bridge that died would read as a dead VM
    if (@(Get-NetTCPConnection -LocalPort $BridgePort -State Listen -EA SilentlyContinue).Count -ge 1) { return $true }
    $cli = Join-Path $env:LOCALAPPDATA 'kun9_rdp\rdp.ps1'
    if (-not (Test-Path $cli)) { return $false }
    Start-Process -FilePath $ps -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-WindowStyle', 'Hidden', '-File', $cli, '-Bridge', '-Port', $BridgePort) -WindowStyle Hidden
    for ($i = 0; $i -lt 6; $i++) {
        Start-Sleep -Seconds 5
        if (@(Get-NetTCPConnection -LocalPort $BridgePort -State Listen -EA SilentlyContinue).Count -ge 1) { return $true }
    }
    return $false
}
function Strike($n) {
    $f = Join-Path $dir 'renew.strike'
    if ($n -le 0) { Remove-Item $f -Force -EA SilentlyContinue; return 0 }
    Set-Content -Path $f -Value ($n.ToString() + ' ' + (Get-Date).ToUniversalTime().ToString('s')) -Encoding ascii
    return $n
}
function Strikes() {
    $f = Join-Path $dir 'renew.strike'
    if (-not (Test-Path $f)) { return 0 }
    $n = 0
    try { [void][int]::TryParse(("" + (Get-Content $f -Raw)).Trim().Split(' ')[0], [ref]$n) } catch { }
    # a strike from more than two ticks ago is stale -- a restart of this box should not renew on its own
    if ($n -ge 1) {
        try {
            $age = ((Get-Date) - (Get-Item $f).LastWriteTime).TotalMinutes
            if ($age -gt 20) { return 0 }
        } catch { }
    }
    return $n
}

function LiveRuns() {
    for ($i = 0; $i -lt 4; $i++) {
        try {
            $j = Invoke-RestMethod -Uri ($api + '/actions/runs?per_page=25') -Headers $h -TimeoutSec 45
            $w = @($j.workflow_runs | Where-Object { $_.name -eq 'winterm' })
            return @{ all = $w; live = @($w | Where-Object { $_.status -in @('queued', 'in_progress') }) }
        } catch { Start-Sleep -Seconds 5 }
    }
    return $null
}
function SessionOf() {
    for ($i = 0; $i -lt 5; $i++) {
        $c = (& curl.exe -4 -sS --ssl-no-revoke -m 45 -H ('Authorization: Bearer ' + $pat) -H 'Accept: application/vnd.github.raw+json' -H 'User-Agent: fleet-ops' ($api + '/contents/winterm/session.json')) -join "`n"
        if ($c) {
            try { return ($c.TrimStart([char]0xFEFF) | ConvertFrom-Json) } catch { return $null }
        }
        Start-Sleep -Seconds 4
    }
    return $null
}
function Cancel($r) {
    try {
        Invoke-RestMethod -Uri ($api + '/actions/runs/' + $r.id + '/cancel') -Method Post -Headers $h -TimeoutSec 45 | Out-Null
        L ('cancelled stalled run #' + $r.run_number + ' (' + $r.status + ')')
    } catch { L ('cancel failed: ' + $_.Exception.Message) }
    Start-Sleep -Seconds 20
}
function Renew($why) {
    Strike 0 | Out-Null
    L ('RENEW now  reason=' + $why + '  minutes=' + $Minutes)
    if (-not (Test-Path $wm)) { L ('missing ' + $wm); return }
    # -NoGui on the child is what keeps this from ever opening a Remote Desktop window on this box,
    # and what keeps the session password out of renew.log.
    # pipe, not $o = &: a renew takes 5-15 min and collecting the child's output until it exits means
    # the log has a 15-minute hole exactly when you are wondering whether it is stuck.
    & $ps -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File $wm -Cmd start -Minutes $Minutes -WaitSec $WaitSec -NoGui 2>&1 | ForEach-Object { L ('   | ' + (("" + $_) -replace "`r|`n", '')) }
    L ('RENEW done exit=' + $LASTEXITCODE)
}
function Register-Task() {
    $a = New-ScheduledTaskAction -Execute $ps -Argument ('-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "' + $me + '"')
    $tr = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 5)
    $st = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero) -StartWhenAvailable
    $pr = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType S4U -RunLevel Limited
    Register-ScheduledTask -TaskName $Task -Action $a -Trigger $tr -Settings $st -Principal $pr -Description 'Keep the GitHub Actions Windows VM at rdp.kun9.ccwu.cc renewed before its 6h cap' -Force | Out-Null
}

Roll
if ($Toggle) {
    $cur = Get-ScheduledTask -TaskName $Task -EA SilentlyContinue
    if ($cur) {
        Unregister-ScheduledTask -TaskName $Task -Confirm:$false
        L 'auto-renew OFF  task removed, the current VM will simply lapse after its remaining time'
    } else {
        try { Register-Task; L ('auto-renew ON  task ' + $Task + ' every 5 min, swaps the VM at ' + $LeadMin + ' min of life left') }
        catch { L ('could not register the task: ' + $_.Exception.Message) }
    }
    exit 0
}

L '--- check ---'
$lr = LiveRuns
if (-not $lr) { L 'GitHub API unreachable, nothing decided'; exit 1 }
$s = SessionOf
$now = (Get-Date).ToUniversalTime()
$rem = -9999.0
$alive = [bool]($s -and $s.alive)
if ($alive -and $s.ends) { try { $rem = [math]::Round(((U ('' + $s.ends)) - $now).TotalMinutes, 1) } catch { $rem = -9999 } }
$live = @($lr.live)
L ('state  live_runs=' + $live.Count + '  session_alive=' + $alive + '  ends=' + $(if ($alive) { $s.ends } else { '-' }) + '  min_left=' + $rem)

# session.json is written by ONE run, so age and health must be read off that same run: the list is
# newest-first, and the previous run stays 'in_progress' for ~30 s after the renewer cancels it, which
# is long enough for the oldest entry to be a dying machine and make a brand-new one look stale.
$r0 = $null
$age = -1.0
if ($live.Count -gt 0) {
    $r0 = $live[0]
    if ($alive -and $s.run_id) {
        foreach ($q in $live) { if ('' + $q.id -eq ('' + $s.run_id)) { $r0 = $q; break } }
    }
    $age = [math]::Round(($now - (U ('' + $r0.created_at))).TotalMinutes, 1)
}

if ($Status) {
    # read-only view of everything a tick can see, with no branch that can start or cancel a VM
    if ($r0) { L ('run      #' + $r0.run_number + '  ' + $r0.status + '  age=' + $age + ' min  id=' + $r0.id) }
    else { L 'run      none live' }
    if ($alive) {
        if (Ensure-Bridge) { $r = Reachable; L ('edge     x224=' + $r.x + '  tunnel=' + $r.t) }
        else { L ('edge     no local bridge listening on ' + $BridgePort) }
    }
    L ('renewer  task_on=' + (@(Get-ScheduledTask -TaskName $Task -EA SilentlyContinue).Count -ge 1) + '  strikes=' + (Strikes) + '  log=' + $log)
    exit 0
}

if ($Force) { Renew 'forced'; exit 0 }

if ($live.Count -eq 0) {
    # nothing is running, so nothing is listening at the tunnel -- whatever session.json claims.
    Renew $(if ($alive) { 'no runner alive but session.json still says alive' } else { 'no runner alive' })
    exit 0
}

if ($alive -and $rem -gt $LeadMin) {
    if ($age -le $BootGrace) {
        L ('ramping  #' + $r0.run_number + ' age=' + $age + ' min (grace ' + $BootGrace + '), swap due in ' + [math]::Round(($rem - $LeadMin), 0) + ' min')
        Strike 0 | Out-Null
        exit 0
    }
    if (-not (Ensure-Bridge)) { L 'bridge is not listening and would not start, so this tick cannot judge anything'; exit 0 }
    $r = Reachable
    if ($r.x -eq 'rdp-ok' -or $r.t -eq 'healthy') {
        Strike 0 | Out-Null
        L ('steady   #' + $r0.run_number + ' x224=' + $r.x + ' tunnel=' + $r.t + ', swap due in ' + [math]::Round(($rem - $LeadMin), 0) + ' min')
        exit 0
    }
    $n = Strike ((Strikes) + 1)
    L ('suspect  #' + $r0.run_number + ' x224=' + $r.x + ' tunnel=' + $r.t + ' strike=' + $n + '/2')
    if ($n -lt 2) { exit 0 }
    Renew ('session.json says alive with ' + $rem + ' min left but nothing answers at the edge (x224=' + $r.x + ' tunnel=' + $r.t + ')')
    exit 0
}
$old = $r0
$why = ''
if ($old.status -eq 'queued' -and $age -gt $StallMin) { $why = 'queued for ' + $age + ' min without a runner' }
elseif ($old.status -eq 'in_progress' -and $age -gt $StallMin -and -not $alive) { $why = 'in_progress for ' + $age + ' min with no live session' }
elseif ($alive) { $why = 'only ' + $rem + ' min of life left (lead is ' + $LeadMin + ')' }
else {
    L ('waiting  #' + $r0.run_number + ' ' + $r0.status + ' age=' + $age + ' min, session not published yet -- no action until ' + $StallMin + ' min')
    exit 0
}
Cancel $old
Renew $why
exit 0

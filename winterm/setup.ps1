param(
    # connect the running VM over Remote Desktop and exit (this is what the one-line paste runs after
    # the first install). No buttons, no keys copy, no GitHub token needed beyond what -Cmd rdp wants.
    [switch]$Rdp,
    # where the four buttons are written; defaults to the folder this file sits in
    [string]$Dir = '',
    # accept a download whose SHA1 is not the pinned one -- only for when a newer version has been
    # shipped and this computer still holds an old copy of this script
    [switch]$Trust,
    [switch]$NoPause,
    [switch]$NoButtons,
    [switch]$Force
)
$ErrorActionPreference = 'Continue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$ProgressPreference = 'SilentlyContinue'

# ONE file is meant to be all you carry to a new computer. Everything else is fetched from the cloud,
# tried in this order:
#   1. jsDelivr    -- mirrors the GitHub repo, usually reachable from inside China
#   2. GitHub raw  -- the same bytes, straight from the repo
#   3. Worker relay ch.kun9.ccwu.cc -- see the warning below
#   4. a copy sitting next to this script, if you kept one
# GitHub first because writing there takes my token. The relay's /report/<box> upload route is open to
# anyone, so a relay copy is only accepted when its SHA1 matches $Pin -- otherwise a stranger could
# hand this computer a script that runs with the user's GitHub token.
$Repo = 'kunge520/kun9-compute'
$Jd  = 'https://cdn.jsdelivr.net/gh/' + $Repo + '@main/winterm/'
$Raw = 'https://raw.githubusercontent.com/' + $Repo + '/main/winterm/'
$Mx  = 'https://ch.kun9.ccwu.cc/mxd/'

# local name -> repo file, relay file, pinned sha1 ('' = nothing pinned yet)
$Pin = @{
    '_winterm.ps1' = @{ gh = 'winterm.ps1'; mx = 'rig_gh_winterm.txt'; sha = '50d7f2f0258457e40a1e7f15fe77f1ac3c2cc4b5' }
}

$tool = Join-Path $env:LOCALAPPDATA 'gh_tools'
$rdpDir = Join-Path $env:LOCALAPPDATA 'kun9_rdp'
if (-not (Test-Path $tool)) { New-Item -ItemType Directory -Path $tool -Force | Out-Null }
$Keys = @('pat.txt', 'wt_priv.xml', 'wt_rdp_login.txt', 'wt_tunnel_token.txt')

function Sha1($p) { (Get-FileHash -Path $p -Algorithm SHA1).Hash.ToLower() }
function A($s) { ('' + $s) -replace '[^\x20-\x7e]', '?' }

function Fetch([string]$name, [string]$dst) {
    # returns $null on total failure, else @{ src; sha; bytes }
    $p = $Pin[$name]
    if (-not $p) { Write-Host ('bad   nothing known about ' + $name); return $null }
    $tries = @(
        @{ u = ($Jd + $p.gh);  trusted = $true;  tag = 'jsdelivr' },
        @{ u = ($Raw + $p.gh); trusted = $true;  tag = 'github-raw' },
        @{ u = ($Mx + $p.mx);  trusted = $false; tag = 'relay' }
    )
    $tmp = Join-Path $env:TEMP ('kun9_fetch_' + [IO.Path]::GetRandomFileName())
    foreach ($t in $tries) {
        Remove-Item $tmp -Force -EA SilentlyContinue
        # curl.exe, not Invoke-WebRequest: jsDelivr answers 200 to curl and 404 to PowerShell's default
        # user-agent, which would make the fastest mirror look dead. Windows 10 1803+ ships curl.
        & curl.exe -4 -sS --ssl-no-revoke -L -m 60 -A 'Mozilla/5.0' -o $tmp $t.u | Out-Null
        if ((-not (Test-Path $tmp)) -or ($LASTEXITCODE -ne 0)) {
            Write-Host ('  try   ' + $t.tag + ' failed (curl ' + $LASTEXITCODE + ')')
            continue
        }
        $len = (Get-Item $tmp).Length
        if ($len -lt 800) { Write-Host ('  try   ' + $t.tag + ' only ' + $len + ' B, ignoring'); continue }
        $head = ([IO.File]::ReadAllText($tmp)).Substring(0, [Math]::Min(300, $len))
        # an error page or a GitHub 404 body both pass for content otherwise
        if ($head -match '(?i)<!DOCTYPE|"error"|rate limit') {
            Write-Host ('  try   ' + $t.tag + ' returned a page, not a script'); continue
        }
        $sha = Sha1 $tmp
        if ($p.sha -and ($p.sha -ne $sha) -and -not $Trust) {
            if ($t.trusted) {
                # GitHub is where I ship to, so a changed hash there means a real new version
                Write-Host ('  NOTE  ' + $t.tag + ' is ' + $sha.Substring(0, 12) + ', this copy of setup.ps1 pins ' + $p.sha.Substring(0, 12) + ' -- using it')
            } else {
                Write-Host ('  HOLD  ' + $t.tag + ' is ' + $sha.Substring(0, 12) + ' but the pin says ' + $p.sha.Substring(0, 12) + '. Unwritable relay? Skipping it; re-run with -Trust only if you know a new version shipped.')
                continue
            }
        }
        Copy-Item $tmp $dst -Force
        Remove-Item $tmp -Force -EA SilentlyContinue
        return @{ src = $t.tag; sha = $sha; bytes = $len }
    }
    return $null
}

function NearPinned([string]$name, [string]$dst) {
    # The packed folder carries offline copies of these scripts. When the one sitting next to this
    # script has exactly the SHA1 this script pins, it IS the version I shipped, so use it and skip the
    # download -- jsDelivr keeps serving the previous bytes for minutes after a release (measured again
    # 2026-10-13: purge answered status=finished, the CDN still returned the old file), which otherwise
    # installs a stale script onto the computer that was just carried the fix in.
    $p = $Pin[$name]
    if (-not ($PSScriptRoot -and $p -and $p.sha)) { return $false }
    $c = Join-Path $PSScriptRoot $name
    if (-not (Test-Path $c)) { return $false }
    if ((Sha1 $c) -ne $p.sha) { return $false }
    if ((Test-Path $dst) -and ((Sha1 $dst) -eq $p.sha)) { Write-Host ('ok     ' + $name + '  already the pinned version'); return $true }
    Copy-Item $c $dst -Force
    Write-Host ('inst   ' + $name + '  from this folder -- it matches the pin, no download needed')
    return $true
}

function Place([string]$name, [string]$dstDir) {
    $dst = Join-Path $dstDir $name
    $near = $null
    if ($PSScriptRoot) { $c = Join-Path $PSScriptRoot $name; if (Test-Path $c) { $near = $c } }
    if (NearPinned $name $dst) { return $true }
    if ($Force -or -not (Test-Path $dst)) {
        $r = Fetch $name $dst
        if ($r) { Write-Host ('inst   ' + $name + '  ' + $r.bytes + ' B  ' + $r.src + '  sha1=' + $r.sha.Substring(0, 12)); return $true }
        if ($near) { Copy-Item $near $dst -Force; Write-Host ('inst   ' + $name + '  from the copy next to this script'); return $true }
        Write-Host ('MISS   ' + $name + '  cloud unreachable and no local copy'); return $false
    }
    $r = Fetch $name $dst
    if ($r) { Write-Host ('ok     ' + $name + '  ' + $r.bytes + ' B  ' + $r.src) }
    else {
        if ($near) { Write-Host ('ok     ' + $name + '  (kept the one on this computer, cloud unreachable)') }
        else { Write-Host ('MISS   ' + $name + '  cloud unreachable'); return $false }
    }
    return $true
}

# ------------------------------------------------------------------ RDP only
if ($Rdp) {
    # Remote Desktop is one command now: whatever -Cmd rdp does on a fully installed machine.
    $wm = Join-Path $tool '_winterm.ps1'
    if (-not (Test-Path $wm)) { [void](Place '_winterm.ps1' $tool) }
    if (-not (Test-Path $wm)) {
        Write-Host 'FAIL   no _winterm.ps1 and the cloud is unreachable -- double-click 1 (it installs itself first).'
        if (-not $NoPause) { Read-Host 'Press Enter' | Out-Null }
        exit 1
    }
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
    & $wm -Cmd rdp
    exit $LASTEXITCODE
}

# ------------------------------------------------------------------ full install
Write-Host '== scripts =='
$got = @{}
foreach ($n in @('_winterm.ps1')) { $got[$n] = Place $n $tool }

# ---- retired: the WebSocket bridge and everything that kept it running ----
# Remote Desktop goes over the Tailscale tailnet now, so the 13389 bridge, its logon task and its
# startup entry are all dead weight. Removing them is what makes an upgraded computer behave like a
# fresh one; the folder itself is left in place in case it still holds something worth looking at.
$sl = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup\kun9-bridge.lnk'
if (Test-Path $sl) { Remove-Item $sl -Force; Write-Host 'clean  startup entry kun9-bridge.lnk removed' }
try {
    if (Get-ScheduledTask -TaskName 'kun9_rdp_bridge' -EA SilentlyContinue) {
        Unregister-ScheduledTask -TaskName 'kun9_rdp_bridge' -Confirm:$false -ErrorAction Stop
        Write-Host 'clean  logon task kun9_rdp_bridge removed'
    }
} catch { Write-Host ('clean  kun9_rdp_bridge could not be removed: ' + (($_.Exception.Message) -split "`r?`n")[0]) }
$stale = @(Get-Content (Join-Path $env:WINDIR 'System32\drivers\etc\hosts') -EA SilentlyContinue | Where-Object { $_ -match 'rdp\.kun9\.ccwu\.cc' })
if ($stale.Count) {
    Write-Host ('note   hosts still carries ' + $stale.Count + ' old rdp.kun9.ccwu.cc line(s). They are harmless but pointless now;')
    Write-Host ('       to drop them: open ' + (Join-Path $env:WINDIR 'System32\drivers\etc\hosts') + ' in Notepad as Administrator and delete those lines.')
}
if (Test-Path $rdpDir) { Write-Host ('note   ' + $rdpDir + ' is no longer read by anything; keep or delete it as you like') }

Write-Host '== keys =='
# These four cannot live in the cloud: pat.txt IS the GitHub token and wt_priv.xml unseals every
# session password. They travel in the 密钥-换电脑拷走 folder next to this script.
foreach ($n in $Keys) {
    $dst = Join-Path $tool $n
    $found = $null
    foreach ($b in @($PSScriptRoot, $Dir)) {
        if (-not $b) { continue }
        $c = Join-Path (Join-Path $b '密钥-换电脑拷走') $n
        if (Test-Path $c) { $found = $c; break }
    }
    if (-not (Test-Path $dst)) {
        if ($found) { Copy-Item $found $dst -Force; Write-Host ('inst   ' + $n + ' -> gh_tools') }
        else { Write-Host ('MISS   ' + $n + '  -- put it in 密钥-换电脑拷走, nothing works without it') }
        continue
    }
    if ($found) {
        if ((Sha1 $found) -eq (Sha1 $dst)) { Write-Host ('ok     ' + $n) }
        elseif ($Force) { Copy-Item $found $dst -Force; Write-Host ('force  ' + $n + ' replaced') }
        else { Write-Host ('keep   ' + $n + ' already here and different (-Force to replace)') }
    } else { Write-Host ('ok     ' + $n + ' (already on this computer)') }
}

Write-Host '== buttons =='
if (-not $Dir) { $Dir = if ($PSScriptRoot) { $PSScriptRoot } else { [Environment]::GetFolderPath('Desktop') } }
# A .lnk stores an ABSOLUTE path, which is why copying this folder to another computer (or into another
# account on it) left the three buttons pointing at C:\Users\<whoever>\AppData\Local\gh_tools and
# double-clicking did nothing. The buttons are .cmd files now: they find the scripts through
# %LOCALAPPDATA% and this folder through %~dp0, so the folder can sit anywhere on any account.
# _run.cmd is the shared worker; on a computer that has never been set up it installs first.
$launcher = @(
    '@echo off',
    'setlocal',
    'set "TOOL=%LOCALAPPDATA%\gh_tools"',
    'set "WM=%TOOL%\_winterm.ps1"',
    'set "PS=%WINDIR%\System32\WindowsPowerShell\v1.0\powershell.exe"',
    'if not exist "%WM%" (',
    '  echo first run on this computer -- installing the scripts and the keys, one moment',
    '  powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0setup.ps1" -NoPause -NoButtons',
    ')',
    'if not exist "%WM%" (',
    '  echo FAILED: %WM% is still missing. Run setup.ps1 by hand and read what it prints.',
    '  pause',
    '  exit /b 1',
    ')',
    'start "" "%PS%" -NoProfile -ExecutionPolicy Bypass -NoExit -File "%WM%" %*'
)
Set-Content -Path (Join-Path $Dir '_run.cmd') -Value $launcher -Encoding ascii
Write-Host 'cmd    _run.cmd'
if ($NoButtons) { Write-Host 'skip   the three buttons were not rewritten (-NoButtons)' }
else {
    $items = @(
        @{ n = '1-开一台新的虚拟机.cmd'; a = '-Cmd start -Minutes 350' },
        @{ n = '2-连上去-远程桌面.cmd'; a = '-Cmd rdp' },
        @{ n = '3-停止这台虚拟机.cmd'; a = '-Cmd stop' }
    )
    foreach ($i in $items) {
        $p = Join-Path $Dir $i.n
        # the inner parentheses matter: without them ',' binds looser than '+' and the argument lands on
        # a second line, so the button would run _run.cmd with NO -Cmd (which means start = a new VM)
        # and then try to execute '-Cmd rdp' as a command.
        Set-Content -Path $p -Value @('@echo off', ('call "%~dp0_run.cmd" ' + $i.a)) -Encoding ascii
        Write-Host ('cmd    ' + $i.n)
        # the old absolute-path shortcut for this button, if a previous kit left one here
        $old = [IO.Path]::ChangeExtension($p, '.lnk')
        if (Test-Path $old) { Remove-Item $old -Force; Write-Host ('gone   ' + [IO.Path]::GetFileName($old)) }
    }
}

Write-Host '== remove auto-renew =='
# 自动续机（到期前自动换一台）在 2026-10-09 按用户要求彻底删除：每 6 小时不断重开一台 Windows
# runner 就是"把 Actions 当免费 VPS"，这正是 GitHub 会封号的那一类用法；而这台机器只是偶尔开机。
# 这里不只跳过安装，还要把旧版本 kit 装好的东西清掉，所以任何一台装过旧 kit 的电脑跑一次本脚本
# 就自愈：任务注销、_renew.ps1 删除、第 4 个按钮删除。
$old = @(Get-ScheduledTask -TaskName 'kun9_wt_renew' -EA SilentlyContinue)
if ($old.Count -ge 1) {
    try { Unregister-ScheduledTask -TaskName 'kun9_wt_renew' -Confirm:$false; Write-Host 'task   kun9_wt_renew unregistered' }
    catch { Write-Host ('task   CANNOT unregister kun9_wt_renew: ' + $_.Exception.Message) }
} else { Write-Host 'task   kun9_wt_renew not present (correct)' }
foreach ($f in @((Join-Path $tool '_renew.ps1'), (Join-Path $Dir '4-自动续机-开或关.lnk'))) {
    if (Test-Path $f) {
        try { Remove-Item $f -Force; Write-Host ('gone   ' + $f) }
        catch { Write-Host ('keep   could not delete ' + $f + ': ' + $_.Exception.Message) }
    }
}
Write-Host 'note   虚拟机到 6 小时上限会自己结束，地址不变；要用就再点一次 1-开一台新的虚拟机'
Write-Host ('done   buttons written to ' + $Dir)
if (-not $NoPause) { Read-Host 'Press Enter to close' | Out-Null }

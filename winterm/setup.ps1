param(
    # only set up the RDP bridge on this computer (this is what the one-line paste runs). No buttons,
    # no keys, no GitHub token needed.
    [switch]$Rdp,
    # where the four buttons are written; defaults to the folder this file sits in
    [string]$Dir = '',
    # accept a download whose SHA1 is not the pinned one -- only for when a newer version has been
    # shipped and this computer still holds an old copy of this script
    [switch]$Trust,
    [switch]$NoPause,
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
    'rdp.ps1'      = @{ gh = 'rdp.ps1';     mx = 'rig_rdp.txt';        sha = 'f6aa05e9ad5aab01a826d3ffc997cfcf12731869' }
    '_winterm.ps1' = @{ gh = 'winterm.ps1'; mx = 'rig_gh_winterm.txt'; sha = 'b5d2cfbff99ebf124967ccf47eac2aed2aeef597' }
    '_renew.ps1'   = @{ gh = 'renew.ps1';   mx = 'rig_gh_renew.txt';   sha = 'db7b93ce54417f19166e2a1ebfe98d7278e418a0' }
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

function Place([string]$name, [string]$dstDir) {
    $dst = Join-Path $dstDir $name
    $near = $null
    if ($PSScriptRoot) { $c = Join-Path $PSScriptRoot $name; if (Test-Path $c) { $near = $c } }
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
    if (-not (Test-Path $rdpDir)) { New-Item -ItemType Directory -Path $rdpDir -Force | Out-Null }
    $dst = Join-Path $rdpDir 'rdp.ps1'
    $r = Fetch 'rdp.ps1' $dst
    if (-not $r) {
        Write-Host 'FAIL   rdp.ps1 could not be downloaded from jsdelivr, github-raw or the relay.'
        Write-Host '       Put rdp.ps1 here by hand (from the packed folder) and double-click it.'
        if (-not $NoPause) { Read-Host 'Press Enter' | Out-Null }
        exit 1
    }
    Write-Host ('got    rdp.ps1  ' + $r.bytes + ' B  from ' + $r.src + '  sha1=' + $r.sha.Substring(0, 12))
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
    & $dst
    exit $LASTEXITCODE
}

# ------------------------------------------------------------------ full install
Write-Host '== scripts =='
$got = @{}
foreach ($n in @('rdp.ps1', '_winterm.ps1', '_renew.ps1')) { $got[$n] = Place $n $tool }

# rdp.ps1 must also sit where the logon task looks for it
$src = Join-Path $tool 'rdp.ps1'
if (Test-Path $src) {
    if (-not (Test-Path $rdpDir)) { New-Item -ItemType Directory -Path $rdpDir -Force | Out-Null }
    $d2 = Join-Path $rdpDir 'rdp.ps1'
    if (-not (Test-Path $d2) -or (Sha1 $src) -ne (Sha1 $d2)) {
        Copy-Item $src $d2 -Force; Write-Host 'sync   kun9_rdp\rdp.ps1'
    } else { Write-Host 'sync   kun9_rdp\rdp.ps1 already same' }
}

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
$ps = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
$wm = Join-Path $tool '_winterm.ps1'
$rn = Join-Path $tool '_renew.ps1'
$sh = New-Object -ComObject WScript.Shell
$items = @(
    @{ n = '1-开一台新的虚拟机.lnk'; t = $wm; a = ('-NoProfile -ExecutionPolicy Bypass -NoExit -File "' + $wm + '" -Cmd start -Minutes 350'); d = '开一台新的 GitHub Windows 虚拟机，起来后自动弹出远程桌面。一般 3-8 分钟，排队久时十几分钟。' },
    @{ n = '2-连上去-远程桌面.lnk'; t = $wm; a = ('-NoProfile -ExecutionPolicy Bypass -NoExit -File "' + $wm + '" -Cmd rdp'); d = '连现在这台：检查隧道和虚拟机状态，然后打开远程桌面。' },
    @{ n = '3-停止这台虚拟机.lnk'; t = $wm; a = ('-NoProfile -ExecutionPolicy Bypass -NoExit -File "' + $wm + '" -Cmd stop'); d = '立刻停掉当前虚拟机（取消 GitHub 上的任务），清掉保存的登录信息，并关掉自动续机。' },
    @{ n = '4-自动续机-开或关.lnk'; t = $rn; a = ('-NoProfile -ExecutionPolicy Bypass -NoExit -File "' + $rn + '" -Toggle'); d = '自动续机开关：开着的话，到期前 30 分钟自动换一台新的，地址账号密码都不变。' }
)
foreach ($i in $items) {
    $p = Join-Path $Dir $i.n
    $l = $sh.CreateShortcut($p)
    $l.TargetPath = $ps
    $l.Arguments = $i.a
    $l.WorkingDirectory = $Dir
    $l.WindowStyle = 1
    $l.Description = $i.d
    $l.Save()
    Write-Host ('lnk    ' + $i.n)
}

Write-Host '== auto-renew =='
# A fresh computer has no timer at all, and a machine nobody renews dies at the 6 h mark. -Toggle would
# flip a switch that is already on, so it is only called when the task does not exist.
$have = @(Get-ScheduledTask -TaskName 'kun9_wt_renew' -EA SilentlyContinue).Count
if ($have -ge 1) { Write-Host 'task   kun9_wt_renew already installed, untouched' }
elseif (Test-Path $rn) {
    & $ps -NoProfile -ExecutionPolicy Bypass -File $rn -Toggle 2>&1 | ForEach-Object { Write-Host (A $_) }
} else { Write-Host 'task   cannot arm, _renew.ps1 missing' }

Write-Host '== check =='
& $ps -NoProfile -ExecutionPolicy Bypass -File $rn -Status 2>&1 | ForEach-Object { Write-Host (A $_) }
Write-Host ('done   buttons written to ' + $Dir)
if (-not $NoPause) { Read-Host 'Press Enter to close' | Out-Null }

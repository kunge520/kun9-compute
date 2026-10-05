param(
    [switch]$Bridge,
    [switch]$Stop,
    [switch]$OnlyHosts,
    [switch]$NoMstsc,
    [int]$Port = 0,
    [string]$Domain = 'rdp.kun9.ccwu.cc',
    [string]$Edge = 'wss://wtedge.kun9.ccwu.cc/'
)
# RDP into the GitHub Actions Windows box from any Windows computer, with nothing to install.
#
# Cloudflare's edge refuses raw TCP 3389 (measured from here: 3389 -> timeout, 443 -> CONNECTED), so
# mstsc cannot dial a tunneled hostname directly. The tunnel does answer a plain, unauthenticated
# WebSocket upgrade on a tcp-ingress hostname and then carries raw bytes, which PowerShell's
# ClientWebSocket can pump -- so this file replaces cloudflared (a 55 MB binary that is impractical to
# fetch behind the GFW) and needs no admin either.
#
#   rdp.ps1              connect: make sure a bridge is running, then open Remote Desktop
#   rdp.ps1 -Bridge      the bridge itself (hidden worker / logon task)
#   rdp.ps1 -Stop        tear the bridge down
#
# On a computer that has never had it, one paste into a PowerShell window does all of the above and
# leaves a Start-menu entry. Deliberately quote-free so it also survives being pasted into cmd:
#   $P=Join-Path $env:LOCALAPPDATA kun9_rdp;$F=Join-Path $P rdp.ps1;md $P|Out-Null;Set-ExecutionPolicy Bypass -Scope Process -Force;iwr -UseBasicParsing https://ch.kun9.ccwu.cc/mxd/rig_rdp.txt -o $F;& $F
#
# Run it once and Remote Desktop can then use the domain name directly for as long as the bridge is up.
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$dir = Join-Path $env:LOCALAPPDATA 'kun9_rdp'
if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
$log = Join-Path $dir 'bridge.log'
$dst = Join-Path $dir 'rdp.ps1'
$self = if ($PSCommandPath) { $PSCommandPath } else { $dst }
if ($PSCommandPath -and ($PSCommandPath -ne $dst)) {
    # Whatever copy was started, keep the canonical one in %LOCALAPPDATA%: the bridge is relaunched as a
    # hidden child from that path, and the elevated hosts pass re-execs it too.
    try { Copy-Item $PSCommandPath $dst -Force } catch { }
}
if (-not $Bridge -and -not $OnlyHosts) {
    # One paste and it is in the Start menu for every later session. The name is built from code points
    # so this file stays pure ASCII: it is served over HTTP and pasted into shells.
    $cn = -join ([char[]]@(0x8FDC, 0x7A0B, 0x684C, 0x9762))
    $lnkPath = Join-Path $env:APPDATA ('Microsoft\Windows\Start Menu\Programs\' + $cn + '-kun9.lnk')
    if (-not (Test-Path $lnkPath)) {
        try {
            $sc = (New-Object -ComObject WScript.Shell).CreateShortcut($lnkPath)
            $sc.TargetPath = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
            $sc.Arguments = '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "' + $dst + '"'
            $sc.IconLocation = (Join-Path $env:WINDIR 'System32\mstsc.exe,0')
            $sc.Description = $cn + ' ' + $Domain
            $sc.Save()
        } catch { }
    }
}
$hostsPath = Join-Path $env:WINDIR 'System32\drivers\etc\hosts'

function L([string]$m) {
    $t = (Get-Date).ToString('MM-dd HH:mm:ss') + ' ' + (($m -replace '[^\x20-\x7e]', '?'))
    Add-Content -Path $log -Value $t -Encoding ascii
}
function IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
function PortFree([int]$p) {
    $used = @()
    try { $used = (Get-NetTCPConnection -State Listen -EA SilentlyContinue).LocalPort } catch { }
    return -not ($used -contains $p)
}
function WaitT($task, [int]$ms) {
    # Wait() on a FAULTED task throws an AggregateException instead of returning false. Left bare, a
    # single failed WebSocket dial punched straight out of the retry loop and tore mstsc's socket
    # (bridge.log said "#5 error ...Wait..." rather than "#5 dial try 1/2/3 failed"). A timeout or a
    # dead socket is a normal outcome here, so it must never be an exception.
    try { return [bool]$task.Wait($ms) } catch { return $false }
}
function BridgeProcs {
    return @(Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -EA SilentlyContinue |
        Where-Object { $_.CommandLine -match 'rdp\.ps1' -and $_.CommandLine -match '-Bridge' })
}
function ListeningPort {
    foreach ($bp in BridgeProcs) {
        if ($bp.CommandLine -match '-Port\s+(\d+)') {
            $p = [int]$matches[1]
            $up = @(Get-NetTCPConnection -State Listen -LocalAddress 127.0.0.1 -LocalPort $p -EA SilentlyContinue).Count
            if ($up -ge 1) { return $p }
        }
    }
    return 0
}

if ($Stop) {
    foreach ($bp in BridgeProcs) { try { Stop-Process -Id $bp.ProcessId -Force -EA SilentlyContinue } catch { } }
    & schtasks.exe /delete /tn kun9_rdp_bridge /f 2>&1 | Out-Null
    L 'stopped'
    Write-Host ('bridge stopped, procs left=' + (@(BridgeProcs).Count))
    exit 0
}

if ($OnlyHosts) {
    # Separate elevated pass, run once per computer. Two things live in hosts:
    #   the user-facing name -> 127.0.0.1, so Remote Desktop can be pointed at the domain;
    #   the edge name -> its IPv4 addresses, because Windows PowerShell prefers AAAA and the IPv6 path
    #   to Cloudflare from this network just stalls (dial times out at 12 s, pins connect in ~6 s).
    $t = Get-Content $hostsPath -Raw -EA SilentlyContinue
    if ($t -notmatch ('(?m)^\s*127\.0\.0\.1\s+' + [regex]::Escape($Domain) + '\b')) {
        Add-Content -Path $hostsPath -Value ("127.0.0.1 `t$Domain`t# kun9 RDP WebSocket bridge") -Encoding ascii
        L 'hosts entry added'
    }
    $eh = ([Uri]$Edge).Host
    $v4 = @(Resolve-DnsName $eh -Type A -EA SilentlyContinue | Where-Object { $_.IPAddress } | ForEach-Object { $_.IPAddress })
    if ($v4.Count -eq 0) { $v4 = @('172.67.203.71', '104.21.37.23') }
    foreach ($ip in $v4) {
        if ((Get-Content $hostsPath -Raw) -notmatch ('(?m)^\s*' + [regex]::Escape($ip) + '\s+' + [regex]::Escape($eh) + '\b')) {
            Add-Content -Path $hostsPath -Value ("$ip `t$eh`t# kun9 RDP bridge IPv4 pin") -Encoding ascii
            L ('pinned ' + $eh + ' -> ' + $ip)
        }
    }
    exit 0
}

if ($Bridge) {
    if ($Port -le 0) { $Port = 13389 }
    try {
        # A permanent logon task writes a flow line every 15 s, so this file is the one thing about
        # this design that does grow. Trim it once at startup rather than on every write.
        if ((Test-Path $log) -and ((Get-Item $log).Length -gt 524288)) {
            (@(Get-Content $log -EA SilentlyContinue) | Select-Object -Last 400) | Set-Content -Path $log -Encoding ascii
        }
    } catch { }
    $listener = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback, $Port)
    try { $listener.Start() } catch {
        L ('bind failed on ' + $Port + ': ' + $_.Exception.Message)
        Write-Host ('bind-failed ' + $Port); exit 2
    }
    ('{0}' + $Port) | Out-File -FilePath (Join-Path $dir 'port.txt') -Encoding ascii
    L ('bridge up 127.0.0.1:' + $Port + ' -> ' + $Edge)
    # Two buffers, never one: ReceiveAsync keeps writing into its target while the send path is still
    # filling it from the socket, and sharing a buffer corrupts the RDP stream -- mstsc reports that as
    # "because of a data encryption error, this session will end".
    $tbuf = New-Object byte[] 32768
    $rbuf = New-Object byte[] 32768
    $ct = [Threading.CancellationToken]::None
    $n = 0
    while ($true) {
        $cli = $listener.AcceptTcpClient()
        $n++
        # One WebSocket per TCP connection: the edge opens a fresh origin connection for each, and
        # mstsc only ever uses a single connection, so serving them in sequence is enough.
        try {
            $ws = $null
            for ($try = 1; $try -le 3; $try++) {
                $w = New-Object Net.WebSockets.ClientWebSocket
                $w.Options.Proxy = $null
                $conn = $w.ConnectAsync([Uri]$Edge, $ct)
                $ok = WaitT $conn 12000
                if ($ok -and $w.State -eq 'Open') { $ws = $w; break }
                # log the exception TYPE as well as its message: on a Chinese Windows the message is
                # GBK text that L() has to turn into ???, but the class name is ASCII and it is what
                # actually tells the difference between "DNS is dead" and "TLS was reset".
                $why = 'state=' + $w.State
                if (-not $ok -and -not $conn.IsCompleted) { $why += ' wait-timeout' }
                if ($conn.Exception) {
                    $ie = $conn.Exception.InnerException
                    $why += ' ' + $ie.GetType().Name + ': ' + $ie.Message
                }
                L ('#' + $n + ' dial try ' + $try + ' failed ' + (($why -replace '[^\x20-\x7e]', '?')))
                try { $w.Dispose() } catch { }
            }
            if (-not $ws) { $cli.Close(); continue }
            L ('#' + $n + ' dialed')
            $ns = $cli.GetStream()
            $sock = $cli.Client
            $selRead = [Net.Sockets.SelectMode]::SelectRead
            $segR = New-Object ArraySegment[byte] ($rbuf, 0, $rbuf.Length)
            $rx = $ws.ReceiveAsync($segR, $ct)
            $idle = 0
            $up = 0; $down = 0
            # Without a mid-flight counter the only thing the log can say about a stalled connect is the
            # byte total at close, which cannot distinguish "handshake never finished" from "session came
            # up and then died". 15 s is cheap and lands several times inside the 90 s window.
            $flow = Get-Date
            while ($ws.State -eq 'Open') {
                if ($ns.DataAvailable) {
                    $c = $ns.Read($tbuf, 0, $tbuf.Length)
                    if ($c -le 0) { break }
                    $up += $c
                    $segS = New-Object ArraySegment[byte] ($tbuf, 0, $c)
                    $st = $ws.SendAsync($segS, [Net.WebSockets.WebSocketMessageType]::Binary, $true, $ct)
                    if (-not (WaitT $st 20000) -or $st.IsFaulted) { L ('#' + $n + ' send dead'); break }
                    $idle = 0
                }
                if ($rx.IsCompleted) {
                    # reading .Result on a faulted or cancelled task throws, so check both first
                    if ($rx.IsFaulted -or $rx.IsCanceled) { break }
                    if ($rx.Result.MessageType -eq 'Close') { break }
                    if ($rx.Result.Count -gt 0) { $ns.Write($rbuf, 0, $rx.Result.Count); $ns.Flush(); $down += $rx.Result.Count; $idle = 0 } else { $idle++ }
                    $segR = New-Object ArraySegment[byte] ($rbuf, 0, $rbuf.Length)
                    $rx = $ws.ReceiveAsync($segR, $ct)
                }
                # $cli.Connected only goes false after a send/receive has already failed, so it never
                # fires for a client that simply closed. This bridge serves one connection at a time, so
                # a half-open leftover wedges every later attempt: mstsc's connect sits in the TCP
                # backlog unanswered for 90 s and then gives up -- which is exactly what "first connect
                # stalls, the automatic retry works" looked like from the outside.
                if ($sock.Poll(1, $selRead) -and $sock.Available -eq 0) { L ('#' + $n + ' client gone'); break }
                $idle++
                # A still RDP screen moves no bytes at all, so this is a generous watchdog rather than
                # an idle timeout -- it exists only to reap a socket the edge silently abandoned.
                if ($idle -gt 900000) { L ('#' + $n + ' zombie'); break }
                if (((Get-Date) - $flow).TotalSeconds -ge 15) {
                    $flow = Get-Date
                    L ('#' + $n + ' flow up=' + $up + ' down=' + $down)
                }
                Start-Sleep -Milliseconds 2
            }
            try { $ws.Dispose() } catch { }
            try { $cli.Close() } catch { }
            L ('#' + $n + ' closed up=' + $up + ' down=' + $down)
        } catch {
            L ('#' + $n + ' error ' + (($_.Exception.Message) -split "`r?`n")[0])
            try { $cli.Close() } catch { }
        }
    }
    exit 0
}

# 3389 is deliberately avoided: mstsc sees a loopback connect to the local RDP port as "dial my own
# console session" and refuses before opening a socket (error 0x104, nothing reaches the bridge).
if (-not $Port) { $Port = 13389 }
$eh = ([Uri]$Edge).Host
$ht = Get-Content $hostsPath -Raw -EA SilentlyContinue
$hostsOk = ($ht -match ('(?m)^\s*127\.0\.0\.1\s+' + [regex]::Escape($Domain) + '\b'))
$pinOk = ($ht -match ('(?m)^\s*\d+\.\d+\.\d+\.\d+\s+' + [regex]::Escape($eh) + '\b'))
if (-not ($hostsOk -and $pinOk)) {
    # Worth the single UAC prompt: without the IPv4 pin the dial hangs on the IPv6 route half the time.
    if (IsAdmin) {
        & $self -OnlyHosts | Out-Null
    } else {
        $elev = '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "' + $self + '" -OnlyHosts'
        try { Start-Process -FilePath 'powershell.exe' -Verb RunAs -WindowStyle Hidden -ArgumentList $elev } catch { }
        Start-Sleep -Seconds 4
        Write-Host ('asked for admin once to record ' + $Domain + ' and the edge IPv4 pins in hosts; if that prompt was declined the bridge still tries plain DNS')
    }
    $ht = Get-Content $hostsPath -Raw -EA SilentlyContinue
    $hostsOk = ($ht -match ('(?m)^\s*127\.0\.0\.1\s+' + [regex]::Escape($Domain) + '\b'))
    $pinOk = ($ht -match ('(?m)^\s*\d+\.\d+\.\d+\.\d+\s+' + [regex]::Escape($eh) + '\b'))
}
$lp = ListeningPort
if ($lp -le 0) {
    if (PortFree $Port) { $target = $Port }
    elseif (PortFree 13390) { $target = 13390 }
    elseif (PortFree 13391) { $target = 13391 }
    elseif (PortFree 13392) { $target = 13392 }
    else { Write-Host 'no free local port for the bridge'; exit 1 }
    $a = '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "' + $self + '" -Bridge -Port ' + $target
    Start-Process -FilePath (Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe') -ArgumentList $a -WindowStyle Hidden | Out-Null
    for ($i = 0; $i -lt 25; $i++) {
        Start-Sleep -Milliseconds 200
        $up = @(Get-NetTCPConnection -State Listen -LocalAddress 127.0.0.1 -LocalPort $target -EA SilentlyContinue).Count
        if ($up -ge 1) { break }
    }
    $lp = $target
}
$addr = if ($hostsOk) { $Domain + ':' + $lp } else { '127.0.0.1:' + $lp }
# The bridge is a detached hidden process, so it survives this window closing but not a reboot. Leave a
# per-user logon task behind as well -- that is what makes the paste a genuinely one-time thing. A
# Limited/Interactive task under one's own account needs no elevation, and if the box still refuses, the
# Start-menu entry above covers the same ground by hand.
try {
    if (-not (Get-ScheduledTask -TaskName 'kun9_rdp_bridge' -EA SilentlyContinue)) {
        $argl = '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "' + $dst + '" -Bridge -Port ' + $lp
        $act = New-ScheduledTaskAction -Execute (Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe') -Argument $argl
        $tri = New-ScheduledTaskTrigger -AtLogOn
        $sts = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero) -StartWhenAvailable
        Register-ScheduledTask -TaskName 'kun9_rdp_bridge' -Action $act -Trigger $tri -Settings $sts | Out-Null
        L 'logon task registered'
    }
} catch { L ('logon task failed ' + (($_.Exception.Message) -split "`r?`n")[0]) }
Write-Host ('bridge 127.0.0.1:' + $lp + ' -> ' + $Edge)
Write-Host ('remote desktop target: ' + $addr + '   (account: administrator)')
L ('client launched target=' + $addr)
# Pre-answer mstsc's "unknown publisher, connect anyway?" warning. The ticked box is a DWORD under
# LocalDevices, and mstsc names the key after the *computer* -- it showed "127.0.0.1" in the dialog while
# the address typed was "127.0.0.1:13393" -- so seed both the bare host and the host:port form. Without
# this the first connect from a fresh machine just sits there and never opens a socket.
try {
    $ld = 'HKCU:\Software\Microsoft\Terminal Server Client\LocalDevices'
    if (-not (Test-Path $ld)) { New-Item -Path $ld -Force | Out-Null }
    $bare = $addr
    $ci = $addr.LastIndexOf(':')
    if ($ci -gt 0) { $bare = $addr.Substring(0, $ci) }
    foreach ($k in @($addr, $bare)) {
        New-ItemProperty -Path $ld -Name $k -Value 76 -PropertyType DWord -Force -EA SilentlyContinue | Out-Null
    }
} catch { }
if (-not $NoMstsc) {
    # An .rdp file rather than mstsc arguments: the VM's RDP certificate can never match the domain, and
    # "authentication level:i:2" is what keeps mstsc from sitting on an un-clickable security warning.
    # The rest trims bandwidth, because this link is measured at tens of KB/s.
    $rdp = Join-Path $dir 'connect.rdp'
@(
    'screen mode id:i:1',
    'desktopwidth:i:1280',
    'desktopheight:i:800',
    ('full address:s:' + $addr),
    'authentication level:i:2',
    'enablecredsspsupport:i:1',
    'prompt for credentials:i:0',
    'bitmap caching:i:1',
    'desktop composition:i:0',
    'disable themes:i:1',
    'disable menu anims:i:1',
    'audiomode:i:2',
    'redirectclipboard:i:1',
    'smart sizing:i:1'
) | Set-Content -Path $rdp -Encoding ascii
    Start-Process mstsc.exe -ArgumentList ('"' + $rdp + '"')
}
exit 0

#!/usr/bin/env bash
# US-vantage baseline for the endpoints the China-side boxes cannot give a fair answer
# about (workers.dev, vercel, CF edge throughput, Google/YouTube). Numbers here are the
# "should be" reference; compare with the same list measured from a rig.
set +e

echo "== who / where =="
date -u '+utc         %F %T'
echo "runner      $(uname -srm)  nproc=$(nproc)"
curl -4 -sS -m 20 https://ipinfo.io/json 2>/dev/null | sed 's/,"/", "/g' | tr ',' '\n' | grep -E '"(ip|city|region|country|org|asn|timezone)"' | head -8
echo

echo "== per-request timing (seconds; remote_ip is what we actually reached) =="
printf '%-22s %-58s %s\n' TARGET URL RESULT
p() {
    label="$1"; url="$2"
    out=$(curl -4 -sS -o /dev/null -m 25 -L -w '%{time_namelookup} %{time_connect} %{time_appconnect} %{time_starttransfer} %{time_total} %{size_download} %{speed_download} %{http_code} %{remote_ip}' "$url" 2>/dev/null)
    rc=$?
    if [ $rc -ne 0 ]; then
        printf '%-22s %-58s curl_exit=%s %s\n' "$label" "$url" "$rc" "$out"
        return
    fi
    set -- $out
    printf '%-22s %-58s dns=%s tcp=%s tls=%s ttfb=%s total=%s %sKB %sKB/s http=%s ip=%s\n' \
        "$label" "$url" "$1" "$2" "$3" "$4" "$5" "$(( $6 / 1024 ))" "$(( $7 / 1024 ))" "$8" "$9"
}

echo "-- Cloudflare, our own stuff"
p relay-list      'https://ch.kun9.ccwu.cc/'
p relay-master    'https://ch.kun9.ccwu.cc/mxd/rig_agent.ps1'
p relay-report    'https://ch.kun9.ccwu.cc/mxd/rig_watchdog.txt'
p telemetry-root  'https://tl.kun9.ccwu.cc/'
p cf-api-noauth   'https://api.cloudflare.com/client/v4/user/tokens/verify'
p cf-cdnjs-32kb   'https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.1/jquery.min.js'
p cf-dash         'https://dash.cloudflare.com/'

echo
echo "-- GitHub"
p gh-api          'https://api.github.com/meta'
p gh-raw-public   'https://raw.githubusercontent.com/github/gitignore/main/PowerShell.gitignore'

echo
echo "-- Google / YouTube (the harvest target)"
p google-204      'https://www.google.com/generate_204'
p gstatic-204     'https://www.gstatic.com/generate_204'
p google-accts    'https://accounts.google.com/'
p youtube-home    'https://www.youtube.com/'
p yt-music        'https://music.youtube.com/'
p yt-thumb        'https://i.ytimg.com/vi/dQw4w9WgXcQ/hqdefault.jpg'
p yt-timedtext    'https://www.youtube.com/timedtext'
p googlevideo-204 'https://redirector.googlevideo.com/generate_204'

echo
echo "-- free tiers we have never measured from anywhere"
p neon            'https://console.neon.tech/'
p turso           'https://turso.tech/'
p mongodb-atlas   'https://cloud.mongodb.com/'

echo
echo "== bulk throughput (the number that decides whether an edge route is usable) =="
t() {
    label="$1"; url="$2"; sz="$3"
    got=$(curl -4 -sS -o /dev/null -m 40 -w '%{size_download} %{speed_download} %{http_code}' "$url" 2>/dev/null)
    set -- $got
    [ -z "$1" ] && { echo "$label  FAILED"; return; }
    printf '%-22s got %s of %s  %s KB/s  http=%s\n' "$label" "$(( $1 / 1024 ))KB" "$sz" "$(( $2 / 1024 ))" "$3"
}
t cf-speed-5MB    'https://speed.cloudflare.com/__down?bytes=5242880'          5MB
t google-dl-2MB   'https://dl.google.com/android/repository/repository2-1.xml' ~2MB
t github-relay-75 'https://ch.kun9.ccwu.cc/mxd/rig_agent.ps1'                  75KB

echo
echo "== transport facts =="
echo "ipv6 curl   : $(curl -6 -sS -o /dev/null -m 15 -w '%{http_code} %{remote_ip}' https://api.github.com/meta 2>&1 | head -1)"
echo "curl        : $(curl --version | head -1)"
echo "openssl     : $(openssl version 2>/dev/null)"
echo "h2 used     : $(curl -4 -sS -o /dev/null -m 20 -L -w '%{http_version}' https://www.youtube.com/ 2>/dev/null)"
echo "dns servers : $(grep '^nameserver' /etc/resolv.conf | awk '{printf "%s ", $2}')"
echo "default rt  : $(ip route get 1.1.1.1 2>/dev/null | head -1)"

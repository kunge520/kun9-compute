#!/usr/bin/env bash
# linuxd boot: a Linux learning box out of one free GitHub runner (public repo = the minutes cost
# nothing). Same connection scheme as winterm, on purpose: the SAME named tunnel (kun9-wt) and the
# SAME hostname for the terminal, because only one of the two machines ever runs, so
# ssh.kun9.ccwu.cc always points at whichever machine is alive. The tunnel's ingress is stored
# server-side and targets loopback (ssh://127.0.0.1:22), so Linux only has to listen there.
#
# The desktop is the one place the two boxes differ, and it has to: Cloudflare's web RDP client is
# IronRDP and it cannot display xrdp (see EnableDesktop). So this box serves VNC and lets noVNC draw
# it, through a hostname route on the SAME named tunnel as the terminal -- vnc.kun9.ccwu.cc is fixed,
# owned by the tunnel, and gated by an Access policy, so nothing about a boot has to mint a URL.
#
# Everything is one credential: WT_RDP_PASS is the password for ssh (runner/root), for the browser
# SSH terminal and for the VNC desktop. WT_TUNNEL_TOKEN is the named-connector token.
# CST_S3_AKID/CST_S3_AKSEC mount the capsule's `github` bucket, the Windows box's Z: under ~.
#
# Desktop order matters for a different reason than it does on Windows: sshd and the tunnel come up
# first and publish a heartbeat, so the machine is reachable inside a minute while apt is still
# pulling xfce4 and tigervnc. Nothing here is a dependency of anything else -- a failed desktop
# install leaves a working SSH box.

set +e
cd "$GITHUB_WORKSPACE" || exit 1

CTL='https://ctl.kun9.ccwu.cc'
REF="${GITHUB_REF_NAME:-main}"
SESSION='linux/session.json'
export DEBIAN_FRONTEND=noninteractive

git config user.name linuxd
git config user.email linuxd@users.noreply.github.com

# Run length: first token of trigger.linuxd, minutes. 350 not 360 because timeout-minutes: 360 is
# GitHub's hard kill, and a job killed there never writes its dead record, so the panel misreports.
MIN=$(head -1 trigger.linuxd 2>/dev/null | tr -d ' \r' | cut -c1-6)
case "$MIN" in ''|*[!0-9]*) MIN=120 ;; esac
[ "$MIN" -lt 5 ] && MIN=5
[ "$MIN" -gt 350 ] && MIN=350
SECS=$((MIN * 60))
OPENED=$(date -u +%Y-%m-%dT%H:%M:%SZ)
ENDS=$(date -u -d "+$SECS seconds" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u +%Y-%m-%dT%H:%M:%SZ)
RESTARTS=0
NOTEG='ssh up'
DESKG='not-installed'
# autoconnect and resize are noVNC URL settings (app/ui.js reads them). The VNC password is NOT one of
# them: this string is committed to linux/session.json in a public repo, and this same password is also
# the SSH and panel credential. So the link is published clean and noVNC asks for it once per session --
# behind the Access login, which is what actually keeps strangers out.
DESKURL='https://vnc.kun9.ccwu.cc/vnc.html?autoconnect=true&resize=scale'
CAPG='not-armed'
CFPG='down'
DBGURL=''
DBGPG='down'
DBGPORT=48220
VNCPORT=5901
WEBPORT=6080

log() { echo "[$(date -u +%H:%M:%S)] $*"; }

# ---- sshd: the only thing that must work ----
EnableSsh() {
  if [ ! -x /usr/sbin/sshd ]; then
    log 'openssh-server missing, installing'
    sudo apt-get update -qq || return 1
    sudo apt-get install -y -qq openssh-server || return 1
  fi
  # Drop-in, not an edit of the main config: the runner image's sshd_config includes sshd_config.d/*
  # and a future image change then cannot undo these three lines.
  printf 'PasswordAuthentication yes\nPermitRootLogin yes\nUsePAM yes\n' \
    | sudo tee /etc/ssh/sshd_config.d/60-linuxd.conf >/dev/null
  printf 'runner:%s\nroot:%s\n' "$WT_RDP_PASS" "$WT_RDP_PASS" | sudo chpasswd
  sudo service ssh restart >/dev/null 2>&1 || sudo /usr/sbin/sshd -D >/dev/null 2>&1 &
  sleep 2
  ss -tlnp 2>/dev/null | grep -q ':22 ' && { log 'sshd listening on 22'; return 0; }
  log 'sshd NOT listening'
  return 1
}

# ---- named tunnel: the connector, same token as the Windows box ----
StartTunnel() {
  local cf="$HOME/cf"
  mkdir -p "$cf"
  if [ ! -x "$cf/cloudflared" ]; then
    # There is no cloudflared-linux-amd64.tgz -- the release ships the bare binary -- and without -f a
    # 404 page gets saved, chmod'ed +x and then "runs" as a silent no-op, which is exactly how a
    # mis-named asset reads months later. So: fail on a bad status and check for an ELF header.
    curl -sfL --max-time 180 -o "$cf/cloudflared" \
      https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 \
      || { CFPG='cf-dl-fail'; return 1; }
    head -c 4 "$cf/cloudflared" | grep -q ELF || { CFPG='cf-dl-fail'; return 1; }
    chmod +x "$cf/cloudflared"
  fi
  # --protocol http2: the QUIC path is blocked on some runner networks and http2 always works -- it is
  # what the Windows box runs. logfile because cloudflared's URL form does not reach redirected stdout.
  nohup "$cf/cloudflared" tunnel --no-autoupdate --protocol http2 --logfile "$cf/cfn.log" \
    run --token "$WT_TUNNEL_TOKEN" >"$cf/cfn.out" 2>&1 &
  for _ in $(seq 1 15); do
    sleep 2
    grep -q 'Registered tunnel connection' "$cf/cfn.log" 2>/dev/null && { CFPG='running'; return 0; }
  done
  CFPG='no-connection'
  return 1
}

# ---- debug channel: key-gated command echo out through a quick tunnel ----
# Same shape as winterm's so the existing dbg.cjs works unchanged: POST /run (and /desk, which on
# Linux is the same user, so it only differs in what it reports) with the body as a bash script and
# X-Key = HMAC-SHA256(WT_RDP_PASS|<capsule secret_access_key>, "kun9-dbg-v1") -- the two values the VM
# already holds as secrets, so no third credential is introduced. A quick tunnel needs no account
# permissions at all, which is what makes this droppable on any machine; its random URL goes into the
# heartbeat, exactly like the Windows box publishes dbg_url.
StartDbgListener() {
  [ -z "$WT_RDP_PASS" ] && { DBGPG='no-pass'; return 1; }
  [ -z "$CST_S3_AKSEC" ] && { DBGPG='no-capkey'; return 1; }
  nohup python3 - "$WT_RDP_PASS" "$CST_S3_AKSEC" "$DBGPORT" <<'PY' >"$HOME/cf/dbg.log" 2>&1 &
import hmac, hashlib, subprocess, sys
from http.server import BaseHTTPRequestHandler, HTTPServer
key = hmac.new((sys.argv[1] + '|' + sys.argv[2]).encode(), b'kun9-dbg-v1', hashlib.sha256).hexdigest()
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def send(self, code, text):
        b = text.encode('utf-8', 'replace')
        self.send_response(code); self.send_header('Content-Length', str(len(b)))
        self.send_header('Content-Type', 'text/plain; charset=utf-8'); self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        if not hmac.compare_digest(self.headers.get('X-Key', ''), key): return self.send(403, 'denied')
        u = subprocess.run(['bash','-c','echo user=$(whoami) host=$(hostname) drives=$(ls / | tr "\\n" " ")'],
                           capture_output=True, text=True).stdout.strip()
        self.send(200, 'pong ' + u)
    def do_POST(self):
        if not hmac.compare_digest(self.headers.get('X-Key', ''), key): return self.send(403, 'denied')
        n = int(self.headers.get('Content-Length', 0) or 0)
        script = self.rfile.read(n).decode('utf-8', 'replace')
        try:
            p = subprocess.run(['bash', '-c', script], capture_output=True, text=True, timeout=180)
            self.send(200, (p.stdout or '') + (p.stderr or '') + 'exit=%d\n' % p.returncode)
        except Exception as e:
            self.send(500, 'exec-fail: %s\n' % e)
HTTPServer(('127.0.0.1', int(sys.argv[3])), H).serve_forever()
PY
  sleep 2
  curl -s --max-time 4 -o /dev/null "http://127.0.0.1:$DBGPORT/" && return 0
  DBGPG='no-listener'
  return 1
}

StartDbgTunnel() {
  local d="$HOME/cf"
  rm -f "$d/dbg.log2"
  nohup "$d/cloudflared" tunnel --no-autoupdate --url "http://127.0.0.1:$DBGPORT" \
    --logfile "$d/dbg.tun.log" >"$d/dbg.tun.out" 2>&1 &
  local i
  for i in $(seq 1 20); do
    sleep 2
    u=$(grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' "$d/dbg.tun.log" 2>/dev/null | head -1)
    [ -n "$u" ] && { DBGURL="$u"; DBGPG='up'; log "dbg tunnel $u"; return 0; }
  done
  DBGPG='no-tunnel-url'
  return 1
}

# ---- desktop: XFCE on a VNC display, drawn in the browser by noVNC ----
# Why this is not RDP like the Windows box: Cloudflare's web RDP client is IronRDP, and with xrdp the
# two never agree. xrdp 0.9.24 has no NLA, so IronRDP sends no Client Info credentials at all (sesman
# logged zero login attempts for every click), xrdp then paints its OWN login window with classic
# bitmap orders, and the web client renders that as diagonal shearing -- before either side has drawn
# a desktop. Cache, compression and channel toggles each made it worse or killed the session outright
# (drdynvc is mandatory for IronRDP), and Ubuntu has no newer xrdp to move to. VNC has no such trap:
# the framebuffer crosses a plain WebSocket and noVNC is the very renderer Cloudflare itself uses for
# browser VNC. A quick tunnel also needs no account permission, unlike a new hostname on kun9-wt --
# the tunnel's ingress cannot be written with this token.
EnableDesktop() {
  if [ ! -x /usr/bin/Xvnc ]; then
    log 'installing xfce4 + tigervnc + novnc (this is the slow part)'
    sudo apt-get update -qq
    # fonts-wqy-microhei so the desktop renders Chinese, not empty boxes.
    sudo apt-get install -y -qq --no-install-recommends xfce4 xfce4-terminal xfce4-goodies \
      dbus-x11 fonts-wqy-microhei tigervnc-standalone-server tigervnc-common tigervnc-tools \
      novnc websockify || { DESKG='apt-fail'; return 1; }
  fi
  # Root owns the display, because root is the account he logs in as and the capsule has to show up in
  # its 文件管理器. /run/user/0 does not exist on a runner and xfce4 complains without it.
  sudo mkdir -p /root/.vnc /run/user/0
  sudo chmod 700 /run/user/0
  # vncpasswd is the only writer of that file's odd 8-byte DES form, so the one credential everything
  # else uses is piped in rather than hand-rolled.
  printf '%s\n%s\n' "$WT_RDP_PASS" "$WT_RDP_PASS" | sudo vncpasswd /root/.vnc/passwd >/dev/null 2>&1
  sudo chmod 600 /root/.vnc/passwd
  # -localhost: 5901 is reachable from this box only, which leaves websockify (and through it the
  # tunnel's vnc. route) as the only way in, with VncAuth as the gate. -AlwaysShared so a dropped tab
  # cannot leave the display locked.
  pgrep -x Xvnc >/dev/null || sudo bash -c \
    "nohup env HOME=/root XDG_RUNTIME_DIR=/run/user/0 /usr/bin/Xvnc :1 -geometry 1280x800 -depth 24 \
     -SecurityTypes VncAuth -PasswordFile /root/.vnc/passwd -localhost yes -rfbport $VNCPORT \
     -AlwaysShared >/root/xvnc.log 2>&1 &"
  local i
  for i in $(seq 1 10); do
    ss -tln 2>/dev/null | grep -q ":$VNCPORT " && break
    sleep 1
  done
  ss -tln 2>/dev/null | grep -q ":$VNCPORT " || { DESKG='no-xvnc'; return 1; }
  pgrep -x xfce4-session >/dev/null || sudo bash -c \
    "nohup env DISPLAY=:1 HOME=/root USER=root XDG_RUNTIME_DIR=/run/user/0 startxfce4 >/root/wm.log 2>&1 &"
  pgrep -x websockify >/dev/null || nohup /usr/bin/websockify --web=/usr/share/novnc \
    "127.0.0.1:$WEBPORT" "127.0.0.1:$VNCPORT" >"$HOME/cf/ws.log" 2>&1 &
  for i in $(seq 1 8); do
    curl -s --max-time 3 -o /dev/null "http://127.0.0.1:$WEBPORT/vnc.html" && return 0
    sleep 2
  done
  DESKG='no-web'
  return 1
}

# ---- data capsule: the owner's S3 bucket, mounted under ~/capsule ----
EnableCapsule() {
  [ -z "$CST_S3_AKID" ] && { CAPG='no-key'; return 1; }
  local d="$HOME/capsule"
  mkdir -p "$d"
  if [ ! -x "$HOME/cf/rclone" ]; then
    curl -sL --max-time 180 -o "$HOME/cf/rc.zip" https://downloads.rclone.org/rclone-current-linux-amd64.zip || { CAPG='rclone-dl-fail'; return 1; }
    (cd "$HOME/cf" && unzip -oq rc.zip) || { CAPG='rclone-unzip-fail'; return 1; }
    f=$(find "$HOME/cf" -name rclone -type f -perm -u+x | head -1)
    [ -f "$f" ] && cp "$f" "$HOME/cf/rclone" && chmod +x "$HOME/cf/rclone" || { CAPG='rclone-missing'; return 1; }
  fi
  command -v fusermount3 >/dev/null || sudo apt-get install -y -qq fuse3 >/dev/null 2>&1
  # provider=Other + path addressing: virtual-host style fails DNS on github.s3.cstcloud.cn.
  { printf '[capsule]\ntype = s3\nprovider = Other\nenv_auth = false\n'
    printf 'access_key_id = %s\n' "$CST_S3_AKID"
    printf 'secret_access_key = %s\n' "$CST_S3_AKSEC"
    printf 'endpoint = s3.cstcloud.cn\naddressing_style = path\n'; } >"$HOME/cf/cap.conf"
  chmod 600 "$HOME/cf/cap.conf"
  # Still mounted by runner (the S3 keys and the cache live in that home), but the desktop session
  # logs in as root, and a plain FUSE mount is closed to every other uid including root -- hence
  # allow_other through fuse.conf, plus a link so 文件管理器 shows it as ~/capsule either way.
  sudo sed -i 's/^#user_allow_other/user_allow_other/' /etc/fuse.conf
  grep -q '^user_allow_other' /etc/fuse.conf || echo user_allow_other | sudo tee -a /etc/fuse.conf >/dev/null
  nohup "$HOME/cf/rclone" mount --config "$HOME/cf/cap.conf" capsule:github "$d" \
    --volname capsule --vfs-cache-mode writes --dir-cache-time 30s --allow-other \
    --log-level INFO --log-file "$HOME/cf/cap.log" >"$HOME/cf/cap.out" 2>&1 &
  for _ in $(seq 1 12); do
    sleep 2
    mountpoint -q "$d" 2>/dev/null && {
      CAPG="mounted $d"; log "capsule mounted at $d"
      sudo ln -sfn "$d" /root/capsule 2>/dev/null
      return 0; }
  done
  CAPG='mount-failed'
  return 1
}

# ---- heartbeat: same file shape the panel already reads for winterm ----
SyncHead() {
  git rebase --quit >/dev/null 2>&1
  git merge --abort >/dev/null 2>&1
  rm -f .git/index.lock
  git fetch -q origin "$REF" >/dev/null 2>&1
  git reset -q --hard "origin/$REF" >/dev/null 2>&1
}

Publish() {
  local note="$1"
  local json
  json=$(printf '{"alive":true,"machine":"linux","run_id":"%s","check":"%s","url":"%s","ssh_url":"https://ssh.kun9.ccwu.cc","user":"root","ttl_min":%s,"opened":"%s","ends":"%s","named":"%s","restarts":%s,"rdp_diag":"%s","rdp_info":"%s","ssh_info":"%s","capsule":"%s","dbg_url":"%s","dbg_diag":"%s","note":"%s"}' \
    "$GITHUB_RUN_ID" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$DESKURL" "$MIN" "$OPENED" "$ENDS" "$CFPG" "$RESTARTS" \
    "$DESKG" "vnc 127.0.0.1:$VNCPORT" "sshd 127.0.0.1:22 user=root" "$CAPG" "$DBGURL" "$DBGPG" "$note")
  echo "LINUXD-JSON $json"
  local i
  for i in 1 2 3; do
    SyncHead
    mkdir -p linux
    printf '%s\n' "$json" >"$SESSION"
    git add -f "$SESSION"
    git commit -qm "linuxd heartbeat $(date -u +%Y-%m-%dT%H:%M:%SZ) named=$CFPG" >/dev/null 2>&1 || { sleep 3; continue; }
    git push -q origin "HEAD:$REF" >/dev/null 2>&1 && return 0
    log "push attempt $i failed"
    sleep 4
  done
  return 1
}

# ---- boot ----
if [ -z "$WT_TUNNEL_TOKEN" ]; then echo 'WT_TUNNEL_TOKEN secret missing'; exit 1; fi
if [ -z "$WT_RDP_PASS" ]; then echo 'WT_RDP_PASS secret missing'; exit 1; fi

log 'boot: sshd'
EnableSsh
log 'boot: tunnel'
StartTunnel
log 'boot: debug channel'
StartDbgListener && StartDbgTunnel
Publish 'booting: ssh+tunnel+dbg up, desktop installing'

( EnableDesktop; log "desktop: $DESKG" ) & DESKJOB=$!
( sleep 1; EnableCapsule; log "capsule: $CAPG" ) & CAPJOB=$!
# Bare `wait` would never return -- the tunnel and the debug listener are background jobs of this
# same shell and run for the whole session, which would leave the machine up but unsupervised (no
# heartbeat refresh, no panel stop). Wait on the two installs by pid.
wait "$DESKJOB"; wait "$CAPJOB"

# A background job cannot set a variable in its parent shell, so DESKG/CAPG still hold their initial
# values no matter what the installs did. Read the truth back from the system instead: the local page
# for the desktop, the mount table for the capsule. A diagnosis that came from the install itself
# (apt-fail, no-key, rclone-missing) is kept: only the never-ran/stale states get rewritten.
Probe() {
  if curl -s --max-time 3 -o /dev/null "http://127.0.0.1:$WEBPORT/vnc.html"; then DESKG='listening'
  elif [ "$DESKG" = listening ]; then DESKG='not-listening'; fi
  if mountpoint -q "$HOME/capsule" 2>/dev/null; then CAPG="mounted $HOME/capsule"
  elif [ "$CAPG" = not-armed ] || [ "$CAPG" = "mounted $HOME/capsule" ]; then CAPG='not-mounted'; fi
}
Probe

Publish "desktop=$DESKG capsule=$CAPG dbg=$DBGPG"
log "reachable: ssh root@ssh.kun9.ccwu.cc  desktop=${DESKURL:-none}  ttl=${MIN}m"

# ---- supervise: keep the tunnel alive, obey the panel, refresh the heartbeat ----
END_TS=$(date -u -d "+$SECS seconds" +%s 2>/dev/null || echo $(( $(date -u +%s) + SECS )))
LASTP=0
while [ "$(date -u +%s)" -lt "$END_TS" ]; do
  sleep 20
  CHANGED=0

  # The panel only writes a flag; this loop is the one that reads it. A stop is what releases the
  # runner. ?m=linux is the machine selector -- without it the Worker answers for the Windows box.
  ASK=$(curl -s --max-time 8 "$CTL/api/power?m=linux" 2>/dev/null)
  case "$ASK" in
    *'"action":"stop"'*)
      curl -s --max-time 8 -X POST "$CTL/api/power/clear?m=linux" >/dev/null 2>&1
      log 'panel asked for stop, exiting'; break ;;
    *'"action":"rdp"'*)
      curl -s --max-time 8 -X POST "$CTL/api/power/clear?m=linux" >/dev/null 2>&1
      EnableDesktop; CHANGED=1; Publish "desktop: $DESKG"; LASTP=$(date -u +%s) ;;
  esac

  if ! pgrep -f 'cloudflared.*run --token' >/dev/null 2>&1; then
    RESTARTS=$((RESTARTS + 1))
    log "named tunnel gone, restarting #$RESTARTS"
    StartTunnel; CHANGED=1
  fi

  # Debug channel: the listener is a plain python process, so it is checked the same way it is used --
  # can the port answer. A dead quick tunnel is caught by its own pid pattern, which carries the port
  # and so cannot be confused with the named connector above.
  if ! curl -s --max-time 3 -o /dev/null "http://127.0.0.1:$DBGPORT/"; then
    log 'dbg listener gone, restarting'
    StartDbgListener && StartDbgTunnel; CHANGED=1
  elif ! pgrep -f "url http://127.0.0.1:$DBGPORT" >/dev/null 2>&1; then
    log 'dbg tunnel gone, restarting'
    StartDbgTunnel; CHANGED=1
  fi

  # Desktop: Xvnc, xfce and websockify, all probed through the one page that needs all three. The
  # route to it is the tunnel's own and is checked by the named-tunnel block above.
  if ! curl -s --max-time 4 -o /dev/null "http://127.0.0.1:$WEBPORT/vnc.html"; then
    log 'desktop web gone, restarting'
    EnableDesktop; CHANGED=1
  fi

  if ! mountpoint -q "$HOME/capsule" 2>/dev/null && [ $(( $(date -u +%s) - ${LASTC:-0} )) -ge 120 ]; then
    LASTC=$(date -u +%s); EnableCapsule; CHANGED=1
  fi

  if [ $(( $(date -u +%s) - LASTP )) -ge 60 ] || [ "$CHANGED" = 1 ]; then
    LASTP=$(date -u +%s)
    Probe
    Publish "desktop=$DESKG capsule=$CAPG dbg=$DBGPG"
  fi
done

# Dead record last, and written after the sync: SyncHead hard-resets the checkout, so a file written
# before it would be discarded before it ever got committed.
SyncHead
printf '{"alive":false,"machine":"linux","run_id":"%s","url":"","ssh_url":"https://ssh.kun9.ccwu.cc","user":"root","closed":"%s","named":"%s","restarts":%s,"ttl_min":%s,"dbg_url":"%s"}\n' \
  "$GITHUB_RUN_ID" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$CFPG" "$RESTARTS" "$MIN" "$DBGURL" >"$SESSION"
git add -f "$SESSION"
git commit -qm "linuxd closed $(date -u +%Y-%m-%dT%H:%M:%SZ)" >/dev/null 2>&1
git push -q origin "HEAD:$REF" >/dev/null 2>&1
log 'released, goodbye'
exit 0

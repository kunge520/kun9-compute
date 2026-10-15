#!/usr/bin/env bash
# linuxd boot: a Linux learning box out of one free GitHub runner (public repo = the minutes cost
# nothing). Same connection scheme as winterm, on purpose: the SAME named tunnel (kun9-wt) and the
# SAME hostnames, because only one of the two machines ever runs, so ssh.kun9.ccwu.cc and
# rdp.kun9.ccwu.cc always point at whichever machine is alive. The tunnel's ingress is stored
# server-side and targets loopback (ssh://127.0.0.1:22, tcp 3389), so Linux only has to listen there.
#
# Everything is one credential: WT_RDP_PASS is the password for ssh (runner/root), for the browser
# SSH terminal and for the browser RDP desktop. WT_TUNNEL_TOKEN is the connector token.
# CST_S3_AKID/CST_S3_AKSEC mount the capsule's `github` bucket, the Windows box's Z: under ~.
#
# Desktop order matters for a different reason than it does on Windows: sshd and the tunnel come up
# first and publish a heartbeat, so the machine is reachable inside a minute while apt is still
# pulling xfce4 and xrdp. Nothing here is a dependency of anything else -- a failed desktop install
# leaves a working SSH box.

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
RDPG='not-installed'
CAPG='not-armed'
CFPG='down'
DBGURL=''
DBGPG='down'
DBGPORT=48220

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
    curl -sL --max-time 180 -o "$cf/cf.tgz" \
      https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.tgz || return 1
    tar -xzf "$cf/cf.tgz" -C "$cf" cloudflared || return 1
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

# ---- desktop: xrdp + XFCE, reached through the Access RDP app on rdp.kun9.ccwu.cc ----
EnableRdp() {
  if [ ! -x /usr/sbin/xrdp ]; then
    log 'installing xfce4 + xrdp (this is the slow part)'
    sudo apt-get update -qq
    # fonts-wqy-microhei so the desktop renders Chinese, not empty boxes.
    sudo apt-get install -y -qq --no-install-recommends xfce4 xfce4-terminal xfce4-goodies \
      xorg xorgxrdp xrdp dbus-x11 fonts-wqy-microhei || { RDPG='apt-fail'; return 1; }
    sudo adduser xrdp ssl-cert >/dev/null 2>&1
  fi
  # Replaced, not probed: startwm.sh differs between images and whatever it does by default, execing
  # startxfce4 is the whole requirement for a session that IronRDP can display.
  printf '#!/bin/sh\nexport XDG_RUNTIME_DIR=/run/user/$(id -u)\nexec startxfce4\n' | sudo tee /etc/xrdp/startwm.sh >/dev/null
  sudo chmod +x /etc/xrdp/startwm.sh
  sudo service xrdp restart >/dev/null 2>&1 || sudo service xrdp start >/dev/null 2>&1
  sleep 3
  if ss -tln 2>/dev/null | grep -q ':3389 '; then RDPG='listening'; log 'xrdp listening on 3389'; return 0; fi
  RDPG='not-listening'
  log 'xrdp NOT listening on 3389'
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
  # Mounted by the SSH user, not root: a FUSE mount is only readable by the user that made it unless
  # allow_other is granted through fuse.conf, and runner is exactly the account that uses the files.
  nohup "$HOME/cf/rclone" mount --config "$HOME/cf/cap.conf" capsule:github "$d" \
    --volname capsule --vfs-cache-mode writes --dir-cache-time 30s --log-level INFO \
    --log-file "$HOME/cf/cap.log" >"$HOME/cf/cap.out" 2>&1 &
  for _ in $(seq 1 12); do
    sleep 2
    mountpoint -q "$d" 2>/dev/null && { CAPG="mounted $d"; log "capsule mounted at $d"; return 0; }
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
  json=$(printf '{"alive":true,"machine":"linux","run_id":"%s","check":"%s","url":"https://rdp.kun9.ccwu.cc","ssh_url":"https://ssh.kun9.ccwu.cc","user":"runner","ttl_min":%s,"opened":"%s","ends":"%s","named":"%s","restarts":%s,"rdp_diag":"%s","rdp_info":"%s","ssh_info":"%s","capsule":"%s","dbg_url":"%s","dbg_diag":"%s","note":"%s"}' \
    "$GITHUB_RUN_ID" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$MIN" "$OPENED" "$ENDS" "$CFPG" "$RESTARTS" \
    "$RDPG" "tcp://localhost:3389" "sshd 127.0.0.1:22 user=runner" "$CAPG" "$DBGURL" "$DBGPG" "$note")
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

( EnableRdp;   log "desktop: $RDPG" ) &
( sleep 1; EnableCapsule; log "capsule: $CAPG" ) &
wait

Publish "desktop=$RDPG capsule=$CAPG dbg=$DBGPG"
log "reachable: https://ssh.kun9.ccwu.cc  (runner / \$WT_RDP_PASS)  ttl=${MIN}m"

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
      EnableRdp; CHANGED=1; Publish "rdp: $RDPG"; LASTP=$(date -u +%s) ;;
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

  if ! mountpoint -q "$HOME/capsule" 2>/dev/null && [ $(( $(date -u +%s) - ${LASTC:-0} )) -ge 120 ]; then
    LASTC=$(date -u +%s); EnableCapsule; CHANGED=1
  fi

  if [ $(( $(date -u +%s) - LASTP )) -ge 60 ] || [ "$CHANGED" = 1 ]; then
    LASTP=$(date -u +%s)
    Publish "desktop=$RDPG capsule=$CAPG dbg=$DBGPG"
  fi
done

# Dead record last, and written after the sync: SyncHead hard-resets the checkout, so a file written
# before it would be discarded before it ever got committed.
SyncHead
printf '{"alive":false,"machine":"linux","run_id":"%s","url":"https://rdp.kun9.ccwu.cc","ssh_url":"https://ssh.kun9.ccwu.cc","user":"runner","closed":"%s","named":"%s","restarts":%s,"ttl_min":%s,"dbg_url":"%s"}\n' \
  "$GITHUB_RUN_ID" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$CFPG" "$RESTARTS" "$MIN" "$DBGURL" >"$SESSION"
git add -f "$SESSION"
git commit -qm "linuxd closed $(date -u +%Y-%m-%dT%H:%M:%SZ)" >/dev/null 2>&1
git push -q origin "HEAD:$REF" >/dev/null 2>&1
log 'released, goodbye'
exit 0

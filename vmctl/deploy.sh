#!/usr/bin/env bash
# Redeploy the vm-ctl panel Worker (https://ctl.kun9.ccwu.cc) from this repo's copy of the source.
#
# Two secrets are read from the machine and never committed: the Cloudflare API token and account
# id (Desktop/密钥.txt, line 9 and line 5) and the panel password (密钥-换电脑拷走/console_key.txt,
# which sits next to this repo in the working tree). Everything else here is public.
#
# The source is fetched from raw.githubusercontent rather than the live Worker, because reading the
# deployed script back returns a multipart envelope whose Content-Disposition line is not JS.
#
# Requires: bash, curl, openssl. Run: bash vmctl/deploy.sh
set -u
REPO=kunge520/kun9-compute
WORKER=vm-ctl
KV=4489efce29d9412b80e727a92d0410f2
CDATE=2026-10-01
HERE=$(cd "$(dirname "$0")" && pwd)
SECRETS="$HOME/Desktop/密钥.txt"
KEYFILE="$HERE/../密钥-换电脑拷走/console_key.txt"
[ -f "$SECRETS" ] || { echo "缺少 $SECRETS（Cloudflare API token 第 9 行、account id 第 5 行）"; exit 1; }
[ -f "$KEYFILE" ] || { echo "缺少 $KEYFILE（面板口令）"; exit 1; }

D=$(mktemp -d); trap 'rm -rf "$D"' EXIT
umask 077
curl -sSfL "https://raw.githubusercontent.com/$REPO/main/vmctl/vm-ctl.worker.js" -o "$D/vm-ctl.worker.js" || { echo "拉取源码失败"; exit 1; }
grep -q 'export default' "$D/vm-ctl.worker.js" || { echo "源码不对（没有 export default），取消部署"; exit 1; }
echo "source=$(wc -c < "$D/vm-ctl.worker.js") bytes"

TOK=$(sed -n '9p' "$SECRETS" | tr -d '\r\n ')
ACCT=$(sed -n '5p' "$SECRETS" | tr -d '\r\n ')
KEY=$(tr -d '\r\n' < "$KEYFILE")
printf 'header = "Authorization: Bearer %s"\n' "$TOK" > "$D/.cf"
printf '%s' '{"main_module":"vm-ctl.worker.js","compatibility_date":"'"$CDATE"'","bindings":[{"name":"PANEL_KEY","type":"secret_text","text":"'"$KEY"'"},{"name":"STORE","type":"kv_namespace","namespace_id":"'"$KV"'"}]}' > "$D/metadata.json"

code=$(curl -sS -m 120 --config "$D/.cf" -o "$D/out.json" -w '%{http_code}' -X PUT \
  "https://api.cloudflare.com/client/v4/accounts/$ACCT/workers/scripts/$WORKER" \
  --form "metadata=@$D/metadata.json;type=application/json;filename=" \
  --form "vm-ctl.worker.js=@$D/vm-ctl.worker.js;type=application/javascript+module;filename=vm-ctl.worker.js")
echo "deploy=$code"
grep -o '"success":[a-z]*\|"message":"[^"]*"' "$D/out.json" | head -4
curl -sS -m 30 -o /dev/null -w 'page=%{http_code}\n' https://ctl.kun9.ccwu.cc/

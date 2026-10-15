#!/usr/bin/env bash
# Redeploy the vm-ctl panel Worker (https://ctl.kun9.ccwu.cc) from this repo's copy of the source.
#
# Two secrets are read from the machine and never committed: the Cloudflare API token and the panel
# password. They live in ~/.qoder-cn/secrets -- the same directory every other script here reads, and
# mirrored in the 数据胶囊 vault (aial:githubxuniji/vault) so a new computer gets them back with one
# rclone pull instead of a hunt through Desktop. Everything else here is public.
#
# A deploy REPLACES the whole binding set, so every secret the Worker needs has to be listed in the
# metadata below -- anything left out is gone the moment this runs. The OIDC signing key and its
# client secret are next to the panel password (idp_jwk.json / idp_client_secret.txt), because the
# browser-desktop login is minted by this Worker itself and losing that key means re-creating the
# Access identity provider.
#
# The source is fetched from raw.githubusercontent rather than the live Worker, because reading the
# deployed script back returns a multipart envelope whose Content-Disposition line is not JS.
# Pass a file as $1 to deploy that copy instead (raw caches by path for a minute after a push).
#
# Requires: bash, curl. Run: bash vmctl/deploy.sh [source.js]
set -u
REPO=kunge520/kun9-compute
WORKER=vm-ctl
KV=4489efce29d9412b80e727a92d0410f2
ACCT=0d5f4724a0cf54b406333fcf8e7a0b65
CDATE=2026-10-01
HERE=$(cd "$(dirname "$0")" && pwd)
VAULT="$HOME/.qoder-cn/secrets"
[ -d "$VAULT" ] || { echo "缺少 $VAULT（先 rclone 从胶囊 vault/ 拉回来）"; exit 1; }
for f in cf_maint_token.txt console_key.txt idp_jwk.json idp_client_secret.txt; do
  [ -f "$VAULT/$f" ] || { echo "缺少 $VAULT/$f（API 令牌 / 面板口令 / 登录签名密钥 / 客户端密钥）"; exit 1; }
done

D=$(mktemp -d); trap 'rm -rf "$D"' EXIT
# curl.exe is a native Windows binary: it cannot read the /tmp path bash hands it, so every
# file argument below goes through $WD, the same directory in C:/ form.
WD=$(cd "$D" && pwd -W)
umask 077
SRC="${1:-}"
if [ -n "$SRC" ]; then
  [ -f "$SRC" ] || { echo "找不到源码 $SRC"; exit 1; }
  cp "$SRC" "$D/vm-ctl.worker.js" || exit 1
else
  curl -sSfL "https://raw.githubusercontent.com/$REPO/main/vmctl/vm-ctl.worker.js" -o "$D/vm-ctl.worker.js" || { echo "拉取源码失败"; exit 1; }
fi
grep -q 'export default' "$D/vm-ctl.worker.js" || { echo "源码不对（没有 export default），取消部署"; exit 1; }
echo "source=$(wc -c < "$D/vm-ctl.worker.js") bytes"

# A secret_text value goes into JSON as a string, so backslash and quote are the two things that
# have to be escaped; the single-line files also lose their line endings here.
esc() { tr -d '\r\n' < "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }

TOK=$(tr -d '\r\n ' < "$VAULT/cf_maint_token.txt")
printf 'header = "Authorization: Bearer %s"\n' "$TOK" > "$WD/.cf"
# One line, deliberately: a backslash-newline inside single quotes is NOT a continuation in bash, it
# is a literal backslash, and Cloudflare rejects the metadata part as unparsable JSON (code 10021).
printf '%s' '{"main_module":"vm-ctl.worker.js","compatibility_date":"'"$CDATE"'","bindings":[{"name":"PANEL_KEY","type":"secret_text","text":"'"$(esc "$VAULT/console_key.txt")"'"},{"name":"IDP_JWK","type":"secret_text","text":"'"$(esc "$VAULT/idp_jwk.json")"'"},{"name":"IDP_SECRET","type":"secret_text","text":"'"$(esc "$VAULT/idp_client_secret.txt")"'"},{"name":"STORE","type":"kv_namespace","namespace_id":"'"$KV"'"}]}' > "$WD/metadata.json"

code=$(curl -sS -m 120 --config "$WD/.cf" -o "$WD/out.json" -w '%{http_code}' -X PUT \
  "https://api.cloudflare.com/client/v4/accounts/$ACCT/workers/scripts/$WORKER" \
  --form "metadata=@$WD/metadata.json;type=application/json;filename=" \
  --form "vm-ctl.worker.js=@$WD/vm-ctl.worker.js;type=application/javascript+module;filename=vm-ctl.worker.js")
echo "deploy=$code"
# The messages array alone is not enough to fix a rejected upload -- print the raw response whenever
# the deploy failed, because the trap deletes the working directory the moment the script exits.
[ "$code" = 200 ] || head -c 1200 "$WD/out.json"
grep -o '"success":[a-z]*\|"message":"[^"]*"' "$WD/out.json" | head -4
curl -sS -m 30 -o "$WD/jwks.json" -w 'jwks=%{http_code}\n' https://ctl.kun9.ccwu.cc/oidc/jwks
grep -o '"kty":"RSA"\|"kid":"[^"]*"\|"d":' "$WD/jwks.json" | head -3
curl -sS -m 30 -o /dev/null -w 'panel=%{http_code}\n' https://ctl.kun9.ccwu.cc/

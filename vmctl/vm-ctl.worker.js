
// kun9 VM control panel — one page that turns the GitHub free Windows runner on and off.
//
//
// Power is credential-free by default: winterm.yml runs a 5-minute watchdog whose first job is to
// ask this Worker "is a start queued?" (/api/claim). If yes the Windows job runs; if no it finishes
// in a few seconds. Stopping is the mirror image: the panel writes a stop flag here and the live VM
// reads it on its next heartbeat (/api/power) and ends its own run. A fine-grained token pasted at
// /token only replaces the watchdog step with an instant dispatch.
//
// The secrets kept in this Worker are PANEL_KEY, the password for the page, and that optional token.

const REPO = 'kunge520/kun9-compute';
const WF = 'winterm.yml';
const API = 'https://api.github.com';
const RAW = 'https://raw.githubusercontent.com/' + REPO + '/main/winterm/session.json';
const RUNS = '/repos/' + REPO + '/actions/workflows/' + WF + '/runs?per_page=3';
const COOKIE = 'vmctl';
// Browser RDP/SSH are only served to a request Access already trusts, and the only trust this kit can
// mint by itself is its own OIDC provider: the panel cookie IS the identity, so 打开桌面/打开终端
// costs no emailed PIN. Access refuses Service Auth and bypass policies for these apps, hence a real IdP.
const RDP_APP = 'https://rdp.kun9.ccwu.cc';
// Clientless SSH is served from the tunnel ingress route ssh.kun9.ccwu.cc -> ssh://127.0.0.1:22, so its
// link is fixed: the origin address is resolved by the connector, never carried in the URL.
const SSH_APP = 'https://ssh.kun9.ccwu.cc';
// Access authorises the desktop link by matching the IP in the URL against the app's target_criteria,
// which only lists the two registered infrastructure targets. vm-local.rdp.kun9.ccwu.cc -> 127.0.0.1 is
// fixed, and the connector runs ON the VM, so dialing loopback always reaches that VM's own 3389. The
// VM's tunnel-side IP (heartbeat rdp_ip) changes every boot and is NOT a registered target, so we do
// not use it -- that made Access reject the target before IronRDP rendered.
const RDP_VNET = '0906b491-71ec-42d1-93b5-aa9048aa2529';
const RDP_TARGET = '127.0.0.1';
const IDP_HOST = 'ctl.kun9.ccwu.cc';
const IDP_CID = 'vmctl-panel';
const IDP_EMAIL = '645478520@qq.com';

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const send = (body, type, status, extra) =>
      new Response(body, Object.assign({ status: status || 200, headers: Object.assign({ 'Content-Type': type + '; charset=utf-8', 'Cache-Control': 'no-store' }, extra || {}) }));

    if (url.pathname === '/favicon.ico') return new Response(null, { status: 204 });

    // ---- machine-facing endpoints: no cookie, they answer nothing a runner could abuse ----
    if (url.pathname === '/api/claim') {
      const q = await read(env, 'power');
      if (!q || q.action !== 'start') return send(JSON.stringify({ action: 'none' }), 'application/json');
      if (await busy(env, true)) return send(JSON.stringify({ action: 'wait', reason: 'busy' }), 'application/json');
      await env.STORE.delete('power');
      // Fifteen minutes is only the gap between a claimed start and that machine's first
      // heartbeat; longer would let a runner killed before it published refuse new starts.
      await env.STORE.put('booting', '1', { expirationTtl: 900 });
      return send(JSON.stringify({ action: 'start', queued_at: q.at }), 'application/json');
    }
    if (url.pathname === '/api/power') {
      // The live VM is the only thing that polls this, so its first poll is also the proof that
      // the claimed start actually became a machine -- which lets the panel trust 'booting' for
      // the few minutes between claim and boot, and drop it the moment the boot is real.
      if (env.STORE && (await env.STORE.get('booting'))) await env.STORE.delete('booting');
      const q = await read(env, 'power');
      return send(JSON.stringify({ action: q && (q.action === 'stop' || q.action === 'rdp') ? q.action : 'none' }), 'application/json');
    }
    if (req.method === 'POST' && url.pathname === '/api/power/clear') {
      const q = await read(env, 'power');
      if (q && (q.action === 'stop' || q.action === 'rdp')) await env.STORE.delete('power');
      await env.STORE.delete('booting');
      return send(JSON.stringify({ ok: true }), 'application/json');
    }

    // ---- own OIDC provider: Access asks it who the user is, the panel cookie is the answer ----
    // The counter is how the wiring got debugged: it says which of these endpoints Access really
    // calls, which the error page alone never tells you.
    if (url.pathname === '/oidc/jwks' || url.pathname === '/.well-known/openid-configuration' || url.pathname === '/oidc/userinfo') {
      const ck = 'hit_' + url.pathname.replace(/[^a-z]/g, '_');
      const prev = (await read(env, ck)) || { n: 0 };
      await env.STORE.put(ck, JSON.stringify({ n: Number(prev.n || 0) + 1, at: new Date().toISOString(), ua: String(req.headers.get('User-Agent') || '').slice(0, 30), auth: req.headers.get('Authorization') ? 'yes' : 'no' }), { expirationTtl: 3600 });
    }
    if (url.pathname === '/oidc/jwks') return send(JSON.stringify(await jwks(env)), 'application/json');
    if (url.pathname === '/oidc/userinfo') {
      const iss = 'https://' + IDP_HOST;
      return send(JSON.stringify({
        sub: 'vmctl-owner', iss: iss, aud: IDP_CID, email: IDP_EMAIL, email_verified: true,
        name: 'kun9', preferred_username: 'kun9', updated_at: Math.floor(Date.now() / 1000),
      }), 'application/json');
    }
    if (url.pathname === '/.well-known/openid-configuration') {
      // Same three endpoints Access was configured with, published the standard way as well.
      const iss = 'https://' + IDP_HOST;
      return send(JSON.stringify({
        issuer: iss, authorization_endpoint: iss + '/oidc/authorize', token_endpoint: iss + '/oidc/token',
        jwks_uri: iss + '/oidc/jwks', userinfo_endpoint: iss + '/oidc/userinfo', response_types_supported: ['code'],
        subject_types_supported: ['pairwise'], id_token_signing_alg_values_supported: ['RS256'],
        scopes_supported: ['openid', 'email', 'profile'],
        claims_supported: ['sub', 'iss', 'aud', 'exp', 'iat', 'email', 'email_verified', 'name', 'preferred_username', 'nonce'],
        grant_types_supported: ['authorization_code'], token_endpoint_auth_methods_supported: ['client_secret_post', 'client_secret_basic'],
        response_modes_supported: ['query'],
      }), 'application/json');
    }
    if (url.pathname === '/oidc/authorize') {
      const rd = url.searchParams.get('redirect_uri') || '';
      if (!/^https:\/\/[a-z0-9-]+\.cloudflareaccess\.com\/cdn-cgi\/access\/callback$/.test(rd)) {
        return send('redirect_uri 不是 Access 的回调地址', 'text/plain', 400);
      }
      const want = COOKIE + '=' + (env.PANEL_KEY ? await sig(env) : 'x');
      if (!(req.headers.get('Cookie') || '').includes(want)) {
        // Straight back here after the password, so the login never dead-ends on the panel.
        return send('', 'text/plain', 302, { Location: '/?next=' + encodeURIComponent(url.pathname + url.search) });
      }
      // The code carries its own state, signed: Access posts the callback to a different Worker
      // instance within a second, and a KV write is not readable elsewhere that fast, so a code
      // stored in the namespace would always come back not-found on the very next call.
      const st = url.searchParams.get('state') || '';
      const code = await mkCode(env, {
        rd: rd,
        st: st,
        nc: url.searchParams.get('nonce') || nonceFromState(st),
        cc: url.searchParams.get('code_challenge') || '',
        x: Date.now(),
      });
      const back = new URL(rd);
      back.searchParams.set('code', code);
      if (st) back.searchParams.set('state', st);
      return send('', 'text/plain', 302, { Location: back.toString() });
    }
    if (req.method === 'POST' && url.pathname === '/oidc/token') {
      // Called by Access's backend, so no cookie here: client_id/secret is the whole gate, and the
      // code is a signature-checked blob this Worker produced at most 90 seconds ago. One body read,
      // then parsed by content type -- formData() consumes the stream, so a second read for a JSON
      // fallback would only ever see an empty body.
      const raw = await req.text();
      let p = {};
      try {
        if ((req.headers.get('Content-Type') || '').indexOf('application/json') >= 0) p = JSON.parse(raw);
        else new URLSearchParams(raw).forEach((v, k) => { p[k] = v; });
      } catch (e) {
        p = {};
      }
      // Some IdP clients put the credentials in a Basic header instead of the body.
      const auth = req.headers.get('Authorization') || '';
      if (auth.indexOf('Basic ') === 0) {
        try {
          const pair = atob(auth.slice(6));
          const colon = pair.indexOf(':');
          if (colon > 0 && !p.client_id) {
            p.client_id = pair.slice(0, colon);
            p.client_secret = pair.slice(colon + 1);
          }
        } catch (e) {}
      }
      const rec = await rcvCode(env, String(p.code || ''));
      const secret = String(p.client_secret || '');
      let ok = p.client_id === IDP_CID && !!env.IDP_SECRET && secret === String(env.IDP_SECRET);
      if (ok && rec && rec.cc) {
        const digest = await crypto.subtle.digest('SHA-256', enc().encode(String(p.code_verifier || '')));
        ok = b64u(new Uint8Array(digest)) === rec.cc;
      }
      await env.STORE.put('oidc_dbg', JSON.stringify({
        at: new Date().toISOString(), body_len: raw.length, form: p.client_id === undefined ? 'no' : 'yes',
        basic: auth ? 'yes' : 'no', cid: p.client_id === IDP_CID ? 'ok' : 'no',
        sec: secret && secret === String(env.IDP_SECRET) ? 'ok' : 'no', code: p.code ? 'yes' : 'no',
        rec: rec ? 'ok' : 'no', grant: String(p.grant_type || ''),
        nc_len: rec ? String(rec.nc || '').length : -1, ua: String(req.headers.get('User-Agent') || '').slice(0, 40),
      }), { expirationTtl: 900 });
      if (!ok || !rec) return send(JSON.stringify({ error: 'invalid_grant' }), 'application/json', 400);
      const jwt = await idToken(env, rec);
      // Second diagnostic hop: what Access actually got back, minus the signature.
      try {
        const cl = JSON.parse(new TextDecoder().decode(fromB64u(jwt.split('.')[1])));
        await env.STORE.put('oidc_dbg2', JSON.stringify({
          keys: Object.keys(cl).sort().join(','), nonce: cl.nonce ? 'yes' : 'no', aud: String(cl.aud),
          iss: String(cl.iss), exp_minus_iat: Number(cl.exp) - Number(cl.iat), email: String(cl.email || '').length,
          head: jwt.split('.')[0].length, siglen: jwt.split('.')[2].length,
        }), { expirationTtl: 900 });
      } catch (e) {}
      return send(JSON.stringify({
        token_type: 'Bearer', access_token: 'panel.' + Math.floor(Date.now() / 1000),
        expires_in: 300, scope: 'openid email profile', id_token: jwt,
      }), 'application/json');
    }

    if (req.method === 'POST' && url.pathname === '/api/login') {
      const form = await req.formData().catch(() => null);
      const body = form ? { p: form.get('p'), next: form.get('next') } : await readJson(req);
      if (!env.PANEL_KEY || String(body.p || '') !== String(env.PANEL_KEY)) {
        return send(page('口令不对', '登录'), 'text/html', 401);
      }
      // 302 back to the panel: a form post that answers 204 leaves the browser on a blank page,
      // and 进入 looks like it did nothing. An OIDC round trip names where to go back to, and only
      // its own authorize path is accepted -- never an outside URL.
      const back = String(body.next || '').startsWith('/oidc/authorize?') ? String(body.next) : '/';
      return send('', 'text/plain', 302, {
        'Set-Cookie': COOKIE + '=' + await sig(env) + '; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000',
        Location: back,
      });
    }
    if (url.pathname === '/logout') {
      return send('', 'text/plain', 302, { 'Set-Cookie': COOKIE + '=; Path=/; Max-Age=0', Location: '/' });
    }

    const authed = req.headers.get('Cookie') || '';
    const wantApi = url.pathname.startsWith('/api/');
    if (!authed.includes(COOKIE + '=' + (env.PANEL_KEY ? await sig(env) : 'x'))) {
      if (wantApi) return send(JSON.stringify({ error: 'auth' }), 'application/json', 401);
      return send(page('kun9 虚拟机', '登录'), 'text/html');
    }

    if (url.pathname === '/token') return send(page('kun9 虚拟机', '令牌'), 'text/html');
    if (req.method === 'POST' && url.pathname === '/api/token') {
      const given = String((await readJson(req)).t || '').trim();
      if (!/^(github_pat_[A-Za-z0-9_-]{20,}|gh[p]_[A-Za-z0-9]{20,})$/.test(given)) {
        return send(JSON.stringify({ ok: false, note: '看起来不是一个 GitHub 令牌（github_pat_… 或 ghp_…）' }), 'application/json', 400);
      }
      const probe = await gh({ GH_TOKEN: given }, '/repos/' + REPO + '/actions/workflows');
      if (probe.status !== 200) {
        return send(JSON.stringify({ ok: false, note: '这个令牌用不了：' + (probe.note || ('http ' + probe.status)) }), 'application/json', 403);
      }
      await env.STORE.put('gh_token', given, { expirationTtl: 60 * 60 * 24 * 365 });
      return send(JSON.stringify({ ok: true, note: '能用。开机从此是即时触发，关机仍然靠机器自己退出' }), 'application/json');
    }

    if (url.pathname === '/api/status') return send(JSON.stringify(await status(env)), 'application/json');

    if (req.method === 'POST' && url.pathname === '/api/queue') {
      const want = String((await readJson(req)).action || '');
      if (want !== 'start' && want !== 'stop' && want !== 'rdp') return send(JSON.stringify({ ok: false, note: 'action 只能是 start、stop 或 rdp' }), 'application/json', 400);
      if (want === 'rdp') {
        // Desktop repair on a live machine: redo the listener setup and report what the connector
        // can actually reach, without a reboot. Only a running machine has a console worth fixing.
        const live = await runs(env);
        const s = await session();
        if (!(live && live.live) && !(s && s.alive === true && fresh(s.check, 180))) {
          return send(JSON.stringify({ ok: false, note: '机器没开着，桌面没什么可修的' }), 'application/json', 409);
        }
        await env.STORE.put('power', JSON.stringify({ action: 'rdp', at: new Date().toISOString() }), { expirationTtl: 300 });
        return send(JSON.stringify({ ok: true, note: '已下发，机器 20 秒内重配桌面并回报连通性' }), 'application/json');
      }
      if (want === 'start' && await busy(env)) {
        return send(JSON.stringify({ ok: false, note: '已经有机器在跑或正在开机，先关机再说' }), 'application/json', 409);
      }
      // A second 关机 within a minute is the same request, so remember what is already pending
      // before overwriting it: only a request the machine sat on earns a hard cancel.
      const prev = await read(env, 'power');
      // Both flags expire: a start is good for an hour (GitHub can hold the first tick of a
      // freshly-added cron well past five minutes, and a queued start that never got claimed is
      // not worth an hour of a machine nobody asked for either), and a stop the current machine
      // never got to read must not kill the next one.
      await env.STORE.put('power', JSON.stringify({ action: want, at: new Date().toISOString() }), { expirationTtl: 3600 });
      if (want === 'start') await env.STORE.put('booting', '1', { expirationTtl: 900 });
      let note = want === 'start' ? '已排队，看门狗最迟 5 分钟内接手，再等 2-3 分钟装好环境' : '已下发关机，机器最多 20 秒后自停';

      // Optional accelerator: one fine-grained token (this repo, Actions write) pasted at /token
      // turns a queued start into a dispatch, and gives 关机 a force button. The flag is the
      // polite stop and it works -- a live machine reads it inside 20 seconds and leaves by
      // itself, writing the dead record on the way out. Only a machine that ignored the request
      // (same flag still pending a minute later) needs the run cancelled, because a runner that
      // squats holds both the free minutes and busy(), which is what blocks the next 开机.
      if (await token(env)) {
        if (want === 'start') {
          const r = await gh(env, '/repos/' + REPO + '/actions/workflows/' + WF + '/dispatches', { method: 'POST', body: { ref: 'main' } });
          if (r.status === 204) {
            await env.STORE.delete('power');
            note = '已即时触发，2-3 分钟后就绪';
          } else {
            note += '（即时触发失败：' + (r.note || r.status) + '，看门狗兜底）';
          }
        } else if (prev && prev.action === 'stop' && prev.at && !fresh(prev.at, 60)) {
          // The authenticated run list is the authority on whether anything is still running; the
          // record's own run_id only counts while the machine claims to be alive, because GitHub
          // rejects a cancel on a finished run and the flag would then sit there until it kills
          // the next machine.
          const live = await runs(env);
          let id = (live && live.live) || '';
          if (!id) {
            const s = await session(true);
            if (s && s.alive === true) id = s.run_id || '';
          }
          if (!id) {
            await env.STORE.delete('power');
            note = '没有在跑的任务，关机标记已清掉';
          } else {
            const r = await gh(env, '/repos/' + REPO + '/actions/runs/' + id + '/cancel', { method: 'POST' });
            if (r.status === 202) {
              await env.STORE.delete('power');
              note = '机器没响应，已强制取消任务 #' + id;
            } else {
              note += '（强制取消 #' + id + ' 失败：' + (r.note || r.status) + '）';
            }
          }
        } else {
          note += '，60 秒后还在就再按一次关机强制取消';
        }
      }
      return send(JSON.stringify({ ok: true, note: note }), 'application/json');
    }

    if (url.pathname === '/' || url.pathname === '/index.html') return send(page('kun9 虚拟机', '面板'), 'text/html');
    return send('not found', 'text/plain', 404);
  },
};

async function readJson(req) {
  try {
    return await req.json();
  } catch (e) {
    return {};
  }
}

async function read(env, key) {
  if (!env.STORE) return null;
  const raw = await env.STORE.get(key);
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch (e) {
    return raw;
  }
}

async function token(env) {
  if (env.GH_TOKEN) return env.GH_TOKEN;
  return env.STORE ? await env.STORE.get('gh_token') : '';
}

async function gh(env, path, opts) {
  opts = opts || {};
  const tok = await token(env);
  const headers = { Accept: 'application/vnd.github+json', 'User-Agent': 'kun9-vmctl', 'X-GitHub-Api-Version': '2022-11-28' };
  if (tok) headers.Authorization = 'Bearer ' + tok;
  if (opts.body) headers['Content-Type'] = 'application/json';
  const res = await fetch(API + path, { method: opts.method || 'GET', headers: headers, body: opts.body ? JSON.stringify(opts.body) : undefined });
  const text = await res.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch (e) {
    json = null;
  }
  return { status: res.status, json: json, note: json && json.message ? String(json.message).slice(0, 160) : '' };
}

// Never bring up a second machine: the watchdog may only claim a start when no heartbeat is
// fresh and no run of this workflow is still queued or in progress.
async function busy(env, ignoreBooting) {
  // 'booting' is written by the panel the moment it queues a start, so the watchdog must not read
  // it as evidence of a machine -- it is evidence of the very request it is here to claim.
  if (!ignoreBooting && env.STORE && (await env.STORE.get('booting'))) return true;
  const s = await session(true);
  if (s && s.alive && fresh(s.check, 180)) return true;
  const r = await runs(env);
  return !!(r && r.live);
}

function fresh(iso, seconds) {
  const t = new Date(iso || 0).getTime();
  return !isNaN(t) && Date.now() - t < seconds * 1000;
}

async function session(force) {
  // raw.githubusercontent answers with max-age=300, so this file can be minutes behind the machine
  // it describes. The ten-second bucket only stops the edge caching it a second time.
  const url = RAW + '?t=' + Math.floor(Date.now() / 10000);
  return fetch(url, { cf: { cacheTtl: force ? 0 : 10, cache: 'bypass', forceRefresh: !!force } })
    .then((r) => (r.ok ? r.json() : null))
    .catch(() => null);
}

// The run list of a public repo is readable without a token, but an anonymous call from the edge
// shares one IP's 60/h budget with every other Worker on the same IP, so it fails often enough to
// matter. With a token this becomes an authenticated call and stops being a coin flip; busy(),
// which refuses to bring up a second machine, is the reason the answer has to be dependable.
async function runs(env) {
  const res = await gh(env, RUNS);
  if (!res.json || !res.json.workflow_runs || !res.json.workflow_runs.length) return null;
  const list = res.json.workflow_runs;
  const live = list.filter((r) => r.status === 'in_progress' || r.status === 'queued');
  const pick = live.length ? live[0] : list[0];
  return {
    id: pick.id,
    number: pick.run_number,
    status: pick.status,
    conclusion: pick.conclusion,
    created: pick.created_at,
    event: pick.event,
    url: pick.html_url,
    live: live.length ? pick.id : null,
  };
}

async function status(env) {
  const out = { now: new Date().toISOString(), vm: null, run: null, queue: null, error: '', has_token: false };
  out.has_token = !!(await token(env));
  const r = await runs(env);
  if (r) out.run = r;
  else out.error = '读任务列表失败（GitHub 限流或未响应）';
  const s = await session();
  if (s) {
    // raw answers with max-age=300, so the file can still be the previous run's alive:true for
    // minutes after that machine was released -- and as soon as a new run is live the old check
    // timestamp stops meaning anything. Only the record of the run that is actually live may claim
    // a machine; anything else is a leftover, and 打开桌面/终端 on it leads nowhere. A runner killed by
    // a cancel never writes alive:false either, so a heartbeat older than three cycles is dead too.
    const mine = !(r && r.live) || String(s.run_id || '') === String(r.live);
    // session.json also carries the RDP/SSH diagnostics and log tails; the panel needs none of
    // that, so only the fields it displays leave the edge.
    out.vm = {
      alive: mine && s.alive === true && (fresh(s.check, 180) || !!(r && r.live)),
      url: s.url || '',
      user: mine ? (s.user || '') : '',
      ends: mine ? (s.ends || '') : '',
      check: s.check || '',
      note: mine ? (s.note || '') : '',
      named: s.named || '',
      run_id: s.run_id || '',
      restarts: mine ? s.restarts : 0,
      origin: mine ? String(s.ssh_info || '') : '',
      rdp: mine ? String(s.rdp_diag || '') : '',
      rdp_ip: mine ? String(s.rdp_ip || '') : '',
      ttl_min: s.ttl_min,
      closed: s.closed || '',
    };
  }
  out.queue = await read(env, 'power');
  return out;
}

const enc = () => new TextEncoder();
const b64u = (bytes) =>
  btoa(String.fromCharCode.apply(null, Array.from(bytes))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

async function idpKey(env) {
  // The signing key lives in a secret_text binding (IDP_JWK), never in KV, and Access only ever
  // sees the public half through /oidc/jwks.
  const jwk = JSON.parse(String(env.IDP_JWK));
  const key = await crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, true, ['sign']);
  return { key: key, kid: jwk.kid || 'vmctl1' };
}

async function jwks(env) {
  const pub = Object.assign({}, JSON.parse(String(env.IDP_JWK)));
  ['d', 'p', 'q', 'dp', 'dq', 'qi', 'k'].forEach((x) => delete pub[x]);
  pub.key_ops = ['verify'];
  pub.kid = pub.kid || 'vmctl1';
  pub.alg = 'RS256';
  pub.use = 'sig';
  return { keys: [pub] };
}

async function idToken(env, rec) {
  const { key, kid } = await idpKey(env);
  const now = Math.floor(Date.now() / 1000);
  const head = { alg: 'RS256', typ: 'JWT', kid: kid };
  const body = {
    iss: 'https://' + IDP_HOST, aud: IDP_CID, sub: 'vmctl-owner', iat: now, exp: now + 300, auth_time: now,
    email: IDP_EMAIL, email_verified: true, name: 'kun9', preferred_username: 'kun9',
  };
  if (rec.nc) body.nonce = rec.nc;
  const unsigned = b64u(enc().encode(JSON.stringify(head))) + '.' + b64u(enc().encode(JSON.stringify(body)));
  const sign = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, enc().encode(unsigned));
  return unsigned + '.' + b64u(new Uint8Array(sign));
}

const fromB64u = (s) => Uint8Array.from(atob(String(s).replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));

function nonceFromState(st) {
  // Access's state is "<64 hex>.<base64 of a percent-encoded JSON>", and the whole thing arrives
  // percent-encoded again, so the blob needs one decode before base64 and one after. The nonce we
  // have to hand back sits in that JSON -- a token without it is refused as an IdP fetch failure.
  try {
    const i = String(st || '').indexOf('.');
    if (i < 0) return '';
    let b = decodeURIComponent(String(st).slice(i + 1)).replace(/-/g, '+').replace(/_/g, '/');
    if (b.indexOf('=') < 0) b += '==='.slice(0, (4 - (b.length % 4)) % 4);
    const o = JSON.parse(decodeURIComponent(atob(b)));
    return String(o.nonce || '');
  } catch (e) {
    return '';
  }
}

async function codeMac(env, data) {
  const key = await crypto.subtle.importKey('raw', enc().encode(String(env.IDP_SECRET || env.PANEL_KEY)), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return b64u(new Uint8Array(await crypto.subtle.sign('HMAC', key, enc().encode(data))));
}

async function mkCode(env, o) {
  const body = b64u(enc().encode(JSON.stringify(o)));
  return body + '.' + (await codeMac(env, body));
}

async function rcvCode(env, code) {
  const p = String(code || '').split('.');
  if (p.length !== 2 || !env.IDP_SECRET) return null;
  if ((await codeMac(env, p[0])) !== p[1]) return null;
  let o;
  try {
    o = JSON.parse(new TextDecoder().decode(fromB64u(p[0])));
  } catch (e) {
    return null;
  }
  if (!o || !o.rd || !o.x || Date.now() - Number(o.x) > 90000) return null;
  return o;
}

async function sig(env) {
  const key = await crypto.subtle.importKey('raw', enc().encode(String(env.PANEL_KEY)), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const mac = await crypto.subtle.sign('HMAC', key, enc().encode('vmctl-v1'));
  return Array.from(new Uint8Array(mac))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function page(title, mode) {
  if (mode === '登录') {
    return '<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">' +
      '<title>' + title + '</title><style>' + css() + '</style></head><body><div class="wrap"><form class="card login" method="post" action="/api/login">' +
      '<h1>' + title + '</h1><p>网页控制台面板</p><input type="password" name="p" placeholder="面板口令" autofocus autocomplete="current-password">' +
      '<input type="hidden" name="next" id="next"><button type="submit">进入</button></form></div>' +
      '<script>var n=new URLSearchParams(location.search).get("next");if(n&&n.indexOf("/oidc/authorize?")==0)document.getElementById("next").value=n;</script>' +
      '</body></html>';
  }
  if (mode === '令牌') {
    return '<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">' +
      '<title>' + title + ' · 可选：即时开机</title><style>' + css() + '</style></head><body><div class="wrap">' +
      '<form class="card login" id="f"><h1>贴一个专用小令牌（可选）</h1>' +
      '<p>不贴也能用：开机走 5 分钟一次的 Actions 看门狗。贴上以后开机变成即时触发，关机照旧靠机器自己退出。' +
      '<a href="https://github.com/settings/personal-access-tokens/new" target="_blank">在这里建令牌</a>：' +
      'Repository access 选 Only select repositories → kunge520/kun9-compute，Permissions 只勾 Actions: Read and write。' +
      '它只存在这个 Worker 里，页面永远不会把它回显出来。</p>' +
      '<input type="password" id="t" placeholder="粘贴 github_pat_…" autocomplete="off">' +
      '<button type="submit">校验并存起来</button><div id="m" class="msg"></div></form>' +
      '<div class="foot"><a href="/">回面板</a></div></div>' +
      '<script>document.getElementById("f").onsubmit=async function(e){e.preventDefault();' +
      'var m=document.getElementById("m");m.textContent="校验中…";' +
      'var r=await fetch("/api/token",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({t:document.getElementById("t").value})});' +
      'var j=await r.json().catch(function(){return {}});m.textContent=j.ok?(j.note+"（回面板按开机就是秒开）"):("不行："+(j.note||r.status));' +
      'if(j.ok){document.getElementById("t").value=\'\'}};</script></body></html>';
  }
  return '<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">' +
    '<title>' + title + '</title><style>' + css() + '</style></head><body><div class="wrap">' +
    '<div class="card head"><div><h1>' + title + '</h1><div id="state" class="state">读取中…</div></div><div id="dot" class="dot"></div></div>' +
    '<div class="card" id="wait" style="display:none"><div class="phase"><div class="spin"></div><div><b id="ph">正在开机</b><div id="elapsed" class="mut"></div></div></div>' +
    '<div class="bar"><i></i></div><div id="hint" class="hint"></div></div>' +
    '<div class="card"><div class="grid">' +
    '<div><span>地址</span><b id="url">-</b></div>' +
    '<div><span>登录名</span><b id="user">-</b></div>' +
    '<div><span>到期</span><b id="ends">-</b></div>' +
    '<div><span>剩余</span><b id="left">-</b></div>' +
    '<div><span>任务</span><b id="run">-</b></div>' +
    '<div><span>心跳</span><b id="check">-</b></div>' +
    '</div><div id="note" class="note"></div></div>' +
    '<div class="card acts">' +
    '<button id="brdp" class="term">打开桌面</button>' +
    '<button id="bssh" class="term">打开终端</button>' +
    '<button id="bstart" class="ok">开机</button>' +
    '<button id="bstop" class="stop">关机</button>' +
    '<a class="log" id="log" href="#" target="_blank">看日志</a>' +
    '</div>' +
    '<div id="msg" class="msg"></div>' +
    '<div class="foot"><span id="upd"></span><a id="tok" href="/token">配令牌（可选，秒开机）</a><a href="/logout">退出</a></div>' +
    '</div><script>' + app() + '</script></body></html>';
}

function css() {
  return [
    '*{box-sizing:border-box}',
    ':root{--bg:#05070e;--ink:#d8fbff;--mut:#5f7c8a;--cy:#22e7ff;--mg:#ff2e88;--pu:#8b5cff;--li:#24ffa0;--am:#ffc93c;--line:rgba(34,231,255,.28)}',
    'html{background:var(--bg)}',
    'body{margin:0;min-height:100vh;color:var(--ink);letter-spacing:.3px;font:14px/1.7 "Cascadia Mono","JetBrains Mono",ui-monospace,Consolas,"DejaVu Sans Mono","Microsoft YaHei",monospace;background:radial-gradient(1100px 600px at 8% -10%,rgba(34,231,255,.12),transparent 60%),radial-gradient(950px 700px at 108% 12%,rgba(255,46,136,.12),transparent 55%),radial-gradient(900px 900px at 50% 120%,rgba(139,92,255,.10),transparent 60%),var(--bg)}',
    'body::before{content:"";position:fixed;inset:0;pointer-events:none;z-index:0;background-image:linear-gradient(rgba(34,231,255,.05) 1px,transparent 1px),linear-gradient(90deg,rgba(34,231,255,.05) 1px,transparent 1px);background-size:34px 34px;-webkit-mask-image:radial-gradient(circle at 50% 35%,#000,transparent 78%);mask-image:radial-gradient(circle at 50% 35%,#000,transparent 78%)}',
    'body::after{content:"";position:fixed;inset:0;pointer-events:none;z-index:40;opacity:.26;background:repeating-linear-gradient(transparent 0 2px,rgba(0,0,0,.55) 2px 3px);animation:scan 9s linear infinite}',
    '@keyframes scan{to{background-position:0 300px}}',
    '.wrap{position:relative;z-index:1;max-width:560px;margin:0 auto;padding:34px 20px 60px}',
    '.wrap::before,.wrap::after{content:"";position:absolute;width:42px;height:42px;pointer-events:none}',
    '.wrap::before{top:12px;left:6px;border-top:2px solid var(--cy);border-left:2px solid var(--cy);filter:drop-shadow(0 0 6px var(--cy))}',
    '.wrap::after{bottom:12px;right:6px;border-bottom:2px solid var(--mg);border-right:2px solid var(--mg);filter:drop-shadow(0 0 6px var(--mg))}',
    '.card{position:relative;background:rgba(8,14,22,.72);backdrop-filter:blur(7px);-webkit-backdrop-filter:blur(7px);border:1px solid var(--line);padding:16px 18px;margin-bottom:16px;clip-path:polygon(0 14px,14px 0,calc(100% - 14px) 0,100% 14px,100% calc(100% - 14px),calc(100% - 14px) 100%,14px 100%,0 calc(100% - 14px));filter:drop-shadow(0 0 6px rgba(34,231,255,.18))}',
    '.head{display:flex;justify-content:space-between;align-items:center}',
    'h1{font-size:17px;margin:0 0 4px;letter-spacing:3px;text-transform:uppercase;color:var(--cy);text-shadow:0 0 8px rgba(34,231,255,.8),0 0 22px rgba(34,231,255,.35);animation:flick 6s infinite}',
    '@keyframes flick{0%,96%,100%{opacity:1}97%{opacity:.5}98.5%{opacity:.85}}',
    '.state{color:var(--mut);font-size:12px;letter-spacing:1px;text-transform:uppercase}',
    '.dot{width:15px;height:15px;border-radius:50%;background:#1a2530;box-shadow:inset 0 0 5px #000,0 0 0 1px rgba(34,231,255,.2)}',
    '.dot.on{background:var(--li);box-shadow:0 0 10px var(--li),0 0 24px var(--li);animation:pulse 1.8s ease-in-out infinite}',
    '.dot.wait{background:var(--am);box-shadow:0 0 10px var(--am),0 0 24px var(--am);animation:pulse 1.05s ease-in-out infinite}',
    '@keyframes pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.4;transform:scale(.7)}}',
    '.grid{display:grid;grid-template-columns:1fr 1fr;gap:11px 18px}',
    '.grid span{display:block;color:var(--mut);font-size:11px;letter-spacing:1.5px;text-transform:uppercase}',
    '.grid b{font-weight:600;word-break:break-all;font-size:14px;color:var(--ink);text-shadow:0 0 7px rgba(34,231,255,.3)}',
    '.note{margin-top:12px;color:var(--mut);font-size:12px;word-break:break-all;line-height:1.8}',
    '.acts{display:flex;gap:10px;align-items:stretch;flex-wrap:wrap}',
    'button{flex:1 1 auto;min-width:120px;padding:12px 6px;border:1px solid var(--cy);background:rgba(34,231,255,.06);color:var(--cy);font:inherit;font-size:14px;font-weight:700;letter-spacing:2px;text-transform:uppercase;cursor:pointer;transition:.18s;clip-path:polygon(0 9px,9px 0,calc(100% - 9px) 0,100% 9px,100% calc(100% - 9px),calc(100% - 9px) 100%,9px 100%,0 calc(100% - 9px))}',
    'button:hover{filter:drop-shadow(0 0 9px currentColor)}',
    'button:active{transform:translateY(1px)}',
    'button:disabled{opacity:.3;cursor:default;filter:none;background:transparent}',
    '.ok{border-color:var(--li);color:var(--li);background:rgba(36,255,160,.06)}',
    '.stop{border-color:var(--mg);color:var(--mg);background:rgba(255,46,136,.06)}',
    '.term{border-color:var(--cy);color:var(--cy);background:rgba(34,231,255,.06)}',
    '.log{display:flex;align-items:center;padding:0 12px;color:var(--mg);border:1px solid var(--mg);font-size:12px;letter-spacing:1px;text-transform:uppercase;text-decoration:none;white-space:nowrap;clip-path:polygon(0 9px,9px 0,100% 0,100% calc(100% - 9px),calc(100% - 9px) 100%,0 100%)}',
    '.log:hover{filter:drop-shadow(0 0 8px var(--mg))}',
    '.msg{min-height:20px;font-size:13px;color:var(--am);letter-spacing:.5px;padding:2px 4px;text-shadow:0 0 7px rgba(255,201,60,.4)}',
    '.phase{display:flex;gap:12px;align-items:center}',
    '.phase b{font-size:14px;color:var(--cy);letter-spacing:1px;text-transform:uppercase;text-shadow:0 0 7px rgba(34,231,255,.5)}',
    '.mut{color:var(--mut);font-size:12px}',
    '.spin{width:26px;height:26px;flex:none;border-radius:50%;border:3px solid rgba(34,231,255,.18);border-top-color:var(--cy);box-shadow:0 0 12px rgba(34,231,255,.5);animation:turn .9s linear infinite}',
    '@keyframes turn{to{transform:rotate(360deg)}}',
    '.bar{height:6px;border-radius:6px;background:rgba(0,0,0,.55);border:1px solid rgba(34,231,255,.18);overflow:hidden;margin:14px 0 10px}',
    '.bar i{display:block;height:100%;width:36%;background:linear-gradient(90deg,transparent,var(--cy),var(--mg),transparent);box-shadow:0 0 14px var(--cy);animation:slide 2.2s linear infinite}',
    '@keyframes slide{0%{transform:translateX(-120%)}100%{transform:translateX(320%)}}',
    '.hint{color:var(--mut);font-size:12px;min-height:20px;letter-spacing:.5px}',
    '.foot{display:flex;justify-content:space-between;align-items:center;gap:10px;color:var(--mut);font-size:11px;letter-spacing:1px;text-transform:uppercase;padding:2px 4px}',
    '.foot a{color:var(--mut);text-decoration:none}',
    '.foot a:hover{color:var(--cy);text-shadow:0 0 8px var(--cy)}',
    '.login input{width:100%;padding:12px;margin-bottom:12px;border:1px solid var(--line);background:rgba(0,0,0,.5);color:var(--ink);font:inherit;font-size:15px;letter-spacing:2px}',
    '.login input:focus{outline:none;border-color:var(--cy);box-shadow:0 0 0 1px var(--cy),0 0 16px rgba(34,231,255,.5)}',
    '.login button{width:100%;min-width:0}',
    '.login p{color:var(--mut);font-size:12px;line-height:1.8;margin:0 0 16px}',
    '.login a{color:var(--mg)}',
  ].join('');
}

function app() {
  return [
    "var $=function(i){return document.getElementById(i)};",
    "function esc(s){return (''+(s==null?'':s)).replace(/[&<>]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;'}[c]})}",
    "function fmt(t){if(!t)return '-';var d=new Date(t);return isNaN(d)?t:d.toLocaleString('zh-CN',{hour12:false})}",
    "function post(u,b){return fetch(u,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b||{})}).then(function(r){return r.json().then(function(j){return {code:r.status,j:j}})})}",
    "function say(m){$('msg').textContent=m||''}",
    "var HINTS=['GitHub 的免费 Windows 机器要先排队领用，这一步最慢','正在装 Git / cloudflared','隧道在握手，第一次连会慢一点','整条链路一般是 2-4 分钟','机器起来后按「打开桌面」或「打开终端」','趁这个空档可以去倒杯水','开机期间再按一次开机是没用的，按钮会自己变灰','桌面走 RDP，终端走 SSH，都是 Cloudflare 直出，不用装客户端'];",
    "var waiting=false,wait0=0,hintI=0,hintAt=0;",
    "async function tick(){",
    " var r;try{r=await(await fetch('/api/status',{cache:'no-store'})).json()}catch(e){say('读取失败：'+e);return}",
    " var v=r.vm||{},u=r.run||{},q=r.queue,alive=v&&v.alive,runLive=u&&u.live;",
    " var dot=$('dot'),st=$('state');",
    " var phase='';",
    " if(alive){dot.className='dot on';st.textContent='运行中';}",
    " else if(runLive){phase='boot';dot.className='dot wait';st.textContent=(u.event==='schedule'?'看门狗已接手，正在开机':'开机中（任务还在跑，还没上报）');}",
    " else if(q&&q.action==='start'){phase='queue';dot.className='dot wait';st.textContent='排队开机，等下一次看门狗';}",
    " else if(q&&q.action==='stop'){dot.className='dot wait';st.textContent='排队关机';}",
    " else {dot.className='dot';st.textContent='已关机';}",
    " waiting=!!phase;",
    " $('wait').style.display=phase?'':'none';",
    " if(phase){$('ph').textContent=phase==='boot'?'正在开机：机器还没开始上报':'排队开机：等看门狗接手';wait0=(new Date(String(phase==='boot'?(u.created||''):(q.at||''))).getTime())||0;}",
    " $('url').textContent=v.url||'-';",
    " $('user').textContent=alive?(v.user||'-'):'administrator';",
    " $('ends').textContent=fmt(v.ends);",
    " $('check').textContent=fmt(v.check);",
    " $('run').textContent=u?('#'+(u.number||'')+' '+u.status+(u.conclusion?' / '+u.conclusion:'')):'-';",
    " $('note').innerHTML=(v.note?('状态：'+esc(v.note)+(v.restarts>0?(' · 隧道重连过 '+esc(v.restarts)+' 次'):'')):'')+(v.rdp?('<br>桌面 '+esc(v.rdp)):'')+(v.origin?('<br>终端 '+esc(v.origin)):'')+(r.error?('<br>'+esc(r.error)):'');",
    " $('log').href=u.url||'https://github.com/kunge520/kun9-compute/actions';",
    " $('bssh').disabled=!alive;",
    " $('brdp').disabled=!alive;",
    " $('bstart').disabled=!!(alive||runLive||(q&&q.action==='start'));",
    " $('bstop').disabled=!(alive||runLive)&&!(q&&q.action==='stop');",
    " $('tok').textContent=r.has_token?'已配令牌（秒开机）':'配令牌（可选，秒开机）';",
    " if(v.ends){var ms=new Date(v.ends).getTime()-Date.now();$('left').textContent=ms>0?Math.floor(ms/60000)+' 分 '+Math.floor(ms%60000/1000)+' 秒':'已到期';}",
    " else $('left').textContent='-';",
    " $('upd').textContent='刷新于 '+new Date().toLocaleTimeString('zh-CN',{hour12:false});",
    "}",
    "$('bssh').onclick=function(){window.open(SSHBASE,'_blank')};",
    "$('bstart').onclick=async function(){say('正在排队开机…');var x=await post('/api/queue',{action:'start'});say(x.j.note||(x.j.ok?'已排队':'开机失败：'+x.code));setTimeout(tick,1500)};",
    "$('bstop').onclick=async function(){if(!confirm('确定关机？这台机器上的未保存内容会丢。'))return;say('正在下发关机…');var x=await post('/api/queue',{action:'stop'});say(x.j.note||(x.j.ok?'已下发':'关机失败：'+x.code));setTimeout(tick,1500)};",
    "var SSHBASE='" + SSH_APP + "';",
    "var RDPURL='" + RDP_APP + '/rdp/' + RDP_VNET + '/' + RDP_TARGET + "/3389';",
    "$('brdp').onclick=function(){window.open(RDPURL,'_blank')};",
    "setInterval(function(){",
    " if(!waiting)return;",
    " var s=wait0?Math.max(0,Math.round((Date.now()-wait0)/1000)):0;",
    " $('elapsed').textContent=wait0?('已等 '+s+' 秒，整条链路一般 2-4 分钟'):'正在开机…';",
    " if(!($('hint').textContent)){hintI=Math.floor(Math.random()*HINTS.length);$('hint').textContent=HINTS[hintI];hintAt=Date.now();return;}",
    " if(Date.now()-hintAt>4000){hintAt=Date.now();hintI=(hintI+1)%HINTS.length;$('hint').textContent=HINTS[hintI];}",
    "},1000);",
    "async function loop(){await tick();setTimeout(loop,waiting?5000:15000)}",
    "loop();",
  ].join('\n');
}

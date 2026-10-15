
// kun9 VM control panel — one page that turns the GitHub free Windows runner on and off.
//
//
// Power is one path each way. 开机 makes this Worker POST workflow_dispatch to GitHub, so a runner
// picks it up in seconds; if the dispatch fails, the panel says so and nothing quietly happens later.
// Stopping is the mirror image: the panel writes a stop flag here and the live VM reads it on its next
// heartbeat (/api/power) and ends its own run.
//
// Dispatch needs a repo Actions token, which is what /token stores here, so without it 开机 reports
// the missing token instead of falling back to something slower. The secrets kept in this Worker are
// PANEL_KEY, the password for the page, and that token.

const REPO = 'kunge520/kun9-compute';
const API = 'https://api.github.com';
// Two machines, one panel, and only ever one of them up. They share a single named tunnel and a
// single pair of hostnames, so 打开桌面/打开终端 below are the same two links for both boxes and can
// never point at the wrong machine -- but it also means busy() is global: a live Windows box blocks
// a Linux start, because two connectors on one tunnel would split the same hostname between them.
// Windows keeps the legacy KV keys so an in-flight request survives this deploy.
const MACH = {
  win: { name: 'Windows', wf: 'winterm.yml', path: 'winterm/session.json', pw: 'power', bt: 'booting' },
  linux: { name: 'Linux', wf: 'linuxd.yml', path: 'linux/session.json', pw: 'power:linux', bt: 'booting:linux' },
};
const KEYS = ['win', 'linux'];
// Default win: winterm.yml polls these endpoints with no machine parameter and must not change.
const pick = (x) => (String(x || '').toLowerCase() === 'linux' ? MACH.linux : MACH.win);
const runsOf = (m) => '/repos/' + REPO + '/actions/workflows/' + m.wf + '/runs?per_page=3';
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
    // ?m=linux selects the Ubuntu box; no parameter means the Windows box, which is what winterm.yml
    // has always sent. There is no /api/claim any more: a start is dispatched by the panel itself, so
    // nothing on the runner side ever has to ask for one.
    if (url.pathname === '/api/power') {
      const m = pick(url.searchParams.get('m'));
      // The live VM is the only thing that polls this, so its first poll is also the proof that the
      // dispatched start actually became a machine -- which is what clears the 'booting' flag that
      // busy() has been holding since the dispatch.
      if (env.STORE && (await env.STORE.get(m.bt))) await env.STORE.delete(m.bt);
      const q = await read(env, m.pw);
      return send(JSON.stringify({ action: q && (q.action === 'stop' || q.action === 'rdp') ? q.action : 'none' }), 'application/json');
    }
    if (req.method === 'POST' && url.pathname === '/api/power/clear') {
      const m = pick(url.searchParams.get('m'));
      // Deleted without reading first: KV can serve a write from a few seconds earlier as missing, and a
      // stop the machine has already obeyed must not survive that race for the rest of its TTL -- the
      // panel would keep saying 关机中 for an hour after a clean shutdown.
      await env.STORE.delete(m.pw);
      await env.STORE.delete(m.bt);
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
      // Only a real form post may go through formData(): reading the body that way consumes it, so a
      // JSON login that tried it first would be left parsing an empty stream and refused as 口令不对.
      const isForm = (req.headers.get('Content-Type') || '').indexOf('application/x-www-form-urlencoded') >= 0;
      const form = isForm ? await req.formData().catch(() => null) : null;
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

    if (url.pathname === '/api/status') return send(JSON.stringify(await status(env, pick(url.searchParams.get('m')))), 'application/json');

    if (req.method === 'POST' && url.pathname === '/api/queue') {
      const body = await readJson(req);
      const want = String(body.action || '');
      const m = pick(body.m);
      if (want !== 'start' && want !== 'stop' && want !== 'rdp') return send(JSON.stringify({ ok: false, note: 'action 只能是 start、stop 或 rdp' }), 'application/json', 400);
      if (want === 'rdp') {
        // Desktop repair on a live machine: redo the listener setup and report what the connector
        // can actually reach, without a reboot. Only a running machine has a console worth fixing.
        const live = await runs(env, m);
        const s = await session(env, m);
        if (!(live && live.live) && !(s && s.alive === true && fresh(s.check, 180))) {
          return send(JSON.stringify({ ok: false, note: '机器没开着，桌面没什么可修的' }), 'application/json', 409);
        }
        await env.STORE.put(m.pw, JSON.stringify({ action: 'rdp', at: new Date().toISOString() }), { expirationTtl: 300 });
        return send(JSON.stringify({ ok: true, note: '已下发，机器 20 秒内重配桌面并回报连通性' }), 'application/json');
      }
      if (want === 'start' && await busy(env)) {
        return send(JSON.stringify({ ok: false, note: '已经有机器在跑或正在开机，先关机再说' }), 'application/json', 409);
      }
      // 开机 is the dispatch and nothing else: GitHub takes it now, so there is no queue record for a
      // start -- that record is only ever read by a live machine, so a queued start would be a stop
      // request for whichever machine comes up next. A failed dispatch says so and sets nothing.
      if (want === 'start') {
        if (!(await token(env))) return send(JSON.stringify({ ok: false, note: '开机需要一个 Actions 令牌，先去 /token 贴一个' }), 'application/json', 409);
        // Clear any leftover stop flag first: the machine that should have read it is gone, and the
        // one coming up must not be handed someone's old 关机.
        await env.STORE.delete(m.pw);
        const r = await gh(env, '/repos/' + REPO + '/actions/workflows/' + m.wf + '/dispatches', { method: 'POST', body: { ref: 'main' } });
        if (r.status !== 204) return send(JSON.stringify({
          ok: false,
          note: '即时触发失败：' + ((r.status === 401 || r.status === 403) ? 'GitHub 不认这个令牌，去 /token 重贴一个' : (r.note || r.status)),
        }), 'application/json', 502);
        // The flag holds busy() across the bring-up and the machine's first /api/power poll clears it;
        // 1200 s is slack for a runner that dies during setup, not an expected wait.
        await env.STORE.put(m.bt, '1', { expirationTtl: 1200 });
        // Measured on both boxes, dispatch -> first heartbeat is about a minute: Linux publishes at
        // +11 s with its desktop listening by +49 s, Windows at +51 s. The only real variance is GitHub
        // handing out a runner.
        return send(JSON.stringify({ ok: true, note: '已触发，一般 1 分钟左右就绪，GitHub 繁忙时排队更久' }), 'application/json');
      }
      // A second 关机 within a minute is the same request, so remember what is already pending
      // before overwriting it: only a request the machine sat on earns a hard cancel.
      const prev = await read(env, m.pw);
      // It expires so that a stop the current machine never got to read cannot kill the next one.
      await env.STORE.put(m.pw, JSON.stringify({ action: want, at: new Date().toISOString() }), { expirationTtl: 3600 });
      let note = '已下发关机，机器最多 20 秒后自停';
      // The flag is the polite stop and it works -- a live machine reads it inside 20 seconds and
      // leaves by itself, writing the dead record on the way out. Only a machine that ignored the
      // request (the same flag still pending a minute later) needs the run cancelled, because a
      // runner that squats holds both the free minutes and busy(), which is what blocks 开机 again.
      if (await token(env)) {
        if (prev && prev.action === 'stop' && prev.at && !fresh(prev.at, 60)) {
          // The authenticated run list is the authority on whether anything is still running; the
          // record's own run_id only counts while the machine claims to be alive, because GitHub
          // rejects a cancel on a finished run and the flag would then sit there until it kills
          // the next machine.
          const live = await runs(env, m);
          let id = (live && live.live) || '';
          if (!id) {
            const s = await session(env, m);
            if (s && s.alive === true) id = s.run_id || '';
          }
          if (!id) {
            await env.STORE.delete(m.pw);
            note = '没有在跑的任务，关机标记已清掉';
          } else {
            const r = await gh(env, '/repos/' + REPO + '/actions/runs/' + id + '/cancel', { method: 'POST' });
            if (r.status === 202) {
              await env.STORE.delete(m.pw);
              note = '机器没响应，已强制取消任务 #' + id;
            } else {
              note += '（强制取消 #' + id + ' 失败：' + (r.note || r.status) + '）';
            }
          }
        } else {
          note += '，60 秒后还在就再按一次关机强制取消';
        }
      } else {
        note += '，没配令牌就取消不了卡死的任务';
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

// Never bring up a second machine: 开机 only dispatches when no heartbeat of EITHER box is fresh and
// no run of EITHER workflow is still queued or in progress. The mutex is global on purpose
// -- both boxes share one tunnel and one hostname pair, so two live connectors would split the same
// address between them.
async function busy(env) {
  for (const k of KEYS) {
    const m = MACH[k];
    if (env.STORE && (await env.STORE.get(m.bt))) return true;
    const s = await session(env, m);
    if (s && s.alive && fresh(s.check, 180)) return true;
    const r = await runs(env, m);
    if (r && r.live) return true;
  }
  return false;
}

function fresh(iso, seconds) {
  const t = new Date(iso || 0).getTime();
  return !isNaN(t) && Date.now() - t < seconds * 1000;
}

// The heartbeat is read through the contents API, not raw.githubusercontent.com: measured 2026-10-16,
// raw keeps serving the previous version of a path for minutes and ignores the query string, so even a
// unique ?t= comes back stale -- that lag, not the machine, was what made the panel sit on 开机中 long
// after the box was already up. The API answers the commit that just landed, and it is paid for with
// the same credential 开机 uses.
async function session(env, m) {
  const r = await gh(env, '/repos/' + REPO + '/contents/' + m.path + '?ref=main');
  if (!r.json || !r.json.content) return null;
  try {
    const bin = atob(String(r.json.content).replace(/\s+/g, ''));
    return JSON.parse(new TextDecoder().decode(Uint8Array.from(bin, (c) => c.charCodeAt(0))));
  } catch (e) {
    return null;
  }
}

// The run list of a public repo is readable without a token, but an anonymous call from the edge
// shares one IP's 60/h budget with every other Worker on the same IP, so it fails often enough to
// matter. With a token this becomes an authenticated call and stops being a coin flip; busy(),
// which refuses to bring up a second machine, is the reason the answer has to be dependable.
async function runs(env, m) {
  const res = await gh(env, runsOf(m));
  if (!res.json || !res.json.workflow_runs || !res.json.workflow_runs.length) return null;
  const list = res.json.workflow_runs;
  const live = list.filter((r) => r.status === 'in_progress' || r.status === 'queued');
  const pickRun = live.length ? live[0] : list[0];
  return {
    id: pickRun.id,
    number: pickRun.run_number,
    status: pickRun.status,
    conclusion: pickRun.conclusion,
    created: pickRun.created_at,
    event: pickRun.event,
    url: pickRun.html_url,
    live: live.length ? pickRun.id : null,
  };
}

async function status(env, m) {
  const out = { now: new Date().toISOString(), machine: m.name, vm: null, run: null, queue: null, error: '', has_token: false };
  out.has_token = !!(await token(env));
  const r = await runs(env, m);
  if (r) out.run = r;
  else out.error = '读任务列表失败（GitHub 限流或未响应）';
  const s = await session(env, m);
  if (s) {
    // A runner killed by a cancel never writes alive:false, so the previous run's heartbeat can outlive
    // it -- only the record whose run_id matches the live run may claim a machine, because 打开桌面/终端
    // on a leftover leads nowhere. A heartbeat older than three cycles is dead too.
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
      drive: mine ? String(s.drive || '') : '',
      rdp_ip: mine ? String(s.rdp_ip || '') : '',
      ttl_min: s.ttl_min,
      closed: s.closed || '',
    };
  }
  out.queue = await read(env, m.pw);
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
      '<h1>' + title + '</h1><p>输入面板口令进入</p><input type="password" name="p" placeholder="面板口令" autofocus autocomplete="current-password">' +
      '<input type="hidden" name="next" id="next"><button type="submit" class="pri">进入</button></form></div>' +
      '<script>var n=new URLSearchParams(location.search).get("next");if(n&&n.indexOf("/oidc/authorize?")==0)document.getElementById("next").value=n;</script>' +
      '</body></html>';
  }
  if (mode === '令牌') {
    return '<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">' +
      '<title>' + title + ' · 开机令牌</title><style>' + css() + '</style></head><body><div class="wrap">' +
      '<form class="card login" id="f"><h1>贴一个 GitHub 开机令牌</h1>' +
      '<p>开机就是即时触发 GitHub Actions，这一步需要一个令牌；关机不用，机器自己读到标记就退出。' +
      '面板下方显示「已配令牌」时说明已经有了，不用再来。' +
      '<a href="https://github.com/settings/personal-access-tokens/new" target="_blank">在这里建令牌</a>：' +
      'Repository access 选 Only select repositories → kunge520/kun9-compute，Permissions 只勾 Actions: Read and write。' +
      '它只存在这个 Worker 里，页面永远不会把它回显出来。</p>' +
      '<input type="password" id="t" placeholder="粘贴 github_pat_…" autocomplete="off">' +
      '<button type="submit" class="pri">校验并存起来</button><div id="m" class="msg"></div></form>' +
      '<div class="foot"><a href="/">回面板</a></div></div>' +
      '<script>document.getElementById("f").onsubmit=async function(e){e.preventDefault();' +
      'var m=document.getElementById("m");m.textContent="校验中…";' +
      'var r=await fetch("/api/token",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({t:document.getElementById("t").value})});' +
      'var j=await r.json().catch(function(){return {}});m.textContent=j.ok?(j.note+"（回面板按开机，机器立刻开始启动）"):("不行："+(j.note||r.status));' +
      'if(j.ok){document.getElementById("t").value=\'\'}};</script></body></html>';
  }
  return '<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">' +
    '<title>' + title + '</title><style>' + css() + '</style></head><body><div class="wrap">' +
    '<header class="bar"><div class="brand">' + title + '</div>' +
    '<div class="seg"><button id="m-win">Windows</button><button id="m-linux">Ubuntu</button></div></header>' +
    '<div class="card">' +
    '<div class="stat"><span id="dot" class="dot"></span><span id="state" class="stat-t">读取中…</span><span id="left" class="left"></span></div>' +
    '<div id="wait" class="wait" style="display:none"><div class="wrow"><b id="ph">正在开机</b><span id="elapsed" class="mut"></span></div><div class="bar2"><i></i></div><div id="hint" class="hint"></div></div>' +
    '<div class="grid">' +
    '<div><span>桌面地址</span><b id="url">-</b></div>' +
    '<div><span>登录名</span><b id="user">-</b></div>' +
    '<div><span>到期时间</span><b id="ends">-</b></div>' +
    '<div><span>运行编号</span><b id="run">-</b></div>' +
    '<div><span>最近上报</span><b id="check">-</b></div>' +
    '</div>' +
    '<div id="ssh" class="sshline"></div>' +
    '<details class="adv"><summary>详细信息</summary><div id="note" class="note"></div></details>' +
    '</div>' +
    '<div class="acts">' +
    '<button id="brdp" class="pri">打开桌面</button>' +
    '<button id="bssh">打开终端</button>' +
    '<button id="bstart">开机</button>' +
    '<button id="bstop" class="dan">关机</button>' +
    '</div>' +
    '<div id="msg" class="msg"></div>' +
    '<footer class="foot"><span id="upd"></span><span class="links">' +
    '<a id="log" href="#" target="_blank">运行日志</a><a id="tok" href="/token">配令牌</a><a href="/logout">退出</a>' +
    '</span></footer>' +
    '</div><script>' + app() + '</script></body></html>';
}

function css() {
  return [
    '*{box-sizing:border-box}',
    ':root{--bg:#f5f6f8;--card:#fff;--line:#e2e5e9;--ink:#1c2025;--mut:#69727d;--acc:#2f6fed;--acc2:#eaf0fe;--ok:#12805c;--wait:#a8600a;--bad:#c33a3a;--shadow:0 1px 2px rgba(16,20,28,.06)}',
    'html{background:var(--bg)}',
    'body{margin:0;color:var(--ink);font:14px/1.6 -apple-system,"Segoe UI","Segoe UI Variable",Roboto,"Microsoft YaHei",system-ui,sans-serif;-webkit-font-smoothing:antialiased;background:var(--bg)}',
    '.wrap{max-width:620px;margin:0 auto;padding:28px 16px 48px}',
    '.bar{display:flex;align-items:center;gap:12px;margin-bottom:16px}',
    '.brand{font-size:15px;font-weight:600;letter-spacing:.2px}',
    '.seg{margin-left:auto;display:flex;gap:2px;padding:2px;background:#eceef1;border-radius:7px}',
    '.seg button{border:0;background:transparent;color:var(--mut);font:inherit;font-size:13px;padding:5px 12px;border-radius:5px;cursor:pointer}',
    '.seg button:hover{color:var(--ink)}',
    '.seg button.on{background:var(--card);color:var(--ink);font-weight:600;box-shadow:var(--shadow)}',
    '.card{background:var(--card);border:1px solid var(--line);border-radius:9px;padding:16px;margin-bottom:12px;box-shadow:var(--shadow)}',
    '.stat{display:flex;align-items:center;gap:9px;padding-bottom:14px;margin-bottom:14px;border-bottom:1px solid var(--line)}',
    '.stat-t{font-size:15px;font-weight:600}',
    '.dot{width:9px;height:9px;border-radius:50%;background:#c6ccd4;flex:none}',
    '.dot.on{background:var(--ok)}',
    '.dot.wait{background:var(--wait);animation:blink 1.4s ease-in-out infinite}',
    '@keyframes blink{0%,100%{opacity:1}50%{opacity:.3}}',
    '.left{margin-left:auto;font-size:13px;color:var(--mut);font-variant-numeric:tabular-nums}',
    '.left b{color:var(--ink);font-weight:600}',
    '.grid{display:grid;grid-template-columns:1fr 1fr;gap:13px 20px}',
    '.grid span{display:block;font-size:12px;color:var(--mut);margin-bottom:2px}',
    '.grid b{font-weight:500;font-size:13px;word-break:break-all;font-family:ui-monospace,"Cascadia Mono",Consolas,"DejaVu Sans Mono",monospace}',
    '.wait{margin:-4px 0 14px}',
    '.wrow{display:flex;align-items:baseline;gap:10px;margin-bottom:9px}',
    '.wrow b{font-size:13px;font-weight:600}',
    '.mut{color:var(--mut);font-size:12px;margin-left:auto}',
    '.bar2{height:3px;border-radius:3px;background:#eceef1;overflow:hidden}',
    '.bar2 i{display:block;height:100%;width:34%;border-radius:3px;background:var(--acc);animation:slide 1.8s ease-in-out infinite}',
    '@keyframes slide{0%{transform:translateX(-100%)}100%{transform:translateX(300%)}}',
    '.hint{margin-top:10px;font-size:12px;color:var(--mut);min-height:18px;transition:opacity .4s}',
    '.acts{display:grid;grid-template-columns:1fr 1fr;gap:9px;background:none;border:0;box-shadow:none;padding:0}',
    'button{font:inherit;font-size:14px;font-weight:500;padding:10px 12px;border-radius:7px;border:1px solid var(--line);background:var(--card);color:var(--ink);cursor:pointer;box-shadow:var(--shadow);transition:background .12s,border-color .12s}',
    'button:hover:not(:disabled){background:#f8f9fb;border-color:#cfd5dd}',
    'button:active:not(:disabled){background:#f0f2f5}',
    'button:disabled{opacity:.45;cursor:default;box-shadow:none;background:#fafbfc}',
    '.pri{background:var(--acc);border-color:var(--acc);color:#fff}',
    '.pri:hover:not(:disabled){background:#2a63d6;border-color:#2a63d6}',
    '.pri:active:not(:disabled){background:#2456bb}',
    '.pri:disabled{background:#a9c1ef;border-color:#a9c1ef;color:#fff}',
    '.dan{color:var(--bad)}',
    '.dan:hover:not(:disabled){background:#fdf4f4;border-color:#eecaca}',
    '.adv{margin-top:14px;padding-top:12px;border-top:1px solid var(--line)}',
    '.adv summary{font-size:12px;color:var(--mut);cursor:pointer;list-style:none}',
    '.adv summary::-webkit-details-marker{display:none}',
    '.adv summary::before{content:"› ";display:inline-block;transition:transform .12s}',
    '.adv[open] summary::before{transform:rotate(90deg)}',
    '.note{margin-top:9px;color:var(--mut);font-size:12px;line-height:1.9;word-break:break-all;font-family:ui-monospace,Consolas,monospace}',
    '.msg{min-height:20px;font-size:13px;color:var(--acc);padding:0 2px}',
    '.msg.err{color:var(--bad)}',
    '.foot{display:flex;align-items:center;gap:14px;color:var(--mut);font-size:12px;padding:2px}',
    '.foot .links{margin-left:auto;display:flex;gap:14px}',
    '.foot a{color:var(--mut);text-decoration:none}',
    '.foot a:hover{color:var(--acc)}',
    '.login{max-width:340px;margin:12vh auto 0}',
    '.login h1{font-size:16px;font-weight:600;margin:0 0 4px}',
    '.login p{color:var(--mut);font-size:12px;line-height:1.8;margin:0 0 16px}',
    '.login a{color:var(--acc)}',
    '.login input{display:block;width:100%;padding:9px 11px;margin-bottom:10px;border:1px solid var(--line);border-radius:7px;background:var(--card);color:var(--ink);font:inherit;font-size:14px}',
    '.login input:focus{outline:none;border-color:var(--acc);box-shadow:0 0 0 3px var(--acc2)}',
    '.login button{width:100%}',
    '.login .pri{margin-bottom:0}',
  ].join('');
}

function app() {
  return [
    "var $=function(i){return document.getElementById(i)};",
    "function esc(s){return (''+(s==null?'':s)).replace(/[&<>]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;'}[c]})}",
    "function fmt(t){if(!t)return '-';var d=new Date(t);return isNaN(d)?t:d.toLocaleString('zh-CN',{hour12:false})}",
    "function post(u,b){return fetch(u,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b||{})}).then(function(r){return r.json().then(function(j){return {code:r.status,j:j}})})}",
    "function say(m,bad){var e=$('msg');e.textContent=m||'';e.className='msg'+(bad?' err':'')}",
    // The box reports raw service states; the panel says one human thing about each and keeps the rest
    // inside 详细信息, which is where the exact values still show for anyone debugging a boot.
    "var DIAG={listening:'已就绪',running:'已连接','not-installed':'未安装','not-listening':'已停止','no-listener':'监听进程掉了','no-tunnel-url':'拿不到网址',up:'已接通','no-pass':'缺少口令','no-key':'缺少密钥',down:'已停止',booting:'正在启动',mounted:'已挂载',pending:'挂载中',unmounted:'挂载掉了',armed:'已就绪，等首次连接桌面','wrong-session':'挂在别的会话','no-token':'缺少谷歌盘密钥','rclone-dl-fail':'rclone 下载失败','rclone-missing':'rclone 缺失','no-fuse':'缺 fuse','winfsp-dl-fail':'磁盘驱动下载失败','mount-failed':'挂载失败'};",
    // One view, two machines. M is the selected machine and every call carries it. The SSH link is the
    // same for both boxes because they share the tunnel and the hostname; the desktop link is not --
    // Windows goes to the fixed Access RDP app, Linux to the noVNC URL it publishes each boot.
    "var M='win',VURL='';",
    "var waiting=false,wait0=0,hintI=0,hintAt=0;",
    // The wait is short but not empty, so the card talks. Plain facts about what is happening, one line
    // at a time -- and the timing numbers here are measured ones, not guesses.
    "var HINTS=[" +
    "'GitHub 分配机器一般几秒，繁忙时才会排队'," +
    "'正在装 Git 和 cloudflared，装完才连得上隧道'," +
    "'隧道握手完成后，桌面和终端就都通了'," +
    "'实测一分钟左右机器就通了，桌面再多半分钟'," +
    "'开机期间再按一次开机没有用，按钮会自己变灰'," +
    "'开机自动挂上谷歌盘，写进盘里的文件不会随关机丢'," +
    "'桌面和终端都是浏览器直连，不用装任何客户端'," +
    "'机器起来后按「打开桌面」或「打开终端」，浏览器会先让你过一次登录'," +
    "];",
    "function nextHint(){hintI=(hintI+1)%HINTS.length;$('hint').textContent=HINTS[hintI];hintAt=Date.now()}",
    "function setM(x){M=x;$('m-win').className=x==='win'?'on':'';$('m-linux').className=x==='linux'?'on':'';say('');tick();}",
    "$('m-win').onclick=function(){setM('win')};",
    "$('m-linux').onclick=function(){setM('linux')};",
    "setM('win');",
    "async function tick(){",
    " var r;try{r=await(await fetch('/api/status?m='+M,{cache:'no-store'})).json()}catch(e){say('状态读取失败，稍后自动重试',1);return}",
    " var v=r.vm||{},u=r.run||{},q=r.queue,alive=v&&v.alive,runLive=u&&u.live;",
    " var dot=$('dot'),st=$('state');",
    " var phase='';",
    " if(alive){dot.className='dot on';st.textContent='运行中'}",
    " else if(runLive){phase='boot';dot.className='dot wait';st.textContent='开机中'}",
    " else if(q&&q.action==='stop'){dot.className='dot wait';st.textContent='关机中'}",
    " else {dot.className='dot';st.textContent='已关机'}",
    " waiting=!!phase;",
    " $('wait').style.display=phase?'':'none';",
    " if(phase){$('ph').textContent='已触发，正在准备系统，还没上报';wait0=(new Date(String(u.created||'')).getTime())||0;}",
    " else $('hint').textContent='';",
    " VURL=alive?(v.url||''):'';$('url').textContent=(alive&&v.url)?v.url:'-';",
    " $('user').textContent=alive?(v.user||'-'):(M==='linux'?'root':'administrator');",
    " $('ends').textContent=fmt(v.ends);",
    " $('check').textContent=fmt(v.check);",
    " $('run').textContent=u?('#'+(u.number||'')+' '+u.status+(u.conclusion?' / '+u.conclusion:'')):'-';",
    // The hostname is real even though the machine is not, so hand over the plain ssh form too: no
    // browser involved, and it works from any terminal that can reach the tunnel.
    " $('ssh').textContent=alive?('终端：ssh '+($('user').textContent)+'@ssh.kun9.ccwu.cc'):'';",
    " var L=[];",
    " if(v.note)L.push('上报内容：'+esc(v.note));",
    " if(v.restarts)L.push('隧道重连：'+esc(v.restarts)+' 次');",
    " if(v.rdp)L.push('桌面：'+esc(DIAG[v.rdp]||v.rdp));",
    " if(v.drive)L.push('谷歌盘：'+esc(DIAG[v.drive]||v.drive));",
    " if(v.origin)L.push('终端进程：'+esc(v.origin));",
    " if(v.named)L.push('隧道：'+esc(DIAG[v.named]||v.named));",
    " if(r.error)L.push(esc(r.error));",
    " $('note').innerHTML=L.join('<br>');",
    " $('log').href=u.url||'https://github.com/kunge520/kun9-compute/actions';",
    " $('bssh').disabled=!alive;",
    " $('brdp').disabled=!alive||(M==='linux'&&!VURL);",
    " $('bstart').disabled=!!(alive||runLive);",
    " $('bstop').disabled=!(alive||runLive)&&!(q&&q.action==='stop');",
    " $('tok').textContent=r.has_token?'已配令牌':'未配令牌，开机不可用';",
    " if(v.ends&&alive){var ms=new Date(v.ends).getTime()-Date.now();$('left').innerHTML=ms>0?('剩余 <b>'+Math.floor(ms/60000)+' 分 '+String(Math.floor(ms%60000/1000)).padStart(2,'0')+' 秒</b>'):'<b>已到期</b>';}",
    " else $('left').innerHTML=alive?'':'<b>每次开机都是全新机器</b>';",
    " $('upd').textContent='更新于 '+new Date().toLocaleTimeString('zh-CN',{hour12:false});",
    "}",
    "$('bssh').onclick=function(){window.open(SSHBASE,'_blank')};",
    "$('bstart').onclick=async function(){say('正在触发开机…');var x=await post('/api/queue',{action:'start',m:M});say(x.j.note||(x.j.ok?'已触发':'开机失败：'+(x.j.note||x.code)),!x.j.ok);setTimeout(tick,1500)};",
    "$('bstop').onclick=async function(){if(!confirm('确定关机？机器上的内容会全部清空，这是每次开机的正常结局。'))return;say('正在通知机器退出…');var x=await post('/api/queue',{action:'stop',m:M});say(x.j.note||(x.j.ok?'已下发，机器自己会退出':'关机失败：'+(x.j.note||x.code)),!x.j.ok);setTimeout(tick,1500)};",
    "var SSHBASE='" + SSH_APP + "';",
    "var RDPURL='" + RDP_APP + '/rdp/' + RDP_VNET + '/' + RDP_TARGET + "/3389';",
    "$('brdp').onclick=function(){window.open(M==='linux'?VURL:RDPURL,'_blank')};",
    "setInterval(function(){",
    " if(!waiting)return;",
    " var s=wait0?Math.max(0,Math.round((Date.now()-wait0)/1000)):0;",
    " $('elapsed').textContent=wait0?('已等 '+s+' 秒'):'…';",
    " if(!$('hint').textContent){$('hint').textContent=HINTS[hintI];hintAt=Date.now();}",
    " else if(Date.now()-hintAt>5000)nextHint();",
    "},1000);",
    "async function loop(){await tick();setTimeout(loop,waiting?5000:15000)}",
    "loop();",
  ].join('\n');
}

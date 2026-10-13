
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
const TTYD = 'https://wt.kun9.ccwu.cc';
const RUNS = '/repos/' + REPO + '/actions/workflows/' + WF + '/runs?per_page=3';
const COOKIE = 'vmctl';

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
      return send(JSON.stringify({ action: q && q.action === 'stop' ? 'stop' : 'none' }), 'application/json');
    }
    if (req.method === 'POST' && url.pathname === '/api/power/clear') {
      const q = await read(env, 'power');
      if (q && q.action === 'stop') await env.STORE.delete('power');
      await env.STORE.delete('booting');
      return send(JSON.stringify({ ok: true }), 'application/json');
    }

    if (req.method === 'POST' && url.pathname === '/api/login') {
      const form = await req.formData().catch(() => null);
      const given = form ? form.get('p') : (await readJson(req)).p;
      if (!env.PANEL_KEY || String(given || '') !== String(env.PANEL_KEY)) {
        return send(page('口令不对', '登录'), 'text/html', 401);
      }
      // 302 back to the panel: a form post that answers 204 leaves the browser on a blank page,
      // and 进入 looks like it did nothing.
      return send('', 'text/plain', 302, {
        'Set-Cookie': COOKIE + '=' + await sig(env) + '; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000',
        Location: '/',
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
      if (want !== 'start' && want !== 'stop') return send(JSON.stringify({ ok: false, note: 'action 只能是 start 或 stop' }), 'application/json', 400);
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
  // it describes. The ten-second bucket only stops the edge caching it a second time -- it cannot
  // beat the origin cache, which is why status() also asks the terminal itself.
  const url = RAW + '?t=' + Math.floor(Date.now() / 10000);
  return fetch(url, { cf: { cacheTtl: force ? 0 : 10, cache: 'bypass', forceRefresh: !!force } })
    .then((r) => (r.ok ? r.json() : null))
    .catch(() => null);
}

// The named tunnel's hostname is fixed, so the terminal can be asked directly: a 401 out there
// means a ttyd is serving right now, which is all 打开终端 needs to be worth clicking. Dead or
// unconnected, Cloudflare answers 502/530 instead.
async function originLive() {
  try {
    const r = await fetch(TTYD + '/', { redirect: 'manual', cache: 'no-store', cf: { cacheTtl: 0 } });
    return r.status === 401 || r.status === 200 || r.status === 302;
  } catch (e) {
    return false;
  }
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
    // a machine; anything else is a leftover, and 打开终端 on it leads to a 530. A runner killed by
    // a cancel never writes alive:false either, so a heartbeat older than three cycles is dead too.
    const mine = !(r && r.live) || String(s.run_id || '') === String(r.live);
    // session.json also carries the sealed console password and log tails; the panel needs none of
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
      ttl_min: s.ttl_min,
      closed: s.closed || '',
    };
  }
  out.queue = await read(env, 'power');
  // While a run is still live, trust the terminal over the five-minute-old heartbeat file: the
  // machine can be serving for minutes before session.json reaches the panel, and a greyed-out
  // 打开终端 in that window reads as "ttyd 连不上".
  if (r && r.live && !(out.vm && out.vm.alive === true) && (await originLive())) {
    const v = out.vm || {};
    out.vm = {
      alive: true, url: TTYD, user: v.user || 'administrator', ends: v.ends || '', check: v.check || '',
      note: '终端已经起来了，心跳文件还在路上', named: v.named || '', run_id: r.live,
      restarts: v.restarts || 0, closed: '',
    };
  }
  return out;
}

async function sig(env) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(String(env.PANEL_KEY)), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const mac = await crypto.subtle.sign('HMAC', key, enc.encode('vmctl-v1'));
  return Array.from(new Uint8Array(mac))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function page(title, mode) {
  if (mode === '登录') {
    return '<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">' +
      '<title>' + title + '</title><style>' + css() + '</style></head><body><div class="wrap"><form class="card login" method="post" action="/api/login">' +
      '<h1>' + title + '</h1><p>网页控制台面板</p><input type="password" name="p" placeholder="面板口令" autofocus autocomplete="current-password">' +
      '<button type="submit">进入</button></form></div></body></html>';
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
    '<button id="bstart" class="ok">开机</button>' +
    '<button id="bterm" class="term">打开终端</button>' +
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
    'body{margin:0;background:#101418;color:#e6edf3;font:15px/1.6 -apple-system,"Segoe UI","Microsoft YaHei",sans-serif}',
    '.wrap{max-width:520px;margin:0 auto;padding:28px 16px 48px}',
    '.card{background:#171d24;border:1px solid #262f3a;border-radius:14px;padding:18px;margin-bottom:14px}',
    '.head{display:flex;justify-content:space-between;align-items:center}',
    'h1{font-size:19px;margin:0 0 4px}',
    '.state{color:#8b98a5;font-size:13px}',
    '.dot{width:14px;height:14px;border-radius:50%;background:#4b5563}',
    '.dot.on{background:#3fb950;box-shadow:0 0 12px #3fb950}',
    '.dot.wait{background:#d29922;box-shadow:0 0 12px #d29922;animation:pulse 1.3s ease-in-out infinite}',
    '@keyframes pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.4;transform:scale(.75)}}',
    '.grid{display:grid;grid-template-columns:1fr 1fr;gap:10px 16px}',
    '.grid span{display:block;color:#8b98a5;font-size:12px}',
    '.grid b{font-weight:600;word-break:break-all;font-size:14px}',
    '.note{margin-top:12px;color:#8b98a5;font-size:12px;word-break:break-all}',
    '.acts{display:flex;gap:10px;align-items:center}',
    'button{flex:1;padding:12px 0;border:0;border-radius:10px;font-size:15px;font-weight:600;color:#0d1117;cursor:pointer}',
    'button:disabled{opacity:.45;cursor:default}',
    '.ok{background:#3fb950}.stop{background:#f85149;color:#fff}.term{background:#58a6ff}',
    '.log{color:#8b98a5;font-size:13px;text-decoration:none;white-space:nowrap}',
    '.msg{min-height:20px;font-size:13px;color:#d29922;padding:0 4px}',
    '.phase{display:flex;gap:12px;align-items:center}',
    '.phase b{font-size:15px}',
    '.mut{color:#8b98a5;font-size:12px}',
    '.spin{width:26px;height:26px;flex:none;border-radius:50%;border:3px solid #262f3a;border-top-color:#58a6ff;animation:turn 1s linear infinite}',
    '@keyframes turn{to{transform:rotate(360deg)}}',
    '.bar{height:6px;border-radius:6px;background:#0d1117;overflow:hidden;margin:14px 0 10px}',
    '.bar i{display:block;height:100%;width:35%;border-radius:6px;background:linear-gradient(90deg,#1f6feb,#58a6ff);animation:slide 2.4s linear infinite}',
    '@keyframes slide{0%{transform:translateX(-100%)}100%{transform:translateX(380%)}}',
    '.hint{color:#8b98a5;font-size:13px;min-height:20px}',
    '.foot{display:flex;justify-content:space-between;color:#4b5563;font-size:12px;padding:0 4px}',
    '.foot a{color:#4b5563}',
    '.login input{width:100%;padding:11px;margin-bottom:10px;border:1px solid #262f3a;border-radius:10px;background:#0d1117;color:#e6edf3;font-size:15px}',
    '.login button{width:100%}',
    '.login p{color:#8b98a5;font-size:13px;margin:0 0 14px}',
  ].join('');
}

function app() {
  return [
    "var $=function(i){return document.getElementById(i)};",
    "function esc(s){return (''+(s==null?'':s)).replace(/[&<>]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;'}[c]})}",
    "function fmt(t){if(!t)return '-';var d=new Date(t);return isNaN(d)?t:d.toLocaleString('zh-CN',{hour12:false})}",
    "function post(u,b){return fetch(u,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b||{})}).then(function(r){return r.json().then(function(j){return {code:r.status,j:j}})})}",
    "function say(m){$('msg').textContent=m||''}",
    "var vu='';",
    "var HINTS=['GitHub 的免费 Windows 机器要先排队领用，这一步最慢','正在装 Git / cloudflared / ttyd','隧道在握手，第一次连会慢一点','整条链路一般是 2-4 分钟','机器起来后按「打开终端」就是 cmd','趁这个空档可以去倒杯水','开机期间再按一次开机是没用的，按钮会自己变灰','ttyd 偶尔会自己退出，脚本 20 秒内会把它拉起来，这期间网页会显示 502'];",
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
    " $('note').innerHTML=(v.note?('状态：'+esc(v.note)+(v.restarts>0?(' · 终端自愈过 '+esc(v.restarts)+' 次'):'')):'')+(r.error?('<br>'+esc(r.error)):'');",
    " if(v.url&&/^https:\\/\\//.test(v.url))vu=v.url;",
    " $('log').href=u.url||'https://github.com/kunge520/kun9-compute/actions';",
    " $('bterm').disabled=!alive;",
    " $('bstart').disabled=!!(alive||runLive||(q&&q.action==='start'));",
    " $('bstop').disabled=!(alive||runLive)&&!(q&&q.action==='stop');",
    " $('tok').textContent=r.has_token?'已配令牌（秒开机）':'配令牌（可选，秒开机）';",
    " if(v.ends){var ms=new Date(v.ends).getTime()-Date.now();$('left').textContent=ms>0?Math.floor(ms/60000)+' 分 '+Math.floor(ms%60000/1000)+' 秒':'已到期';}",
    " else $('left').textContent='-';",
    " $('upd').textContent='刷新于 '+new Date().toLocaleTimeString('zh-CN',{hour12:false});",
    "}",
    "$('bterm').onclick=function(){if(vu)window.open(vu,'_blank')};",
    "$('bstart').onclick=async function(){say('正在排队开机…');var x=await post('/api/queue',{action:'start'});say(x.j.note||(x.j.ok?'已排队':'开机失败：'+x.code));setTimeout(tick,1500)};",
    "$('bstop').onclick=async function(){if(!confirm('确定关机？这台机器上的未保存内容会丢。'))return;say('正在下发关机…');var x=await post('/api/queue',{action:'stop'});say(x.j.note||(x.j.ok?'已下发':'关机失败：'+x.code));setTimeout(tick,1500)};",
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

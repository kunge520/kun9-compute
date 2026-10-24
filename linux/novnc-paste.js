// kun9-paste.js -- gives the noVNC clipboard panel a channel that actually carries text.
// Installed by ClipPanel in linux/boot.sh into a private copy of the noVNC tree; upstream files are
// otherwise untouched, so if this fails to load the desktop still draws exactly as before.
//
// Why the stock panel is broken, measured on the live box:
//   * it sends legacy CutText built with `data[i] = text.charCodeAt(i)` -- one byte per character, over
//     its own `// FIXME: text can have values outside of Latin1/Uint8` -- and TigerVNC 1.13 implements
//     no extended clipboard (it answers nothing to SetEncodings of pseudo-encoding -239), so Chinese
//     arrives re-encoded from Latin-1, i.e. mojibake;
//   * it has no Send button: `ui.js:327` wires `change`, so the text only crosses when he clicks
//     outside the box;
//   * the one path that does carry Chinese is keysyms (Xvnc maps 0x01000000+codepoint on the fly), but
//     the field feeding it, `#noVNC_keyboardinput`, is a 1x1px off-screen textarea and its Keyboard is
//     built in addTouchSpecificHandlers() -- on a desktop browser it is neither visible nor wired,
//     because the real keyboard is `new Keyboard(this._canvas)`.
// So: stop the CutText send, and make the panel's button type the text instead.
const UNICODE_KEYSYM = 0x01000000;

function keysymOf(cp) {
  if (cp === 0x0a) return 0xff0d;                        // Return
  if (cp === 0x09) return 0xff09;                        // Tab
  return cp <= 0xff ? cp : UNICODE_KEYSYM + cp;
}

// RFB KeyEvent: [4, down, 0, 0, keysym big-endian u32] -- 8 bytes.
function keyFrame(keysym, down) {
  const f = new Uint8Array(8);
  f[0] = 4;
  f[1] = down;
  new DataView(f.buffer).setUint32(4, keysym, false);
  return f;
}

function keyFrames(text) {
  const out = [];
  for (const ch of text) {
    const cp = ch.codePointAt(0);
    if (cp === 0x0d) continue;                           // the desktop takes LF, not CR
    const keysym = keysymOf(cp);
    out.push(keyFrame(keysym, 1), keyFrame(keysym, 0));
  }
  return out;
}

function connect(url) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(url);
    ws.binaryType = 'arraybuffer';
    let buf = new Uint8Array(0);
    let state = 'greeting';
    const read32 = (o) => new DataView(buf.buffer, buf.byteOffset, buf.length).getUint32(o, false);
    const fail = (msg) => { try { ws.close(); } catch (e) {} reject(new Error(msg)); };

    ws.onopen = () => ws.send(new TextEncoder().encode('RFB 003.008\n'));
    ws.onerror = () => fail('连不上桌面');
    // Without this a server that hangs up mid-handshake leaves the promise pending forever, which is
    // exactly what a 12-byte version line did the first time this was tested.
    ws.onclose = () => fail('桌面挂断了连接');
    ws.onmessage = (ev) => {
      const add = new Uint8Array(ev.data);
      const joined = new Uint8Array(buf.length + add.length);
      joined.set(buf);
      joined.set(add, buf.length);
      buf = joined;
      for (;;) {
        if (state === 'greeting') {
          if (buf.length < 12) return;                   // "RFB 003.008\n"
          buf = buf.subarray(12);
          state = 'types';
        } else if (state === 'types') {
          if (buf.length < 1) return;
          const n = buf[0];
          if (buf.length < 1 + n) return;
          if (!buf.subarray(1, 1 + n).includes(1)) return fail('桌面开了密码，这个通道只支持免认证');
          buf = buf.subarray(1 + n);
          ws.send(new Uint8Array([1]));                  // security type: None
          state = 'auth';
        } else if (state === 'auth') {
          if (buf.length < 4) return;
          const code = read32(0);
          buf = buf.subarray(4);
          if (code !== 0) return fail('认证被拒');
          ws.send(new Uint8Array([1]));                  // ClientInit: shared
          state = 'serverinit';
        } else if (state === 'serverinit') {
          if (buf.length < 24) return;
          const nameLen = read32(20);
          if (buf.length < 24 + nameLen) return;
          buf = buf.subarray(24 + nameLen);
          state = 'ready';
          return resolve(ws);
        } else {
          return;                                        // ready: whatever the server sends is pixels
        }
      }
    };
  });
}

// Four characters per frame with a gap: Xvnc binds a spare keycode as it handles each unknown unicode
// keysym, so the frames have to arrive in the order the mappings are made.
export async function typeText(text, url) {
  const ws = await connect(url);
  const frames = keyFrames(text);
  for (let i = 0; i < frames.length; i += 8) {
    const len = Math.min(8, frames.length - i);
    const batch = new Uint8Array(len * 8);
    for (let k = 0; k < len; k++) batch.set(frames[i + k], k * 8);
    ws.send(batch);
    if (i + len < frames.length) await new Promise((r) => setTimeout(r, 20));
  }
  await new Promise((r) => setTimeout(r, 60));
  ws.close();
  return frames.length / 2;
}

if (typeof document !== 'undefined') {
  const panel = document.getElementById('noVNC_clipboard');
  const ta = document.getElementById('noVNC_clipboard_text');
  const wsurl = (location.protocol === 'https:' ? 'wss://' : 'ws://')
    + location.host + new URL('websockify', location.href).pathname;

  if (panel && ta) {
    // Capture phase, so the stock `change` listener on the textarea never runs: the CutText path is
    // gone, not shadowed. Receiving from the desktop still fills the box (that is a value assignment).
    panel.addEventListener('change', (e) => {
      if (e.target === ta) { e.stopPropagation(); e.preventDefault(); }
    }, true);

    ta.placeholder = '把要送进桌面的文字贴在这里（中文可以）';

    // Chrome offers "translate this page" on noVNC because the stock UI is English, and its engine then
    // rewrites our own Chinese ("已送入 10 个字符" came back as "送入 10 个角色已"). Opt these nodes out.
    const noTranslate = (el) => { el.setAttribute('translate', 'no'); return el; };
    const hint = noTranslate(document.createElement('div'));
    hint.style.cssText = 'margin-top:6px;color:#bbb;font-size:12px';
    hint.textContent = '先在桌面里把光标点到要输入的位置，再按送入。';
    const status = noTranslate(document.createElement('div'));
    status.style.cssText = 'margin-top:4px;color:#bbb;font-size:12px';

    const send = noTranslate(document.createElement('input'));
    send.type = 'button';
    send.value = '送入桌面';
    send.className = 'noVNC_submit';
    send.style.cssText = 'margin-left:8px';
    // An ASCII marker, so a health check or a headless dump can prove this branch ran without having to
    // carry Chinese through a channel that eats non-ASCII bytes.
    send.setAttribute('data-kun9', 'paste');
    panel.append(send, status, hint);

    const run = async () => {
      const text = ta.value;
      if (!text) { status.textContent = '框里还没有内容'; return; }
      status.textContent = '正在送入…';
      try {
        const n = await typeText(text, wsurl);
        ta.value = '';
        status.textContent = '已送入 ' + n + ' 个字符';
      } catch (err) {
        status.textContent = '失败：' + err.message;
      }
    };
    send.addEventListener('click', run);
    ta.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) { e.preventDefault(); run(); }
    });
  }
}

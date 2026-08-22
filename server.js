'use strict';
const http = require('node:http');
const net = require('node:net');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const QRCode = require('qrcode');

const PORT = Number(process.env.PORT) || 3000;
const PASS = process.env.PANEL_PASS || '';
const DATA_DIR = process.env.DATA_DIR || process.cwd();
const STORE = path.join(DATA_DIR, 'state.json');

const sha = (s) => crypto.createHash('sha256').update(s).digest();
const PANEL = '/app/' + sha('sid:' + PASS).toString('hex').slice(0, 24);
const GATE = '/api/m/' + sha('sid:' + PASS + '|gate').toString('hex').slice(0, 24);
const SALT = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

let db = { users: [] };
try { db = JSON.parse(fs.readFileSync(STORE, 'utf8')); } catch {}
if (!Array.isArray(db.users)) db.users = [];

let saveTimer = null;
function persist() {
  if (saveTimer) return;
  saveTimer = setTimeout(() => {
    saveTimer = null;
    try {
      fs.mkdirSync(DATA_DIR, { recursive: true });
      fs.writeFileSync(STORE, JSON.stringify(db));
    } catch {}
  }, 500);
}

const UNITS = { MB: 1048576, GB: 1073741824, TB: 1099511627776 };
const rnd = (n) => crypto.randomBytes(n).toString('hex');
const activeUser = (u) =>
  !u.off &&
  (!u.maxBytes || u.up + u.down < u.maxBytes) &&
  (!u.maxDays || Date.now() - u.created < u.maxDays * 86400000);

const KEY = sha('sid:' + PASS);
const mac = (t) => crypto.createHmac('sha256', KEY).update(t).digest('hex').slice(0, 32);
const newSid = () => { const t = Date.now().toString(36); return t + '.' + mac(t); };
function goodSid(s) {
  if (!s) return false;
  const i = s.indexOf('.');
  if (i < 1) return false;
  const t = s.slice(0, i);
  const n = parseInt(t, 36);
  return mac(t) === s.slice(i + 1) && Date.now() - n < 432e5;
}
function cookieGet(req, k) {
  const c = req.headers.cookie || '';
  for (const part of c.split(';')) {
    const idx = part.indexOf('=');
    if (idx < 0) continue;
    if (part.slice(0, idx).trim() === k) return part.slice(idx + 1).trim();
  }
  return '';
}

const send = (res, code, head, body) => { res.writeHead(code, head); res.end(body); };
const json = (res, code, obj) => send(res, code, { 'content-type': 'application/json' }, JSON.stringify(obj));

function readBody(req, cap) {
  return new Promise((ok, bad) => {
    const parts = [];
    let n = 0;
    req.on('data', (c) => {
      n += c.length;
      if (n > (cap || 1048576)) { bad(new Error('big')); req.destroy(); }
      else parts.push(c);
    });
    req.on('end', () => ok(Buffer.concat(parts)));
    req.on('error', bad);
  });
}

function linksFor(x, host) {
  const g = encodeURIComponent(GATE);
  const c = 'encryption=none&security=tls&sni=' + host + '&fp=chrome&alpn=h2%2Chttp%2F1.1&host=' + host;
  return [
    'vless://' + x.uuid + '@' + host + ':443?' + c.replace('&alpn=h2%2Chttp%2F1.1', '') + '&type=ws&path=' + g + '#' + encodeURIComponent(x.name),
    'vless://' + x.uuid + '@' + host + ':443?' + c + '&type=xhttp&path=' + g + '&mode=auto#' + encodeURIComponent(x.name)
  ];
}

const server = http.createServer((req, res) => {
  handle(req, res).catch(() => { try { send(res, 500, {}, ''); } catch {} });
});

async function handle(req, res) {
  const u = new URL(req.url, 'http://x');
  const p = u.pathname;

  if (p === '/') {
    return send(res, 200,
      { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'public, max-age=3600' },
      '<!doctype html><html><head><title>Welcome</title></head><body><h1>Welcome</h1><p>Everything is running smoothly.</p></body></html>');
  }

  if (p === GATE || p.startsWith(GATE + '/')) {
    return xhttpHandler(req, res, p);
  }

  if (p.startsWith('/api/')) return api(req, res, p);

  if (p === PANEL) {
    return send(res, 200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' }, panel());
  }

  if (p.startsWith('/sub/')) return subPage(req, res, u);

  return send(res, 404, {}, '');
}

async function api(req, res, p) {
  if (p === '/api/login') {
    const b = JSON.parse((await readBody(req)).toString() || '{}');
    const a = sha(String(b.pass || ''));
    const e = sha(PASS);
    if (!PASS.length || !crypto.timingSafeEqual(a, e)) return json(res, 401, { e: 'bad' });
    res.setHeader('set-cookie', 'sid=' + newSid() + '; HttpOnly; Path=/; SameSite=Lax; Max-Age=43200');
    return json(res, 200, { ok: 1 });
  }

  if (p === '/api/logout') {
    res.setHeader('set-cookie', 'sid=; HttpOnly; Path=/; Max-Age=0');
    return json(res, 200, { ok: 1 });
  }

  if (!goodSid(cookieGet(req, 'sid'))) return json(res, 401, { e: 'auth' });

  if (req.method === 'GET' && p === '/api/state') {
    return json(res, 200, {
      users: db.users,
      gate: GATE,
      host: (req.headers.host || '').split(':')[0]
    });
  }

  if (req.method === 'POST' && p === '/api/create') {
    const b = JSON.parse((await readBody(req)).toString() || '{}');
    const unit = UNITS[b.unit] || 0;
    db.users.push({
      id: rnd(6),
      name: String(b.name || 'user').slice(0, 24),
      uuid: crypto.randomUUID(),
      sub: rnd(10),
      created: Date.now(),
      maxBytes: Math.round(Number(b.val) || 0) * unit,
      maxDays: Math.round(Number(b.days) || 0),
      up: 0,
      down: 0,
      off: false
    });
    persist();
    return json(res, 200, { ok: 1 });
  }

  const m = p.match(/^\/api\/(reset|remove|toggle)$/);
  if (req.method === 'POST' && m) {
    const b = JSON.parse((await readBody(req)).toString() || '{}');
    if (m[1] === 'remove') {
      db.users = db.users.filter((x) => x.id !== b.id);
    } else {
      const usr = db.users.find((x) => x.id === b.id);
      if (!usr) return json(res, 404, { e: 'nf' });
      if (m[1] === 'reset') { usr.up = 0; usr.down = 0; }
      if (m[1] === 'toggle') usr.off = !usr.off;
    }
    persist();
    return json(res, 200, { ok: 1 });
  }

  if (req.method === 'GET' && p === '/api/qr') {
    const t = new URL(req.url, 'http://x').searchParams.get('t') || '';
    const svg = await QRCode.toString(t, { type: 'svg', margin: 1, color: { dark: '#101828', light: '#ffffff' } });
    return send(res, 200, { 'content-type': 'image/svg+xml' }, svg);
  }

  return json(res, 404, { e: 'nf' });
}

async function subPage(req, res, u) {
  const tok = u.pathname.slice(5);
  const host = (req.headers.host || '').split(':')[0];
  const usr = db.users.find((x) => x.sub === tok);
  if (!usr) return send(res, 404, { 'content-type': 'text/plain' }, 'not found');

  const links = linksFor(usr, host);
  const accept = req.headers.accept || '';

  if (u.searchParams.get('raw') === '1') {
    return send(res, 200, { 'content-type': 'text/plain; charset=utf-8' }, links.join('\n'));
  }
  if (!accept.includes('text/html') || !activeUser(usr)) {
    if (!activeUser(usr)) return send(res, 404, { 'content-type': 'text/plain' }, 'not found');
    return send(res, 200, { 'content-type': 'text/plain; charset=utf-8' },
      Buffer.from(links.join('\n'), 'utf8').toString('base64'));
  }

  const svgs = [];
  for (const l of links) {
    svgs.push(await QRCode.toString(l, { type: 'svg', margin: 1, color: { dark: '#e8ecf8', light: '#ffffff' } }));
  }
  const used = usr.up + usr.down;
  const st = activeUser(usr) ? 'Active' : 'Disabled';
  const body = '<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>' +
    esc(usr.name) + '</title><style>*{margin:0;padding:0;box-sizing:border-box;font-family:Segoe UI,system-ui,sans-serif}' +
    'body{min-height:100vh;background:#0b1020;color:#e8ecf8;display:flex;align-items:center;justify-content:center;padding:20px}' +
    '.glass{background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.12);border-radius:22px;padding:26px;max-width:520px;width:100%;backdrop-filter:blur(16px)}' +
    'h1{font-size:20px;background:linear-gradient(90deg,#22d3ee,#a78bfa);-webkit-background-clip:text;background-clip:text;color:transparent}' +
    '.mut{color:#93a1c4;font-size:13px;margin-top:4px}' +
    '.qrs{display:flex;gap:18px;flex-wrap:wrap;justify-content:center;margin-top:18px}' +
    '.qr{text-align:center}.qr svg{width:190px;height:190px;background:#fff;border-radius:14px;padding:8px}' +
    '.lbl{font-size:12px;color:#9fb0d8;margin-bottom:6px}' +
    'textarea{width:100%;background:rgba(255,255,255,.07);border:1px solid rgba(255,255,255,.14);border-radius:12px;color:#9fd6e8;font-family:Consolas,monospace;font-size:11px;padding:10px;margin-top:14px;height:74px}' +
    '</style></head><body><div class="glass">' +
    '<h1>' + esc(usr.name) + '</h1><div class="mut">status: ' + st + ' · used ' + fmtMB(used) +
    (usr.maxBytes ? ' / ' + fmtMB(usr.maxBytes) : '') + '</div>' +
    '<div class="qrs"><div class="qr"><div class="lbl">WebSocket</div>' + svgs[0] + '</div>' +
    '<div class="qr"><div class="lbl">XHTTP</div>' + svgs[1] + '</div></div>' +
    '<textarea readonly onclick="this.select()">' + esc(links.join('\n')) + '</textarea>' +
    '<div class="mut" style="margin-top:8px">tap the box to select all, then import in your client</div>' +
    '</div></body></html>';
  return send(res, 200, { 'content-type': 'text/html; charset=utf-8' }, body);
}

const fmtMB = (n) => {
  if (!n) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (n >= 1024 && i < 4) { n /= 1024; i++; }
  return n.toFixed(n >= 100 || i === 0 ? 0 : 1) + ' ' + units[i];
};
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

// ---------- XHTTP (packet-up) ----------

const sessions = new Map();
setInterval(() => {
  const now = Date.now();
  for (const [k, s] of sessions) {
    if (now - s.last > 300000) killSession(s);
  }
}, 60000).unref();

function killSession(s) {
  sessions.delete(s.sid);
  if (s.up) { try { s.up.destroy(); } catch {} s.up = null; }
  if (s.res && !s.done) { s.done = true; try { s.res.end(); } catch {} }
  persist();
}

function writeDown(s, chunk) {
  if (s.res && !s.done) {
    try { s.res.write(chunk); return; } catch {}
  }
  s.backlog.push(chunk);
}

function billUp(s, n) {
  if (!s.usr) return;
  s.usr.up += n;
  if (s.usr.maxBytes && s.usr.up + s.usr.down >= s.usr.maxBytes) killSession(s);
}

function billDown(s, n) {
  if (!s.usr) return;
  s.usr.down += n;
  writeDown(s, null);
  if (s.usr.maxBytes && s.usr.up + s.usr.down >= s.usr.maxBytes) killSession(s);
}

function xhttpHandler(req, res, p) {
  const sid = p.slice(GATE.length + 1);
  if (!sid || sid.length > 80 || !/^[A-Za-z0-9_-]+$/.test(sid)) return send(res, 404, {}, '');

  let s = sessions.get(sid);
  if (!s) {
    s = { sid, head: Buffer.alloc(0), extra: [], backlog: [], armed: false, up: null, res: null, done: true, usr: null, dest: null, last: Date.now(), ver: 0 };
    sessions.set(sid, s);
  }
  s.last = Date.now();

  if (req.method === 'GET') {
    if (s.res && !s.done) return send(res, 409, {}, '');
    s.res = res;
    s.done = false;
    res.writeHead(200, {
      'content-type': 'application/octet-stream',
      'cache-control': 'no-store',
      'x-accel-buffering': 'no'
    });
    if (res.flushHeaders) res.flushHeaders();
    res.on('close', () => { if (s.res === res) { s.done = true; } });
    if (s.up) {
      writeDown(s, Buffer.from([s.ver, 0]));
      const b = s.backlog.splice(0);
      for (const c of b) writeDown(s, c);
    }
    return;
  }

  if (req.method === 'POST') {
    readBody(req, 20971520).then((body) => {
      if (!body.length) return send(res, 200, {}, '');
      if (s.up) {
        try { s.up.write(body); } catch {}
        billUp(s, body.length);
        return send(res, 200, {}, '');
      }
      s.head = Buffer.concat([s.head, body]);
      engage(s);
      if (s.armed && s.up) return send(res, 200, {}, '');
      if (s.head === null || s.dead) return send(res, 403, {}, '');
      s.pending = (s.pending || 0) + 1;
      const check = () => {
        if (s.armed || s.dead) {
          s.pending--;
          return send(res, s.dead ? 403 : 200, {}, '');
        }
        setTimeout(check, 50);
      };
      check();
    }).catch(() => { try { res.destroy(); } catch {} });
    return;
  }

  send(res, 405, {}, '');
}

function parseTarget(head) {
  if (head.length < 25) return { need: true };
  const ver = head[0];
  if (ver !== 0) return { bad: true };
  const hex = head.subarray(1, 17).toString('hex');
  const usr = db.users.find((x) => x.uuid.replace(/-/g, '').toLowerCase() === hex);
  if (!usr || !activeUser(usr)) return { bad: true };
  const pad = head[17];
  if (head.length < pad + 23) return { need: true };
  const act = head[18 + pad];
  if (act !== 1) return { bad: true };
  const port = head.readUInt16BE(19 + pad);
  const kind = head[21 + pad];
  let dest;
  let at = 22 + pad;
  if (kind === 1) {
    if (head.length < at + 4) return { need: true };
    dest = head.subarray(at, at + 4).join('.');
    at += 4;
  } else if (kind === 2) {
    const n = head[at];
    if (head.length < at + 1 + n) return { need: true };
    dest = head.subarray(at + 1, at + 1 + n).toString('utf8');
    at += 1 + n;
  } else if (kind === 3) {
    if (head.length < at + 16) return { need: true };
    const seg = [];
    for (let i = 0; i < 16; i += 2) seg.push(head.readUInt16BE(at + i).toString(16));
    dest = seg.join(':');
    at += 16;
  } else return { bad: true };
  if (!dest || !port) return { bad: true };
  return { ver, usr, port, dest, at };
}

function engage(s) {
  const t = parseTarget(s.head);
  if (t.need) return;
  if (t.bad) { s.dead = true; return; }
  s.usr = t.usr;
  s.ver = t.ver;
  s.dest = t.dest + ':' + t.port;

  s.up = net.createConnection({ host: t.dest, port: t.port });
  s.up.setNoDelay(true);
  s.up.on('connect', () => {
    s.armed = true;
    const tail = s.head.subarray(t.at);
    s.head = null;
    try { s.up.write(tail); } catch {}
    billUp(s, tail.length);
    writeDown(s, Buffer.from([s.ver, 0]));
    const bl = s.backlog.splice(0);
    for (const c of bl) writeDown(s, c);
  });
  s.up.on('data', (piece) => {
    if (s.usr) s.usr.down += piece.length;
    writeDown(s, piece);
    if (s.usr && s.usr.maxBytes && s.usr.up + s.usr.down >= s.usr.maxBytes) killSession(s);
  });
  s.up.on('error', () => killSession(s));
  s.up.on('close', () => killSession(s));
}

// ---------- WebSocket relay ----------

server.on('upgrade', (req, socket) => {
  if ((req.url || '').split('?')[0] !== GATE) return socket.destroy();
  const nonce = req.headers['sec-websocket-key'];
  if (!nonce) return socket.destroy();
  const tag = (req.headers['sec-websocket-protocol'] || '').split(',')[0].trim();
  const stamp = crypto.createHash('sha1').update(nonce + SALT).digest('base64');
  socket.write(
    'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ' +
    stamp + '\r\n' + (tag ? 'Sec-WebSocket-Protocol: ' + tag + '\r\n' : '') + '\r\n'
  );
  let prelude = Buffer.alloc(0);
  try { prelude = Buffer.from(tag, 'base64'); } catch {}
  wsAttach(socket, prelude);
});

function wsAttach(socket, first) {
  let wire = Buffer.from(first);
  let head = Buffer.alloc(0);
  let extra = [];
  let up = null;
  let armed = false;
  let live = true;
  let usr = null;

  const stop = () => {
    if (!live) return;
    live = false;
    persist();
    if (up) { up.destroy(); up = null; }
    try { socket.end(); } catch {}
    try { socket.destroy(); } catch {}
  };

  const push = (op, body) => {
    if (!live) return;
    const n = body.length;
    let cap;
    if (n < 126) { cap = Buffer.allocUnsafe(2); cap[0] = 128 | op; cap[1] = n; }
    else if (n < 65536) { cap = Buffer.allocUnsafe(4); cap[0] = 128 | op; cap[1] = 126; cap.writeUInt16BE(n, 2); }
    else { cap = Buffer.allocUnsafe(10); cap[0] = 128 | op; cap[1] = 127; cap.writeBigUInt64BE(BigInt(n), 2); }
    try { socket.write(Buffer.concat([cap, body])); } catch {}
  };

  socket.on('error', stop);
  socket.on('close', stop);

  socket.on('data', (chunk) => {
    wire = Buffer.concat([wire, chunk]);
    for (;;) {
      if (!live) return;
      if (wire.length < 2) return;
      const op = wire[0] & 15;
      let span = wire[1] & 127;
      let cut = 2;
      if (span === 126) { if (wire.length < 4) return; span = wire.readUInt16BE(2); cut = 4; }
      else if (span === 127) { if (wire.length < 10) return; span = Number(wire.readBigUInt64BE(2)); cut = 10; }
      let veil = null;
      if (wire[1] & 128) {
        if (wire.length < cut + 4) return;
        veil = wire.subarray(cut, cut + 4);
        cut += 4;
      }
      if (wire.length < cut + span) return;
      let body = wire.subarray(cut, cut + span);
      if (veil) {
        body = Buffer.from(body);
        for (let i = 0; i < body.length; i++) body[i] ^= veil[i & 3];
      }
      wire = wire.subarray(cut + span);
      if (op === 8) { push(8, Buffer.alloc(0)); return stop(); }
      if (op === 9) { push(10, body); continue; }
      if (op === 10) continue;
      if (up) {
        try { up.write(body); } catch {}
        if (usr) {
          usr.up += body.length;
          if (usr.maxBytes && usr.up + usr.down >= usr.maxBytes) return stop();
        }
        continue;
      }
      if (armed) { extra.push(body); continue; }
      head = Buffer.concat([head, body]);
      engageWs();
    }
  });

  function engageWs() {
    const t = parseTarget(head);
    if (t.need) return;
    if (t.bad) return stop();
    usr = t.usr;
    armed = true;
    up = net.createConnection({ host: t.dest, port: t.port });
    up.setNoDelay(true);
    up.on('connect', () => {
      push(2, Buffer.from([t.ver, 0]));
      const tail = head.subarray(t.at);
      head = null;
      if (tail.length) {
        try { up.write(tail); } catch {}
        usr.up += tail.length;
        if (usr.maxBytes && usr.up + usr.down >= usr.maxBytes) return stop();
      }
      while (extra.length) { try { up.write(extra.shift()); } catch {} }
    });
    up.on('data', (piece) => {
      usr.down += piece.length;
      push(2, piece);
      if (usr.maxBytes && usr.up + usr.down >= usr.maxBytes) return stop();
    });
    up.on('error', stop);
    up.on('close', stop);
  }
}

server.listen(PORT, '0.0.0.0');

// ---------- panel ----------

function panel() {
  return `<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Console</title>
<style>
*{margin:0;padding:0;box-sizing:border-box;font-family:'Segoe UI',system-ui,sans-serif}
body{min-height:100vh;background:#0b1020;color:#e8ecf8}
body:before{content:"";position:fixed;width:520px;height:520px;border-radius:50%;background:radial-gradient(circle,#7c3aed55,transparent 70%);top:-140px;left:-120px}
body:after{content:"";position:fixed;width:620px;height:620px;border-radius:50%;background:radial-gradient(circle,#06b6d444,transparent 70%);bottom:-200px;right:-160px;z-index:0}
.wrap{position:relative;z-index:1;max-width:980px;margin:0 auto;padding:28px 18px 80px}
.glass{background:rgba(255,255,255,.055);border:1px solid rgba(255,255,255,.12);border-radius:20px;backdrop-filter:blur(18px);box-shadow:0 18px 50px rgba(0,0,0,.35)}
.pad{padding:22px}
h1{font-size:22px;background:linear-gradient(90deg,#22d3ee,#a78bfa);-webkit-background-clip:text;background-clip:text;color:transparent;display:inline-block}
input,select{background:rgba(255,255,255,.07);border:1px solid rgba(255,255,255,.14);border-radius:12px;padding:10px 13px;color:#eef2ff;outline:none;font-size:14px;width:100%}
option{background:#131a33}
button{cursor:pointer;border:none;border-radius:12px;padding:10px 15px;font-size:13.5px;font-weight:600;color:#04121f;background:linear-gradient(90deg,#22d3ee,#60a5fa)}
button:hover{filter:brightness(1.12);transform:translateY(-1px)}
button.ghost{background:rgba(255,255,255,.08);color:#dfe7ff;border:1px solid rgba(255,255,255,.16)}
button.danger{background:linear-gradient(90deg,#f472b6,#fb7185);color:#2a0410}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(270px,1fr));gap:16px}
.chip{font-size:11.5px;padding:3px 10px;border-radius:99px;font-weight:700}
.okc{background:rgba(34,197,94,.16);color:#4ade80}.warnc{background:rgba(251,191,36,.16);color:#fbbf24}.badc{background:rgba(244,63,94,.16);color:#fb7185}.offc{background:rgba(148,163,184,.16);color:#94a3b8}
.bar{height:7px;border-radius:99px;background:rgba(255,255,255,.09);overflow:hidden;margin-top:9px}
.bar>i{display:block;height:100%;background:linear-gradient(90deg,#22d3ee,#a78bfa)}
.mut{color:#93a1c4;font-size:12.5px}
.stats{display:flex;gap:14px;flex-wrap:wrap;margin-bottom:18px}
.stat{flex:1;min-width:130px;text-align:center;padding:15px 10px}
.stat b{font-size:23px;background:linear-gradient(90deg,#e2e8f0,#9adcf0);-webkit-background-clip:text;background-clip:text;color:transparent}
#login{max-width:360px;margin:14vh auto 0;text-align:center}
#login input{margin:16px 0 12px;text-align:center}
#modal{position:fixed;inset:0;background:rgba(5,8,20,.72);backdrop-filter:blur(6px);display:none;align-items:center;justify-content:center;z-index:9}
#modal .glass{max-width:min(480px,92vw);text-align:center}
#qa,#qb,#qc{width:min(180px,54vw);background:#fff;border-radius:14px;padding:8px}
.toast{position:fixed;bottom:24px;left:50%;transform:translateX(-50%) translateY(80px);opacity:0;transition:.25s;background:rgba(20,30,60,.92);border:1px solid rgba(255,255,255,.18);padding:10px 22px;border-radius:99px;font-size:13px;z-index:99}
.toast.on{transform:translateX(-50%) translateY(0);opacity:1}
</style></head><body><div class="wrap">

<div id="login" class="glass pad" style="display:none">
<h1>Console</h1><p class="mut" style="margin-top:6px">restricted area</p>
<input id="pass" type="password" placeholder="password">
<button style="width:100%" id="go">Enter</button>
</div>

<div id="app" style="display:none">
<div class="row" style="justify-content:space-between;margin-bottom:18px"><h1>Console</h1><button class="ghost" id="out">Logout</button></div>

<div class="stats">
<div class="glass stat"><b id="st-u">0</b><div class="mut">users</div></div>
<div class="glass stat"><b id="st-a">0</b><div class="mut">active</div></div>
<div class="glass stat"><b id="st-t">0 B</b><div class="mut">traffic</div></div>
</div>

<div class="glass pad" style="margin-bottom:18px"><b>New user</b>
<div class="row" style="margin-top:12px">
<input id="nn" placeholder="name" style="flex:2;min-width:130px">
<input id="nv" type="number" min="0" placeholder="amount" style="flex:1;min-width:90px">
<select id="nu" style="flex:1;min-width:84px"><option>MB</option><option selected>GB</option><option>TB</option></select>
<input id="nd" type="number" min="0" placeholder="days" style="flex:1;min-width:80px">
<button id="add">Add</button></div>
<p class="mut" style="margin-top:7px">empty amount or 0 days = unlimited · every user gets WS + XHTTP links</p></div>

<div id="cards" class="grid"></div>
</div>

<div id="modal"><div class="glass pad">
<img id="qa" alt=""><div class="mut" style="margin:8px 0 14px">websocket link</div>
<img id="qb" alt=""><div class="mut" style="margin:8px 0 14px">xhttp link</div>
<img id="qc" alt=""><div class="mut" style="margin:8px 0 12px">subscription</div>
<button class="ghost" id="mclose">Close</button></div></div>

</div><div class="toast" id="toast"></div>

<script>
var D=null;
function $(i){return document.getElementById(i)}
function el(t,c,x){var e=document.createElement(t);if(c)e.className=c;if(x!==undefined)e.textContent=x;return e}
function toast(m){var t=$('toast');t.textContent=m;t.classList.add('on');setTimeout(function(){t.classList.remove('on')},1500)}
function fmt(n){if(!n)return'0 B';var u=['B','KB','MB','GB','TB'];var i=0;while(n>=1024&&i<4){n/=1024;i++}return n.toFixed(n>=100||i===0?0:1)+' '+u[i]}
function cp(t){if(navigator.clipboard){navigator.clipboard.writeText(t).then(function(){toast('copied')},function(){toast('copy failed')})}else toast('copy failed')}
function api(m,p,b){return fetch(p,{method:m,headers:{'content-type':'application/json'},body:b===undefined?undefined:JSON.stringify(b)}).then(function(r){if(r.status===401&&p!=='/api/login'){showLogin();throw new Error('auth')}return r.json()})}
function showLogin(){$('login').style.display='block';$('app').style.display='none'}
function boot(){$('login').style.display='none';$('app').style.display='block'}
function login(){api('POST','/api/login',{pass:$('pass').value}).then(function(r){if(r.ok)load();else toast('wrong password')}).catch(function(){})}
function logout(){api('POST','/api/logout',{}).then(showLogin).catch(function(){})}
function load(){api('GET','/api/state').then(function(d){D=d;boot();render()}).catch(function(){})}
function statusOf(u){if(u.off)return['offc','Disabled'];var used=u.up+u.down;if(u.maxBytes&&used>=u.maxBytes)return['warnc','Limit'];if(u.maxDays&&(Date.now()-u.created)>=u.maxDays*86400000)return['badc','Expired'];return['okc','Active']}
function linkOf(u,t){var g=encodeURIComponent(D.gate);var h=D.host;var a='&alpn=h2%2Chttp%2F1.1';if(t==='ws')a='';var c='encryption=none&security=tls&sni='+h+'&fp=chrome'+a+'&host='+h;return 'vless://'+u.uuid+'@'+h+':443?'+c+'&type='+t+'&path='+g+(t==='xhttp'?'&mode=auto':'')+'#'+encodeURIComponent(u.name)}
function subOf(u){return location.origin+'/sub/'+u.sub}
function act(m,id){api('POST','/api/'+m,{id:id}).then(load).catch(function(){})}
function create(){api('POST','/api/create',{name:$('nn').value,val:Number($('nv').value)||0,unit:$('nu').value,days:Number($('nd').value)||0}).then(function(r){if(r.ok){$('nn').value='';$('nv').value='';$('nd').value='';toast('user added');load()}}).catch(function(){})}
function card(u){
 var st=statusOf(u);
 var used=u.up+u.down;
 var c=el('div','glass pad');
 var top=el('div','row');
 top.style.justifyContent='space-between';
 top.appendChild(el('b',null,u.name));
 top.appendChild(el('span','chip '+st[0],st[1]));
 c.appendChild(top);
 c.appendChild(el('div','mut',fmt(u.up)+' up · '+fmt(u.down)+' down · '+(u.maxBytes?'limit '+fmt(u.maxBytes):'unlimited')));
 var bar=el('div','bar');var fill=el('i');fill.style.width=(u.maxBytes?Math.min(100,used/u.maxBytes*100):0)+'%';bar.appendChild(fill);
 c.appendChild(bar);
 c.appendChild(el('div','mut','days left: '+(u.maxDays?String(Math.max(0,u.maxDays-Math.floor((Date.now()-u.created)/864e5))):'unlimited')));
 var r1=el('div','row');r1.style.marginTop='13px';
 function b(label,fn){var x=el('button','ghost',label);x.addEventListener('click',fn);r1.appendChild(x);return x}
 b('Link',function(){cp(linkOf(u,'ws'))});
 b('XHTTP',function(){cp(linkOf(u,'xhttp'))});
 b('Sub',function(){cp(subOf(u))});
 b('QR',function(){
   $('qa').src='/api/qr?t='+encodeURIComponent(linkOf(u,'ws'));
   $('qb').src='/api/qr?t='+encodeURIComponent(linkOf(u,'xhttp'));
   $('qc').src='/api/qr?t='+encodeURIComponent(subOf(u));
   $('modal').style.display='flex';
 });
 var r2=el('div','row');r2.style.marginTop='9px';
 function b2(label,cls,fn){var x=el('button',cls,label);x.addEventListener('click',fn);r2.appendChild(x);return x}
 b2('Reset','ghost',function(){act('reset',u.id)});
 b2(u.off?'Enable':'Disable','ghost',function(){act('toggle',u.id)});
 b2('Delete','danger',function(){act('remove',u.id)});
 c.appendChild(r1);
 c.appendChild(r2);
 return c;
}
function render(){
 var actN=0,tot=0;
 D.users.forEach(function(u){tot+=u.up+u.down;if(statusOf(u)[0]==='okc')actN++});
 $('st-u').textContent=String(D.users.length);
 $('st-a').textContent=String(actN);
 $('st-t').textContent=fmt(tot);
 var box=$('cards');box.innerHTML='';
 D.users.forEach(function(u){box.appendChild(card(u))});
}
window.addEventListener('load',function(){
 $('go').addEventListener('click',login);
 $('pass').addEventListener('keydown',function(e){if(e.key==='Enter')login()});
 $('out').addEventListener('click',logout);
 $('add').addEventListener('click',create);
 $('mclose').addEventListener('click',function(){$('modal').style.display='none'});
 $('modal').addEventListener('click',function(e){if(e.target===$('modal'))$('modal').style.display='none'});
 api('GET','/api/state').then(function(d){D=d;render();boot()}).catch(function(){showLogin()});
});
</script></body></html>`;
}

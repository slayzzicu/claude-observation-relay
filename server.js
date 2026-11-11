'use strict';
// Claude Observation - relais en ligne (zero dependance).
// Le PC (agent) appelle ce serveur en sortie : il garde une requete "poll" ouverte, le relais lui passe les
// requetes du telephone/navigateur (/api/*), l'agent les rejoue sur son serveur local et renvoie la reponse.
// Rien n'est stocke : tout est en memoire.
const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 3000;
const UI = fs.readFileSync(path.join(__dirname, 'ui.html'), 'utf8');
const LANDING = fs.readFileSync(path.join(__dirname, 'landing.html'), 'utf8');

const POLL_MS = 25000;      // duree max d'un poll agent
const ONLINE_MS = 45000;    // agent considere en ligne si poll vu il y a moins de ca
const JOB_TIMEOUT_MS = 90000;
const MAX_ROOMS = 200;

/** code -> { secret, lastPoll, queue:[job], waiters:[{res,timer}], pending: Map(id -> {res,timer}) } */
const rooms = new Map();

const sha = (s) => crypto.createHash('sha256').update(s).digest();
const safeEq = (a, b) => a.length === b.length && crypto.timingSafeEqual(a, b);
const normCode = (c) => String(c || '').toLowerCase().replace(/[^a-z2-9]/g, '');
const validCode = (c) => /^[a-z2-9]{8}$/.test(c);

// ---- anti-abus : trop d'echecs depuis une meme IP => 429
const fails = new Map();
const ipOf = (req) => (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
function blocked(ip) {
  const f = fails.get(ip);
  return !!f && f.n >= 15 && Date.now() - f.t < 10 * 60 * 1000;
}
function fail(ip) {
  const f = fails.get(ip);
  if (!f || Date.now() - f.t > 10 * 60 * 1000) fails.set(ip, { n: 1, t: Date.now() });
  else { f.n++; f.t = Date.now(); }
}

// ---- utilitaires HTTP
function send(res, code, type, body, extra) {
  const h = Object.assign({
    'Content-Type': type,
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'X-Frame-Options': 'DENY',
  }, extra || {});
  res.writeHead(code, h);
  res.end(body);
}
const json = (res, code, obj) => send(res, code, 'application/json; charset=utf-8', JSON.stringify(obj));

function readBody(req, max) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let n = 0;
    req.on('data', (c) => {
      n += c.length;
      if (n > max) { reject(new Error('too large')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function cookie(req, name) {
  const m = (req.headers.cookie || '').split(';').map((s) => s.trim()).find((s) => s.startsWith(name + '='));
  return m ? decodeURIComponent(m.slice(name.length + 1)) : '';
}
const isHttps = (req) => (req.headers['x-forwarded-proto'] || '').startsWith('https');
const cookieHdr = (req, v, maxAge) =>
  `co_room=${encodeURIComponent(v)}; Path=/; Max-Age=${maxAge}; HttpOnly; SameSite=Lax${isHttps(req) ? '; Secure' : ''}`;

const landing = (err) => LANDING.replace('<!--ERR-->', err ? String(err).replace(/[<>&"]/g, '') : '');
const online = (r) => Date.now() - r.lastPoll < ONLINE_MS;

// ---- cote agent
function agentAuth(req, res, code, create) {
  const ip = ipOf(req);
  if (blocked(ip)) { json(res, 429, { error: 'trop d\'essais' }); return null; }
  const secret = String(req.headers['x-secret'] || '');
  if (!validCode(code) || secret.length < 16 || secret.length > 128) { fail(ip); json(res, 400, { error: 'requete invalide' }); return null; }
  let room = rooms.get(code);
  if (!room) {
    if (!create) { json(res, 404, { error: 'room inconnue' }); return null; }
    if (rooms.size >= MAX_ROOMS) { json(res, 503, { error: 'relais plein' }); return null; }
    room = { secret: sha(secret), lastPoll: 0, queue: [], waiters: [], pending: new Map() };
    rooms.set(code, room);
  } else if (!safeEq(room.secret, sha(secret))) {
    fail(ip); json(res, 403, { error: 'secret invalide' }); return null;
  }
  return room;
}

function deliver(room, job) {
  const w = room.waiters.shift();
  if (w) {
    clearTimeout(w.timer);
    json(w.res, 200, job);
  } else {
    room.queue.push(job);
  }
}

function agentPoll(req, res, q) {
  const code = normCode(q.get('room'));
  const room = agentAuth(req, res, code, true);
  if (!room) return;
  room.lastPoll = Date.now();
  if (room.queue.length) return json(res, 200, room.queue.shift());
  const w = { res, timer: null };
  w.timer = setTimeout(() => {
    room.waiters = room.waiters.filter((x) => x !== w);
    room.lastPoll = Date.now();
    send(res, 204, 'text/plain', '');
  }, POLL_MS);
  room.waiters.push(w);
  res.on('close', () => {
    clearTimeout(w.timer);
    room.waiters = room.waiters.filter((x) => x !== w);
  });
}

async function agentResp(req, res, q) {
  const code = normCode(q.get('room'));
  const room = agentAuth(req, res, code, false);
  if (!room) return;
  room.lastPoll = Date.now();
  let body;
  try { body = await readBody(req, 3 * 1024 * 1024); } catch (e) { return json(res, 413, { error: 'trop gros' }); }
  const p = room.pending.get(q.get('id'));
  if (!p) return json(res, 200, { ok: false }); // le telephone a deja abandonne
  room.pending.delete(q.get('id'));
  clearTimeout(p.timer);
  const status = parseInt(q.get('status'), 10) || 502;
  const h = { 'Content-Type': q.get('ct') || 'application/octet-stream', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' };
  if (q.get('hash')) h['X-Hash'] = q.get('hash').replace(/[^0-9a-f]/gi, '').slice(0, 32);
  p.res.writeHead(status, h);
  p.res.end(body);
  json(res, 200, { ok: true });
}

// ---- cote telephone / navigateur
async function viewerApi(req, res, url) {
  const ip = ipOf(req);
  if (blocked(ip)) return json(res, 429, { error: 'trop d\'essais' });
  const code = normCode(req.headers['x-room'] || cookie(req, 'co_room'));
  const room = rooms.get(code);
  if (!room) { fail(ip); return json(res, 404, { error: 'no_room' }); }
  if (!online(room)) return json(res, 503, { error: 'pc_offline' });
  const p = url.pathname;
  if (!(p === '/hello' || p.startsWith('/api/')) || url.pathname.length > 200 || req.url.length > 1500) return json(res, 400, { error: 'chemin refuse' });
  if (req.method !== 'GET' && req.method !== 'POST') return json(res, 405, { error: 'methode refusee' });

  let body = Buffer.alloc(0);
  if (req.method === 'POST') {
    try { body = await readBody(req, 8192); } catch (e) { return json(res, 413, { error: 'trop gros' }); }
  }
  const id = crypto.randomBytes(9).toString('base64url');
  const job = { id, method: req.method, path: req.url, key: String(req.headers['x-key'] || '').slice(0, 128), body: body.toString('base64') };
  const timer = setTimeout(() => {
    room.pending.delete(id);
    json(res, 504, { error: 'pas de reponse du PC' });
  }, JOB_TIMEOUT_MS);
  room.pending.set(id, { res, timer });
  res.on('close', () => { // le telephone a coupe
    if (room.pending.delete(id)) {
      clearTimeout(timer);
      room.queue = room.queue.filter((j) => j.id !== id);
    }
  });
  deliver(room, job);
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://x');
    const p = url.pathname;

    if (p === '/health') return send(res, 200, 'text/plain', 'ok');

    if (p === '/_agent/poll' && req.method === 'GET') return agentPoll(req, res, url.searchParams);
    if (p === '/_agent/resp' && req.method === 'POST') return agentResp(req, res, url.searchParams);

    if (p === '/' && req.method === 'GET') {
      const room = rooms.get(normCode(cookie(req, 'co_room')));
      if (room) return send(res, 200, 'text/html; charset=utf-8', UI.replace('<!--RELAY-->', '<script>window.CO_RELAY=true</script>'));
      return send(res, 200, 'text/html; charset=utf-8', landing(''));
    }

    if (p === '/join' && req.method === 'POST') {
      const ip = ipOf(req);
      if (blocked(ip)) return send(res, 429, 'text/html; charset=utf-8', landing('Trop d\'essais. Patiente quelques minutes.'));
      let body = '';
      try { body = (await readBody(req, 512)).toString('utf8'); } catch (e) { return send(res, 413, 'text/plain', ''); }
      const code = normCode(new URLSearchParams(body).get('code'));
      if (!validCode(code) || !rooms.has(code)) {
        fail(ip);
        return send(res, 404, 'text/html; charset=utf-8', landing('Code inconnu. Vérifie le code affiché sur ton PC et que l\'agent est lancé (réessaie dans une minute si le serveur vient de se réveiller).'));
      }
      return send(res, 303, 'text/plain', '', { Location: '/', 'Set-Cookie': cookieHdr(req, code, 31536000) });
    }

    if (p === '/leave') return send(res, 303, 'text/plain', '', { Location: '/', 'Set-Cookie': cookieHdr(req, '', 0) });

    if (p === '/hello' || p.startsWith('/api/')) return viewerApi(req, res, url);

    send(res, 404, 'text/plain', 'not found');
  } catch (e) {
    try { json(res, 500, { error: 'erreur interne' }); } catch (_) { /* deja repondu */ }
  }
});
server.keepAliveTimeout = 65000;
server.headersTimeout = 70000;

// nettoyage : rooms inactives depuis 7 jours, compteurs d'echecs perimes
setInterval(() => {
  const now = Date.now();
  for (const [c, r] of rooms) if (now - r.lastPoll > 7 * 24 * 3600 * 1000 && !r.waiters.length) rooms.delete(c);
  for (const [ip, f] of fails) if (now - f.t > 10 * 60 * 1000) fails.delete(ip);
}, 3600 * 1000).unref();

server.listen(PORT, () => console.log('Claude Observation relay sur le port ' + PORT));

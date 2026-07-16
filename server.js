const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, 'data');
const DB_FILE = path.join(DATA_DIR, 'users.json');
const MIME = {'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.jpg':'image/jpeg','.jpeg':'image/jpeg','.png':'image/png','.mp3':'audio/mpeg'};

function ensureDb() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  if (!fs.existsSync(DB_FILE)) fs.writeFileSync(DB_FILE, JSON.stringify({ users: {}, sessions: {} }, null, 2));
}
function readDb() { ensureDb(); return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); }
function writeDb(db) { ensureDb(); fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2)); }
function json(res, code, body, cookie) {
  const headers = { 'Content-Type': 'application/json; charset=utf-8' };
  if (cookie) headers['Set-Cookie'] = cookie;
  res.writeHead(code, headers); res.end(JSON.stringify(body));
}
function parseCookies(req) {
  return Object.fromEntries((req.headers.cookie || '').split(';').filter(Boolean).map(v => {
    const [k, ...rest] = v.trim().split('='); return [k, decodeURIComponent(rest.join('='))];
  }));
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = ''; req.on('data', c => { body += c; if (body.length > 1e6) req.destroy(); });
    req.on('end', () => { try { resolve(body ? JSON.parse(body) : {}); } catch (e) { reject(e); } });
  });
}
function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}
function verifyPassword(password, stored) {
  const [salt, hash] = stored.split(':');
  const check = crypto.scryptSync(password, salt, 64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(check, 'hex'));
}
function currentUser(req, db) {
  const sid = parseCookies(req).sns_sid;
  return sid && db.sessions[sid] ? db.sessions[sid] : null;
}
function publicUser(id, user) {
  return { id, coins: user.coins, dailyDate: user.dailyDate || '', dailyCount: user.dailyCount || 0, lastDraw: user.lastDraw || 0 };
}
async function api(req, res) {
  const db = readDb();
  try {
    if (req.url === '/api/me' && req.method === 'GET') {
      const id = currentUser(req, db); return json(res, 200, { user: id ? publicUser(id, db.users[id]) : null });
    }
    if (req.url === '/api/signup' && req.method === 'POST') {
      const { id, password } = await readBody(req);
      if (!id || !password) return json(res, 400, { error: '아이디와 비밀번호를 입력하세요.' });
      if (db.users[id]) return json(res, 409, { error: '이미 존재하는 아이디입니다.' });
      db.users[id] = { passwordHash: hashPassword(password), coins: 30000, dailyDate: '', dailyCount: 0, lastDraw: 0, createdAt: new Date().toISOString() };
      const sid = crypto.randomBytes(24).toString('hex'); db.sessions[sid] = id; writeDb(db);
      return json(res, 200, { user: publicUser(id, db.users[id]) }, `sns_sid=${sid}; HttpOnly; SameSite=Lax; Path=/`);
    }
    if (req.url === '/api/login' && req.method === 'POST') {
      const { id, password } = await readBody(req);
      if (!db.users[id] || !verifyPassword(password || '', db.users[id].passwordHash)) return json(res, 401, { error: '아이디 또는 비밀번호가 올바르지 않습니다.' });
      const sid = crypto.randomBytes(24).toString('hex'); db.sessions[sid] = id; writeDb(db);
      return json(res, 200, { user: publicUser(id, db.users[id]) }, `sns_sid=${sid}; HttpOnly; SameSite=Lax; Path=/`);
    }
    if (req.url === '/api/logout' && req.method === 'POST') {
      const sid = parseCookies(req).sns_sid; if (sid) delete db.sessions[sid]; writeDb(db);
      return json(res, 200, { ok: true }, 'sns_sid=; Max-Age=0; Path=/');
    }
    if (req.url === '/api/user' && req.method === 'PATCH') {
      const id = currentUser(req, db); if (!id) return json(res, 401, { error: '로그인이 필요합니다.' });
      const patch = await readBody(req); const user = db.users[id];
      ['coins','dailyDate','dailyCount','lastDraw'].forEach(k => { if (patch[k] !== undefined) user[k] = patch[k]; });
      writeDb(db); return json(res, 200, { user: publicUser(id, user) });
    }
    return json(res, 404, { error: 'API를 찾을 수 없습니다.' });
  } catch (error) { return json(res, 500, { error: error.message }); }
}
function sendFile(file, res) {
  fs.readFile(file, (err, data) => {
    if (err) { res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }); return res.end('Not found'); }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(file).toLowerCase()] || 'application/octet-stream' }); res.end(data);
  });
}
function staticFile(req, res) {
  if (req.method !== 'GET' && req.method !== 'HEAD') { res.writeHead(405); return res.end('Method not allowed'); }
  const requestPath = decodeURIComponent(req.url.split('?')[0]);
  const safePath = requestPath === '/' ? '/index.html' : requestPath;
  const file = path.normalize(path.join(ROOT, safePath));
  if (!file.startsWith(ROOT) || file.startsWith(DATA_DIR)) { res.writeHead(403); return res.end('Forbidden'); }
  fs.access(file, fs.constants.R_OK, (err) => {
    if (!err) return sendFile(file, res);
    if (!path.extname(requestPath)) return sendFile(path.join(ROOT, 'index.html'), res);
    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }); res.end('Not found');
  });
}
http.createServer((req, res) => req.url.startsWith('/api/') ? api(req, res) : staticFile(req, res)).listen(PORT, () => {
  ensureDb(); console.log(`Card game server running at http://localhost:${PORT}`);
});

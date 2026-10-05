import http from 'node:http';
import { createHash, randomBytes, scrypt as scryptCallback, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';
import { readFile, writeFile, mkdir, access } from 'node:fs/promises';
import { join, extname } from 'node:path';

const scrypt = promisify(scryptCallback);
const PORT = Number(process.env.PORT || 3000);
const PUBLIC = join(process.cwd(), 'public');
const DATA = join(process.cwd(), 'data');
const USERS_FILE = join(DATA, 'users.json');
const sessions = new Map();
const attempts = new Map();
const SESSION_AGE = 1000 * 60 * 30;
const MIME = { '.html':'text/html; charset=utf-8', '.css':'text/css; charset=utf-8', '.js':'text/javascript; charset=utf-8', '.svg':'image/svg+xml' };

async function ensureStore() {
  await mkdir(DATA, { recursive: true });
  try { await access(USERS_FILE); } catch { await writeFile(USERS_FILE, '[]', { mode: 0o600 }); }
}
async function users() { await ensureStore(); return JSON.parse(await readFile(USERS_FILE, 'utf8')); }
async function saveUsers(list) { await writeFile(USERS_FILE, JSON.stringify(list, null, 2), { mode: 0o600 }); }
async function hashPassword(password) {
  const salt = randomBytes(16).toString('hex');
  const hash = await scrypt(password, salt, 64, { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
  return `${salt}:${Buffer.from(hash).toString('hex')}`;
}
async function verifyPassword(password, stored) {
  const [salt, expected] = stored.split(':');
  if (!salt || !expected) return false;
  const actual = Buffer.from(await scrypt(password, salt, 64, { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 }));
  const expectedBuffer = Buffer.from(expected, 'hex');
  return actual.length === expectedBuffer.length && timingSafeEqual(actual, expectedBuffer);
}
function parseCookies(req) { return Object.fromEntries((req.headers.cookie || '').split(';').filter(Boolean).map(x => { const i=x.indexOf('='); return [x.slice(0,i).trim(), decodeURIComponent(x.slice(i+1))]; })); }
function session(req) { const id = parseCookies(req).sid; const value = id && sessions.get(id); if (!value || value.expires < Date.now()) { if(id) sessions.delete(id); return null; } return { id, ...value }; }
function reply(res, status, body) { res.writeHead(status, { 'Content-Type':'application/json; charset=utf-8', 'Cache-Control':'no-store', 'X-Content-Type-Options':'nosniff' }); res.end(JSON.stringify(body)); }
function validEmail(email) { return typeof email === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && email.length <= 254; }
function validPassword(password) { return typeof password === 'string' && password.length >= 12 && password.length <= 128 && /[a-z]/.test(password) && /[A-Z]/.test(password) && /\d/.test(password); }
function clientKey(req) { return createHash('sha256').update(req.socket.remoteAddress || '').digest('hex'); }
function tooMany(req) { const key=clientKey(req), now=Date.now(), values=(attempts.get(key)||[]).filter(t=>now-t<15*60*1000); values.push(now); attempts.set(key,values); return values.length > 8; }
async function body(req) { let raw=''; for await (const part of req) { raw += part; if(raw.length > 10_000) throw Error('Request too large'); } try { return JSON.parse(raw); } catch { throw Error('Invalid request'); } }
function setSession(res, user) { const id=randomBytes(32).toString('base64url'); sessions.set(id,{ user:{ id:user.id, email:user.email, name:user.name }, expires:Date.now()+SESSION_AGE }); res.setHeader('Set-Cookie', `sid=${id}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_AGE/1000}`); }

const server = http.createServer(async (req,res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host}`);
    if (url.pathname === '/api/me' && req.method === 'GET') { const current=session(req); return reply(res,200,{ user:current?.user || null }); }
    if (url.pathname === '/api/register' && req.method === 'POST') {
      const { name, email, password }=await body(req); const safeName=typeof name==='string' ? name.trim() : '';
      if (safeName.length < 2 || safeName.length > 60 || !validEmail(email) || !validPassword(password)) return reply(res,400,{ error:'Use a valid email, name, and a 12+ character password with upper, lower, and a number.' });
      const list=await users(); const normalized=email.toLowerCase();
      if (list.some(u=>u.email===normalized)) return reply(res,409,{ error:'An account already exists for this email.' });
      const user={ id:randomBytes(12).toString('hex'), name:safeName, email:normalized, passwordHash:await hashPassword(password), createdAt:new Date().toISOString() };
      list.push(user); await saveUsers(list); setSession(res,user); return reply(res,201,{ user:{ name:user.name,email:user.email } });
    }
    if (url.pathname === '/api/login' && req.method === 'POST') {
      if (tooMany(req)) return reply(res,429,{ error:'Too many attempts. Please wait 15 minutes and try again.' });
      const { email, password }=await body(req); if (!validEmail(email) || typeof password !== 'string') return reply(res,400,{ error:'Enter your email and password.' });
      const user=(await users()).find(u=>u.email===email.toLowerCase());
      if (!user || !(await verifyPassword(password,user.passwordHash))) return reply(res,401,{ error:'Email or password is incorrect.' });
      setSession(res,user); return reply(res,200,{ user:{ name:user.name,email:user.email } });
    }
    if (url.pathname === '/api/logout' && req.method === 'POST') { const current=session(req); if(current) sessions.delete(current.id); res.setHeader('Set-Cookie','sid=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0'); return reply(res,200,{ ok:true }); }
    if (req.method === 'GET') {
      const requested=url.pathname === '/' ? '/index.html' : url.pathname;
      const file=join(PUBLIC, requested); if (!file.startsWith(PUBLIC)) return reply(res,403,{error:'Forbidden'});
      const content=await readFile(file); res.writeHead(200,{ 'Content-Type':MIME[extname(file)] || 'application/octet-stream', 'X-Content-Type-Options':'nosniff' }); return res.end(content);
    }
    reply(res,404,{ error:'Not found' });
  } catch (error) { reply(res,400,{ error:error.message || 'Unable to process request.' }); }
});
server.listen(PORT, () => console.log(`VaultGate listening at http://localhost:${PORT}`));

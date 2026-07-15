require('dotenv').config();
const http = require('http');
const fs   = require('fs');
const path = require('path');
const nodemailer = require('nodemailer');
const { createClient } = require('@supabase/supabase-js');

// ── Config ────────────────────────────────────────────────────────────────────
const PORT           = process.env.PORT || 5555;
const ROOT           = __dirname;
const EMAIL_CONFIG   = path.join(ROOT, 'email.config.json');
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '123456';
const TOKEN_TTL_MS   = 8 * 60 * 60 * 1000;

const SUPABASE_URL = process.env.SUPABASE_URL || 'https://yyxiboxamnkytyiqefpz.supabase.co';
const SUPABASE_KEY = process.env.SUPABASE_KEY || '';
const db = createClient(SUPABASE_URL, SUPABASE_KEY);

// ── Email ─────────────────────────────────────────────────────────────────────
let emailCfg = { sender:'', appPassword:'', receiver:'' };
try { emailCfg = JSON.parse(fs.readFileSync(EMAIL_CONFIG,'utf8')); } catch(_){}

function makeTransporter() {
  return nodemailer.createTransport({
    service: 'gmail',
    auth: { user: emailCfg.sender, pass: emailCfg.appPassword.replace(/\s/g,'') }
  });
}

// ── Security state ────────────────────────────────────────────────────────────
const loginAttempts    = new Map();
const rateLimiter      = new Map();
const contactLimit     = new Map();
const applyLimit       = new Map();
const regLimit         = new Map();
const activeSessions   = new Map();
const studentSessions  = new Map(); // token → { email, student_id }
const studentLoginAttempts = new Map();

const RATE_LIMIT_MAX   = 120;
const LOGIN_MAX        = 5;
const LOGIN_LOCKOUT_MS = 15 * 60 * 1000;
const CONTACT_MAX      = 5;
const APPLY_MAX        = 3;
const REG_MAX          = 5;

// ── MIME ──────────────────────────────────────────────────────────────────────
const MIME_MAP = {
  '.html':'text/html; charset=utf-8', '.css':'text/css',
  '.js':'application/javascript',     '.json':'application/json',
  '.png':'image/png',   '.jpg':'image/jpeg', '.jpeg':'image/jpeg',
  '.webp':'image/webp', '.gif':'image/gif',  '.svg':'image/svg+xml',
  '.ico':'image/x-icon','.woff':'font/woff', '.woff2':'font/woff2',
  '.ttf':'font/ttf',    '.mp4':'video/mp4',
};

// ── Helpers ───────────────────────────────────────────────────────────────────
function getIP(req) {
  return (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
}
function getBody(req, maxBytes = 50 * 1024) {
  return new Promise((resolve, reject) => {
    let data = '', size = 0;
    req.on('data', chunk => { size += chunk.length; if (size > maxBytes) { reject(new Error('Body too large')); return; } data += chunk; });
    req.on('end', () => resolve(data));
    req.on('error', reject);
  });
}
function sanitize(str) {
  if (typeof str !== 'string') return '';
  return str.replace(/[<>]/g, '').trim().slice(0, 2000);
}
const ALLOWED_ORIGINS = [
  'http://localhost:5555',
  'https://gic.alfaisal.edu',
];
function securityHeaders(res, isApi = false) {
  res.setHeader('X-Content-Type-Options',            'nosniff');
  res.setHeader('X-Frame-Options',                   'DENY');
  res.setHeader('X-XSS-Protection',                  '1; mode=block');
  res.setHeader('X-Permitted-Cross-Domain-Policies', 'none');
  res.setHeader('Referrer-Policy',                   'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy',                'camera=(), microphone=(), geolocation=(), payment=()');
  res.setHeader('Strict-Transport-Security',         'max-age=31536000; includeSubDomains; preload');
  if (!isApi) {
    res.setHeader('Content-Security-Policy', [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com",
      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
      "font-src 'self' https://fonts.gstatic.com",
      "img-src 'self' data: blob:",
      "connect-src 'self'",
      "media-src 'self'",
      "object-src 'none'",
      "base-uri 'self'",
      "form-action 'self'",
      "frame-ancestors 'none'",
      "upgrade-insecure-requests",
    ].join('; '));
  }
}
function cors(res, req) {
  const origin = req?.headers?.origin || '';
  if (ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin',  origin);
    res.setHeader('Vary', 'Origin');
  } else {
    res.setHeader('Access-Control-Allow-Origin', ALLOWED_ORIGINS[0]);
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Max-Age',       '86400');
}
function json(res, data, status = 200) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

// ── Rate limiting ─────────────────────────────────────────────────────────────
function checkRateLimit(ip) {
  const now = Date.now();
  let e = rateLimiter.get(ip);
  if (!e || now > e.resetAt) { e = { count: 0, resetAt: now + 60_000 }; rateLimiter.set(ip, e); }
  return ++e.count > RATE_LIMIT_MAX;
}
function checkContactLimit(ip) {
  const now = Date.now();
  let e = contactLimit.get(ip);
  if (!e || now > e.resetAt) { e = { count: 0, resetAt: now + 3_600_000 }; contactLimit.set(ip, e); }
  return ++e.count > CONTACT_MAX;
}
function checkApplyLimit(ip) {
  const now = Date.now();
  let e = applyLimit.get(ip);
  if (!e || now > e.resetAt) { e = { count: 0, resetAt: now + 86_400_000 }; applyLimit.set(ip, e); }
  return ++e.count > APPLY_MAX;
}
function checkRegLimit(ip) {
  const now = Date.now();
  let e = regLimit.get(ip);
  if (!e || now > e.resetAt) { e = { count: 0, resetAt: now + 86_400_000 }; regLimit.set(ip, e); }
  return ++e.count > REG_MAX;
}

// ── Auth ──────────────────────────────────────────────────────────────────────
function issueToken() {
  const token = require('crypto').randomBytes(32).toString('hex');
  activeSessions.set(token, { createdAt: Date.now() });
  return token;
}
function checkAuth(req) {
  const auth  = req.headers['authorization'] || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  const sess  = activeSessions.get(token);
  if (!sess) return false;
  if (Date.now() - sess.createdAt > TOKEN_TTL_MS) { activeSessions.delete(token); return false; }
  return true;
}
function checkLoginAllowed(ip) {
  const now = Date.now();
  const e   = loginAttempts.get(ip) || { count: 0, lockedUntil: 0 };
  if (e.lockedUntil > now) return { allowed: false, wait: Math.ceil((e.lockedUntil - now) / 60000) };
  return { allowed: true };
}
function recordLoginFail(ip) {
  const e = loginAttempts.get(ip) || { count: 0, lockedUntil: 0 };
  e.count++;
  if (e.count >= LOGIN_MAX) e.lockedUntil = Date.now() + LOGIN_LOCKOUT_MS;
  loginAttempts.set(ip, e);
}
function clearLoginFail(ip) { loginAttempts.delete(ip); }

// ── Email ─────────────────────────────────────────────────────────────────────
async function sendContactEmail(name, email, message) {
  if (!emailCfg.sender || !emailCfg.appPassword) return;
  const t = makeTransporter();
  await t.sendMail({
    from: `"GIC Website" <${emailCfg.sender}>`,
    to: emailCfg.receiver, replyTo: email,
    subject: `[GIC Contact] New message from ${name}`,
    html: `<div style="font-family:sans-serif;max-width:600px;background:#06000F;color:#EDE0FF;padding:32px;border-radius:12px;border:1px solid rgba(191,0,255,.3)">
      <h2 style="color:#BF00FF;margin-top:0">New Contact Form Submission</h2>
      <p><strong>Name:</strong> ${name}</p>
      <p><strong>Email:</strong> <a href="mailto:${email}" style="color:#00E5FF">${email}</a></p>
      <div style="margin-top:16px;padding:16px;background:rgba(191,0,255,.08);border-radius:8px">
        <div style="color:rgba(237,224,255,.5);font-size:.8rem;margin-bottom:8px">MESSAGE</div>
        <div style="line-height:1.7">${message.replace(/\n/g,'<br>')}</div>
      </div>
      <div style="margin-top:20px;font-size:.75rem;color:rgba(237,224,255,.3)">${new Date().toLocaleString()}</div>
    </div>`
  });
}

// ── DB helpers ────────────────────────────────────────────────────────────────
function mapRow(section, row) {
  if (section === 'programs' || section === 'news' || section === 'events') {
    const { description, ...rest } = row;
    return { ...rest, desc: description };
  }
  return row;
}

function mapBody(section, body) {
  if (section === 'programs' || section === 'news' || section === 'events') {
    const { desc, ...rest } = body;
    return { ...rest, description: desc };
  }
  return body;
}

async function getContent() {
  const [programs, news, faq, events, team, heroRes] = await Promise.all([
    db.from('programs').select('*').order('id'),
    db.from('news').select('*').order('id'),
    db.from('faq').select('*').order('id'),
    db.from('events').select('*').order('id'),
    db.from('team').select('*').order('id'),
    db.from('hero').select('*').eq('id', 1).single(),
  ]);
  const h = heroRes.data || {};
  return {
    programs: (programs.data||[]).map(r => mapRow('programs', r)),
    news:     (news.data||[]).map(r => mapRow('news', r)),
    faq:      faq.data || [],
    events:   (events.data||[]).map(r => mapRow('events', r)),
    team:     team.data || [],
    hero: {
      title: h.title, subtitle: h.subtitle,
      stat1: { value: h.stat1_value, label: h.stat1_label },
      stat2: { value: h.stat2_value, label: h.stat2_label },
      stat3: { value: h.stat3_value, label: h.stat3_label },
    }
  };
}

// ── Request handler ───────────────────────────────────────────────────────────
const handler = async (req, res) => {
  const ip       = getIP(req);
  const parsed   = new URL(req.url, `http://localhost:${PORT}`);
  const pathname = parsed.pathname;

  const isApi = pathname.startsWith('/api/');
  securityHeaders(res, isApi);
  cors(res, req);

  if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }
  // Rate-limit only API write/auth endpoints — not static files or public reads
  const isApiWrite = pathname.startsWith('/api/') && req.method !== 'GET' && pathname !== '/api/auth/logout';
  if (isApiWrite && checkRateLimit(ip)) return json(res, { error: 'Too many requests' }, 429);

  if (pathname.startsWith('/api/')) {

    // POST /api/auth
    if (pathname === '/api/auth' && req.method === 'POST') {
      const lock = checkLoginAllowed(ip);
      if (!lock.allowed) return json(res, { error: `Locked. Try again in ${lock.wait} min.` }, 429);
      let body; try { body = JSON.parse(await getBody(req)); } catch(_) { return json(res, { error: 'Bad request' }, 400); }
      if (body.password === ADMIN_PASSWORD) {
        clearLoginFail(ip);
        return json(res, { ok: true, token: issueToken() });
      }
      recordLoginFail(ip);
      const left = LOGIN_MAX - (loginAttempts.get(ip)?.count || 0);
      return json(res, { ok: false, attemptsLeft: Math.max(0, left) }, 401);
    }

    // POST /api/auth/logout
    if (pathname === '/api/auth/logout' && req.method === 'POST') {
      const token = (req.headers['authorization']||'').replace('Bearer ','');
      activeSessions.delete(token);
      return json(res, { ok: true });
    }

    // POST /api/upload (admin — upload team photo)
    if (pathname === '/api/upload' && req.method === 'POST') {
      if (!checkAuth(req)) return json(res, { error: 'Unauthorized' }, 401);
      const ct = req.headers['content-type'] || '';
      if (!ct.includes('multipart/form-data')) return json(res, { error: 'Must be multipart/form-data' }, 400);
      const boundary = ct.split('boundary=')[1];
      if (!boundary) return json(res, { error: 'No boundary' }, 400);
      const buf = await new Promise((resolve, reject) => {
        const chunks = [];
        req.on('data', c => chunks.push(c));
        req.on('end', () => resolve(Buffer.concat(chunks)));
        req.on('error', reject);
      });
      const boundaryBuf = Buffer.from('--' + boundary);
      const parts = [];
      let start = 0;
      while (true) {
        const idx = buf.indexOf(boundaryBuf, start);
        if (idx === -1) break;
        if (start > 0) parts.push(buf.slice(start, idx - 2));
        start = idx + boundaryBuf.length + 2;
      }
      let filePath = null;
      for (const part of parts) {
        const headerEnd = part.indexOf('\r\n\r\n');
        if (headerEnd === -1) continue;
        const headers = part.slice(0, headerEnd).toString();
        if (!headers.includes('filename=')) continue;
        const filenameMatch = headers.match(/filename="([^"]+)"/);
        if (!filenameMatch) continue;
        const origName = filenameMatch[1];
        const ext = path.extname(origName).toLowerCase();
        if (!['.jpg','.jpeg','.png','.webp','.gif'].includes(ext)) return json(res, { error: 'Invalid file type' }, 400);
        const data = part.slice(headerEnd + 4);
        if (data.length > 5 * 1024 * 1024) return json(res, { error: 'File too large (max 5MB)' }, 400);
        const uploadDir = path.join(ROOT, 'team-photos');
        if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);
        const fname = Date.now() + '_' + Math.random().toString(36).slice(2) + ext;
        fs.writeFileSync(path.join(uploadDir, fname), data);
        filePath = 'team-photos/' + fname;
        break;
      }
      if (!filePath) return json(res, { error: 'No file found' }, 400);
      return json(res, { url: filePath });
    }

    // GET /api/content (public)
    if (pathname === '/api/content' && req.method === 'GET') {
      try { return json(res, await getContent()); }
      catch(e) { return json(res, { error: e.message }, 500); }
    }

    // POST /api/apply (public)
    if (pathname === '/api/apply' && req.method === 'POST') {
      if (checkApplyLimit(ip)) return json(res, { error: 'Application limit reached. Try again tomorrow.' }, 429);
      let body; try { body = JSON.parse(await getBody(req)); } catch(_) { return json(res, { error: 'Bad request' }, 400); }
      const name       = sanitize(body.name || '');
      const email      = sanitize(body.email || '');
      const student_id = sanitize(body.student_id || '');
      const major      = sanitize(body.major || '');
      const year_level = sanitize(body.year_level || '');
      const program    = sanitize(body.program || '');
      const message    = sanitize(body.message || '');
      if (!name || !email || !program) return json(res, { error: 'Name, email and program are required.' }, 400);
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return json(res, { error: 'Invalid email address.' }, 400);
      const { data, error } = await db.from('applications').insert([{
        name, email, student_id, major, year_level, program, message,
        ip, date: new Date().toISOString(), status: 'pending', read: false
      }]).select().single();
      if (error) return json(res, { error: 'Failed to submit. Please try again.' }, 500);
      // Email notification
      if (emailCfg.sender && emailCfg.appPassword) {
        makeTransporter().sendMail({
          from: emailCfg.sender, to: emailCfg.receiver,
          subject: `New Application: ${name} → ${program}`,
          html: `<h2>New GIC Application</h2><p><b>Name:</b> ${name}<br><b>Email:</b> ${email}<br><b>Program:</b> ${program}<br><b>Major:</b> ${major||'—'}<br><b>Year:</b> ${year_level||'—'}<br><b>Student ID:</b> ${student_id||'—'}</p><p><b>Message:</b><br>${message||'—'}</p>`
        }).catch(() => {});
      }
      return json(res, { ok: true });
    }

    // GET /api/applications (admin)
    if (pathname === '/api/applications' && req.method === 'GET') {
      if (!checkAuth(req)) return json(res, { error: 'Unauthorized' }, 401);
      const { data } = await db.from('applications').select('*').order('date', { ascending: false });
      return json(res, data || []);
    }

    // PATCH /api/applications/:id
    if (pathname.match(/^\/api\/applications\/\d+$/) && req.method === 'PATCH') {
      if (!checkAuth(req)) return json(res, { error: 'Unauthorized' }, 401);
      const id = parseInt(pathname.split('/')[3]);
      let body; try { body = JSON.parse(await getBody(req)); } catch(_) { return json(res, { error: 'Bad request' }, 400); }
      const update = {};
      if ('status' in body) update.status = body.status;
      if ('read'   in body) update.read   = body.read;
      const { data, error } = await db.from('applications').update(update).eq('id', id).select().single();
      if (error) return json(res, { error: error.message }, 500);
      return json(res, data);
    }

    // DELETE /api/applications/:id
    if (pathname.match(/^\/api\/applications\/\d+$/) && req.method === 'DELETE') {
      if (!checkAuth(req)) return json(res, { error: 'Unauthorized' }, 401);
      const id = parseInt(pathname.split('/')[3]);
      await db.from('applications').delete().eq('id', id);
      return json(res, { ok: true });
    }

    // POST /api/register (public — event booking)
    if (pathname === '/api/register' && req.method === 'POST') {
      if (checkRegLimit(ip)) return json(res, { error: 'Registration limit reached. Try again tomorrow.' }, 429);
      let body; try { body = JSON.parse(await getBody(req)); } catch(_) { return json(res, { error: 'Bad request' }, 400); }
      const event_title = sanitize(body.event_title || '');
      const name        = sanitize(body.name || '');
      const email       = sanitize(body.email || '');
      const student_id  = sanitize(body.student_id || '');
      const message     = sanitize(body.message || '');
      if (!event_title || !name || !email) return json(res, { error: 'Event, name and email are required.' }, 400);
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return json(res, { error: 'Invalid email address.' }, 400);
      const { error } = await db.from('event_registrations').insert([{
        event_title, name, email, student_id, message,
        ip, date: new Date().toISOString(), status: 'pending', read: false
      }]);
      if (error) return json(res, { error: 'Failed to register. Please try again.' }, 500);
      if (emailCfg.sender && emailCfg.appPassword) {
        makeTransporter().sendMail({
          from: emailCfg.sender, to: emailCfg.receiver,
          subject: `New Event Registration: ${name} → ${event_title}`,
          html: `<h2>New Event Registration</h2><p><b>Event:</b> ${event_title}<br><b>Name:</b> ${name}<br><b>Email:</b> ${email}<br><b>Student ID:</b> ${student_id||'—'}</p><p><b>Message:</b><br>${message||'—'}</p>`
        }).catch(() => {});
      }
      return json(res, { ok: true });
    }

    // GET /api/registrations (admin)
    if (pathname === '/api/registrations' && req.method === 'GET') {
      if (!checkAuth(req)) return json(res, { error: 'Unauthorized' }, 401);
      const { data } = await db.from('event_registrations').select('*').order('date', { ascending: false });
      return json(res, data || []);
    }

    // PATCH /api/registrations/:id
    if (pathname.match(/^\/api\/registrations\/\d+$/) && req.method === 'PATCH') {
      if (!checkAuth(req)) return json(res, { error: 'Unauthorized' }, 401);
      const id = parseInt(pathname.split('/')[3]);
      let body; try { body = JSON.parse(await getBody(req)); } catch(_) { return json(res, { error: 'Bad request' }, 400); }
      const update = {};
      if ('status' in body) update.status = body.status;
      if ('read'   in body) update.read   = body.read;
      const { data, error } = await db.from('event_registrations').update(update).eq('id', id).select().single();
      if (error) return json(res, { error: error.message }, 500);
      return json(res, data);
    }

    // DELETE /api/registrations/:id
    if (pathname.match(/^\/api\/registrations\/\d+$/) && req.method === 'DELETE') {
      if (!checkAuth(req)) return json(res, { error: 'Unauthorized' }, 401);
      const id = parseInt(pathname.split('/')[3]);
      await db.from('event_registrations').delete().eq('id', id);
      return json(res, { ok: true });
    }

    // POST /api/contact (public)
    if (pathname === '/api/contact' && req.method === 'POST') {
      if (checkContactLimit(ip)) return json(res, { error: 'Too many submissions. Try later.' }, 429);
      let body; try { body = JSON.parse(await getBody(req)); } catch(_) { return json(res, { error: 'Bad request' }, 400); }
      const name    = sanitize(body.name);
      const email   = sanitize(body.email);
      const message = sanitize(body.message);
      if (!name || !email || !message) return json(res, { error: 'All fields required' }, 400);
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return json(res, { error: 'Invalid email' }, 400);
      if (name.length < 2) return json(res, { error: 'Name too short' }, 400);
      if (message.length < 10) return json(res, { error: 'Message too short' }, 400);
      const entry = { id: Date.now(), name, email, message, ip, date: new Date().toISOString(), read: false };
      await db.from('contacts').insert(entry);
      sendContactEmail(name, email, message).catch(e => console.error('[Email]', e.message));
      return json(res, { ok: true, message: 'Message received!' });
    }

    // GET /api/contacts (admin)
    if (pathname === '/api/contacts' && req.method === 'GET') {
      if (!checkAuth(req)) return json(res, { error: 'Unauthorized' }, 401);
      const { data } = await db.from('contacts').select('*').order('date', { ascending: false });
      return json(res, data || []);
    }

    // PATCH /api/contacts/:id/read
    if (pathname.match(/^\/api\/contacts\/\d+\/read$/) && req.method === 'PATCH') {
      if (!checkAuth(req)) return json(res, { error: 'Unauthorized' }, 401);
      const id = parseInt(pathname.split('/')[3]);
      await db.from('contacts').update({ read: true }).eq('id', id);
      return json(res, { ok: true });
    }

    // DELETE /api/contacts/:id
    if (pathname.match(/^\/api\/contacts\/\d+$/) && req.method === 'DELETE' && pathname.split('/').length === 4) {
      if (!checkAuth(req)) return json(res, { error: 'Unauthorized' }, 401);
      const id = parseInt(pathname.split('/')[3]);
      await db.from('contacts').delete().eq('id', id);
      return json(res, { ok: true });
    }

    // Auth guard for write ops (student portal routes are public)
    if (['POST','PUT','DELETE'].includes(req.method) && !pathname.startsWith('/api/student/') && !checkAuth(req)) {
      return json(res, { error: 'Unauthorized' }, 401);
    }

    const parts   = pathname.split('/').filter(Boolean);
    const section = parts[1];
    const id      = parts[2] ? parseInt(parts[2]) : null;

    // PUT /api/hero
    if (section === 'hero' && req.method === 'PUT') {
      let body; try { body = JSON.parse(await getBody(req)); } catch(_) { return json(res, { error: 'Bad request' }, 400); }
      const h = body;
      await db.from('hero').upsert({
        id: 1, title: h.title, subtitle: h.subtitle,
        stat1_value: h.stat1?.value, stat1_label: h.stat1?.label,
        stat2_value: h.stat2?.value, stat2_label: h.stat2?.label,
        stat3_value: h.stat3?.value, stat3_label: h.stat3?.label,
      });
      return json(res, { ok: true });
    }

    // ── Student Portal ──────────────────────────────────────────────────────

    // POST /api/student/login
    if (pathname === '/api/student/login' && req.method === 'POST') {
      const la = studentLoginAttempts.get(ip) || { count: 0, lockedUntil: 0 };
      if (la.lockedUntil > Date.now()) return json(res, { error: `Too many attempts. Try again in ${Math.ceil((la.lockedUntil - Date.now())/60000)} min.` }, 429);
      let body; try { body = JSON.parse(await getBody(req)); } catch(_) { return json(res, { error: 'Bad request' }, 400); }
      const email      = sanitize(body.email || '').toLowerCase();
      const student_id = sanitize(body.student_id || '');
      if (!email) return json(res, { error: 'Email is required.' }, 400);
      const [appRes2, regRes2] = await Promise.all([
        db.from('applications').select('*').ilike('email', email),
        db.from('event_registrations').select('*').ilike('email', email)
      ]);
      const apps2 = appRes2.data || [];
      const regs2 = regRes2.data || [];
      if (!apps2.length && !regs2.length) {
        la.count++; if (la.count >= 5) la.lockedUntil = Date.now() + 15*60*1000;
        studentLoginAttempts.set(ip, la);
        return json(res, { error: 'No records found for this email.' }, 401);
      }
      if (student_id) {
        const sid = student_id.toLowerCase();
        const match = [...apps2, ...regs2].some(r => (r.student_id||'').toLowerCase() === sid);
        if (!match) {
          la.count++; if (la.count >= 5) la.lockedUntil = Date.now() + 15*60*1000;
          studentLoginAttempts.set(ip, la);
          return json(res, { error: 'Student ID does not match our records.' }, 401);
        }
      }
      studentLoginAttempts.delete(ip);
      const token = require('crypto').randomBytes(32).toString('hex');
      studentSessions.set(token, { email, createdAt: Date.now() });
      return json(res, { ok: true, token });
    }

    // GET /api/student/dashboard
    if (pathname === '/api/student/dashboard' && req.method === 'GET') {
      const auth2  = req.headers['authorization'] || '';
      const token2 = auth2.startsWith('Bearer ') ? auth2.slice(7) : '';
      const sess2  = studentSessions.get(token2);
      if (!sess2) return json(res, { error: 'Unauthorized' }, 401);
      if (Date.now() - sess2.createdAt > TOKEN_TTL_MS) { studentSessions.delete(token2); return json(res, { error: 'Session expired' }, 401); }
      const [appRes3, regRes3] = await Promise.all([
        db.from('applications').select('id,program,name,status,date,message').ilike('email', sess2.email).order('date', { ascending: false }),
        db.from('event_registrations').select('id,event_title,name,status,date,message').ilike('email', sess2.email).order('date', { ascending: false })
      ]);
      return json(res, { email: sess2.email, applications: appRes3.data||[], registrations: regRes3.data||[] });
    }

    // POST /api/student/logout
    if (pathname === '/api/student/logout' && req.method === 'POST') {
      const token3 = (req.headers['authorization']||'').replace('Bearer ','');
      studentSessions.delete(token3);
      return json(res, { ok: true });
    }

    // ── Sections Manager ────────────────────────────────────────────────────────

    // GET /api/sections (public)
    if (section === 'sections' && !id && req.method === 'GET') {
      const { data } = await db.from('page_sections').select('*').order('position');
      if (!data || !data.length) {
        const defaults = [
          { slug:'about',     name:'About',     visible:true,  position:1,  type:'builtin', section_type:'builtin', title:'', subtitle:'', content:[] },
          { slug:'facilities',name:'Facilities', visible:true,  position:2,  type:'builtin', section_type:'builtin', title:'', subtitle:'', content:[] },
          { slug:'programs',  name:'Programs',   visible:true,  position:3,  type:'builtin', section_type:'builtin', title:'', subtitle:'', content:[] },
          { slug:'events',    name:'Events',     visible:true,  position:4,  type:'builtin', section_type:'builtin', title:'', subtitle:'', content:[] },
          { slug:'team',      name:'Team',       visible:true,  position:5,  type:'builtin', section_type:'builtin', title:'', subtitle:'', content:[] },
          { slug:'projects',  name:'Projects',   visible:true,  position:6,  type:'builtin', section_type:'builtin', title:'', subtitle:'', content:[] },
          { slug:'news',      name:'News',       visible:true,  position:7,  type:'builtin', section_type:'builtin', title:'', subtitle:'', content:[] },
          { slug:'faq',       name:'FAQ',        visible:true,  position:8,  type:'builtin', section_type:'builtin', title:'', subtitle:'', content:[] },
          { slug:'contact',   name:'Contact',    visible:true,  position:9,  type:'builtin', section_type:'builtin', title:'', subtitle:'', content:[] },
          { slug:'partners',  name:'Partners',   visible:true,  position:10, type:'builtin', section_type:'builtin', title:'', subtitle:'', content:[] },
        ];
        const { data: seeded } = await db.from('page_sections').insert(defaults).select();
        return json(res, seeded || defaults);
      }
      return json(res, data);
    }

    // POST /api/sections (admin — add custom section)
    if (section === 'sections' && !id && req.method === 'POST') {
      if (!checkAuth(req)) return json(res, { error: 'Unauthorized' }, 401);
      let body; try { body = JSON.parse(await getBody(req)); } catch(_) { return json(res, { error: 'Bad request' }, 400); }
      const name = sanitize(body.name || '');
      if (!name) return json(res, { error: 'Name is required.' }, 400);
      const slug = name.toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/^-|-$/g,'') + '-' + Date.now();
      const { data: existing } = await db.from('page_sections').select('position').order('position',{ascending:false}).limit(1);
      const nextPos = existing?.[0] ? existing[0].position + 1 : 11;
      const { data, error } = await db.from('page_sections').insert({
        slug, name,
        visible: true,
        position: nextPos,
        type: 'custom',
        section_type: sanitize(body.section_type || 'text'),
        title: sanitize(body.title || ''),
        subtitle: sanitize(body.subtitle || ''),
        content: body.content || [],
      }).select().single();
      if (error) return json(res, { error: error.message }, 400);
      return json(res, data);
    }

    // PUT /api/sections/:id (admin — update visibility/content)
    if (section === 'sections' && id && req.method === 'PUT') {
      if (!checkAuth(req)) return json(res, { error: 'Unauthorized' }, 401);
      let body; try { body = JSON.parse(await getBody(req)); } catch(_) { return json(res, { error: 'Bad request' }, 400); }
      const update = {};
      if ('visible'      in body) update.visible      = body.visible;
      if ('position'     in body) update.position     = body.position;
      if ('name'         in body) update.name         = sanitize(body.name);
      if ('title'        in body) update.title        = sanitize(body.title);
      if ('subtitle'     in body) update.subtitle     = sanitize(body.subtitle);
      if ('content'      in body) update.content      = body.content;
      if ('section_type' in body) update.section_type = sanitize(body.section_type);
      const { data, error } = await db.from('page_sections').update(update).eq('id', id).select().single();
      if (error) return json(res, { error: error.message }, 400);
      return json(res, data);
    }

    // DELETE /api/sections/:id (admin — only custom)
    if (section === 'sections' && id && req.method === 'DELETE') {
      if (!checkAuth(req)) return json(res, { error: 'Unauthorized' }, 401);
      const { data: sec } = await db.from('page_sections').select('type').eq('id', id).single();
      if (sec?.type === 'builtin') return json(res, { error: 'Built-in sections cannot be deleted. You can hide them instead.' }, 400);
      await db.from('page_sections').delete().eq('id', id);
      return json(res, { ok: true });
    }

    const TABLES = ['programs','news','faq','events','team'];
    if (!TABLES.includes(section)) return json(res, { error: 'Unknown section' }, 404);

    if (req.method === 'GET') {
      const { data } = await db.from(section).select('*').order('id');
      return json(res, (data||[]).map(r => mapRow(section, r)));
    }

    if (req.method === 'POST') {
      let body; try { body = JSON.parse(await getBody(req)); } catch(_) { return json(res, { error: 'Bad request' }, 400); }
      delete body.id;
      const { data, error } = await db.from(section).insert(mapBody(section, body)).select().single();
      if (error) return json(res, { error: error.message }, 400);
      return json(res, mapRow(section, data));
    }

    if (req.method === 'PUT' && id) {
      let body; try { body = JSON.parse(await getBody(req)); } catch(_) { return json(res, { error: 'Bad request' }, 400); }
      const { data, error } = await db.from(section).update(mapBody(section, body)).eq('id', id).select().single();
      if (error) return json(res, { error: error.message }, 400);
      return json(res, mapRow(section, data));
    }

    if (req.method === 'DELETE' && id) {
      await db.from(section).delete().eq('id', id);
      return json(res, { ok: true });
    }

    return json(res, { error: 'Bad request' }, 400);
  }

  // ── Static files ──────────────────────────────────────────────────────────
  let filePath;
  try { filePath = path.join(ROOT, pathname === '/' ? 'index.html' : decodeURIComponent(pathname)); }
  catch(_) { res.writeHead(400); res.end('Bad request'); return; }

  if (!filePath.startsWith(ROOT)) { res.writeHead(403); res.end('Forbidden'); return; }

  const blocked = ['server.js','email.config.json','migrate.js','package.json','package-lock.json','.env'];
  const basename = path.basename(filePath);
  if (blocked.includes(basename) || basename.startsWith('.')) { res.writeHead(403); res.end('Forbidden'); return; }

  const IMMUTABLE_EXTS = new Set(['.png','.jpg','.jpeg','.webp','.gif','.svg','.ico','.woff','.woff2','.ttf','.mp4']);
  const NOCACHE_FILES  = new Set(['index.html','admin.html','sitemap.xml','robots.txt']);

  fs.stat(filePath, (err, stat) => {
    if (err || !stat.isFile()) {
      const htmlPath = filePath + '.html';
      if (fs.existsSync(htmlPath)) { filePath = htmlPath; }
      else { res.writeHead(404); res.end('Not found'); return; }
    }
    const ext  = path.extname(filePath).toLowerCase();
    const mime = MIME_MAP[ext] || 'application/octet-stream';
    const file = path.basename(filePath);
    const cacheControl = NOCACHE_FILES.has(file)
      ? 'no-cache, must-revalidate'
      : IMMUTABLE_EXTS.has(ext)
      ? 'public, max-age=31536000, immutable'
      : 'public, max-age=3600';
    res.writeHead(200, { 'Content-Type': mime, 'Cache-Control': cacheControl });
    fs.createReadStream(filePath).pipe(res);
  });
};

// Local dev — start HTTP server
if (require.main === module) {
  http.createServer(handler).listen(PORT, () => {
    console.log(`\n  ✓ GIC Server      http://localhost:${PORT}`);
    console.log(`  ✓ Admin panel     http://localhost:${PORT}/admin.html`);
    console.log(`  ✓ Database        Supabase (${SUPABASE_URL})`);
    console.log(`  ✓ Email sender    ${emailCfg.sender || '(not configured)'}\n`);
  });
}

// Vercel serverless export
module.exports = handler;

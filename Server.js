// ─── We Track Server — MongoDB Atlas Edition ──────────────────────────────────
const http   = require('http');
const path   = require('path');
const fs     = require('fs');
const crypto = require('crypto');
const { MongoClient } = require('mongodb');

const PORT         = process.env.PORT || 3000;
const MONGODB_URI  = process.env.MONGODB_URI;
const DB_NAME      = process.env.DB_NAME || 'wetrack';

if (!MONGODB_URI) {
  console.error('FATAL: MONGODB_URI environment variable not set.');
  process.exit(1);
}

let ADMIN_TOKEN = process.env.ADMIN_TOKEN;
if (!ADMIN_TOKEN) {
  ADMIN_TOKEN = crypto.randomBytes(24).toString('hex');
  console.warn('\n⚠️  ADMIN_TOKEN not set — one-time token for this session:');
  console.warn('   ADMIN_TOKEN =', ADMIN_TOKEN, '\n');
}

// ─── MONGODB CONNECTION ───────────────────────────────────────────────────────
const client = new MongoClient(MONGODB_URI, {
  maxPoolSize: 10,
  serverSelectionTimeoutMS: 5000,
  connectTimeoutMS: 10000,
});

let db;
let col; // shorthand collections

async function connectDB() {
  await client.connect();
  db = client.db(DB_NAME);
  col = {
    users:        db.collection('users'),
    sessions:     db.collection('sessions'),
    tasks:        db.collection('tasks'),
    habits:       db.collection('habits'),
    habitLog:     db.collection('habitLog'),
    friends:      db.collection('friends'),
    teams:        db.collection('teams'),
    teamMessages: db.collection('teamMessages'),
  };
  // Indexes for performance & uniqueness
  await col.users.createIndex({ email: 1 },    { unique: true });
  await col.users.createIndex({ username: 1 }, { unique: true, collation: { locale: 'en', strength: 2 } });
  await col.sessions.createIndex({ token: 1 }, { unique: true });
  await col.sessions.createIndex({ createdAt: 1 }, { expireAfterSeconds: 60 * 60 * 24 * 30 }); // 30-day session TTL
  await col.tasks.createIndex({ userId: 1, date: 1 });
  await col.habits.createIndex({ userId: 1 });
  await col.habitLog.createIndex({ habitId: 1, userId: 1, date: 1 }, { unique: true });
  await col.habitLog.createIndex({ date: 1 });
  await col.friends.createIndex({ userId: 1 }, { unique: true });
  await col.teams.createIndex({ members: 1 });
  await col.teamMessages.createIndex({ teamId: 1, created: 1 });
  console.log('✅ MongoDB connected:', DB_NAME);
}

// ─── RATE LIMITING ────────────────────────────────────────────────────────────
const rateLimitMap = new Map();
const RATE_WINDOWS = {
  auth:  { max: 10,  windowMs: 60_000 },
  api:   { max: 300, windowMs: 60_000 },
  admin: { max: 60,  windowMs: 60_000 },
};

function getClientIP(req) {
  return (req.headers['x-forwarded-for'] || '').split(',')[0].trim()
    || req.socket?.remoteAddress || 'unknown';
}

function checkRateLimit(ip, category) {
  const key  = `${category}:${ip}`;
  const rule = RATE_WINDOWS[category];
  const now  = Date.now();
  const rec  = rateLimitMap.get(key) || { count: 0, reset: now + rule.windowMs };
  if (now > rec.reset) { rec.count = 0; rec.reset = now + rule.windowMs; }
  rec.count++;
  rateLimitMap.set(key, rec);
  return rec.count <= rule.max;
}
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of rateLimitMap) { if (now > v.reset) rateLimitMap.delete(k); }
}, 300_000);

// ─── HELPERS ──────────────────────────────────────────────────────────────────
function uid()           { return crypto.randomBytes(12).toString('hex'); }
function hashPwdLegacy(p){ return crypto.createHash('sha256').update(p + 'fp_salt_2024').digest('hex'); }
function hashPwd(p)      { return crypto.pbkdf2Sync(p, 'we_track_pbkdf2_salt_v1', 100_000, 32, 'sha256').toString('hex'); }
function today()         { return new Date().toISOString().slice(0, 10); }

function getLastNDays(n) {
  const d = [];
  for (let i = n - 1; i >= 0; i--) {
    const dt = new Date(); dt.setDate(dt.getDate() - i);
    d.push(dt.toISOString().slice(0, 10));
  }
  return d;
}

const MAX_BODY = 64 * 1024;
function parseBody(req) {
  return new Promise((res, rej) => {
    let b = '', size = 0;
    req.on('data', c => {
      size += c.length;
      if (size > MAX_BODY) { req.destroy(); return rej(new Error('Payload too large')); }
      b += c;
    });
    req.on('end', () => { try { res(JSON.parse(b || '{}')); } catch { res({}); } });
    req.on('error', rej);
  });
}

// ─── VALIDATION ───────────────────────────────────────────────────────────────
function isValidEmail(e)    { return typeof e === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e) && e.length <= 254; }
function isValidUsername(u) { return typeof u === 'string' && /^[a-zA-Z0-9_\-. ]{1,30}$/.test(u.trim()); }
function isValidHexId(id)   { return typeof id === 'string' && /^[a-f0-9]{24}$/.test(id); }
function isValidDate(d)     { return typeof d === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(d); }
function sanitizeText(s, maxLen = 500) {
  if (typeof s !== 'string') return '';
  return s.replace(/[<>"'`]/g, '').trim().slice(0, maxLen);
}
const VALID_COLORS     = ['neon','lime','amber','coral','sky','pink'];
const VALID_PRIORITIES = ['low','med','high'];
const VALID_CATEGORIES = ['','work','health','learning','personal','finance'];

// ─── CORS ─────────────────────────────────────────────────────────────────────
const ALLOWED_ORIGINS = (
  process.env.ALLOWED_ORIGINS || 'https://we-trackk.netlify.app,http://localhost:3000'
).split(',').map(s => s.trim()).filter(Boolean);
console.log('✅ CORS origins:', ALLOWED_ORIGINS.join(', '));

function setCORS(req, res) {
  const origin = req.headers['origin'] || '';
  if (ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Vary', 'Origin');
  }
}

function json(res, data, status = 200) {
  res.writeHead(status, {
    'Content-Type':          'application/json',
    'X-Content-Type-Options':'nosniff',
    'X-Frame-Options':       'DENY',
    'Cache-Control':         'no-store',
  });
  res.end(JSON.stringify(data));
}
function err(res, msg, status = 400) { json(res, { error: msg }, status); }

// ─── AUTH HELPER ──────────────────────────────────────────────────────────────
async function getUser(req) {
  const token = req.headers['x-session'] || '';
  if (!token || token.length > 64) return null;
  const session = await col.sessions.findOne({ token });
  if (!session) return null;
  return col.users.findOne({ id: session.userId });
}

// ─── FRIEND DATA HELPER ───────────────────────────────────────────────────────
async function getFriendDoc(userId) {
  let doc = await col.friends.findOne({ userId });
  if (!doc) {
    doc = { userId, friends: [], sent: [], received: [] };
    await col.friends.insertOne(doc);
  }
  return doc;
}

// ─── ANALYTICS HELPERS ────────────────────────────────────────────────────────
async function habitPct(userId, date) {
  const habits = await col.habits.find({ userId }).toArray();
  if (!habits.length) return 0;
  const logs = await col.habitLog.find({ userId, date, value: true }).toArray();
  const doneIds = new Set(logs.map(l => l.habitId));
  return (habits.filter(h => doneIds.has(h.id)).length / habits.length) * 100;
}

async function taskPct(userId, date) {
  const tasks = await col.tasks.find({ userId, date }).toArray();
  if (!tasks.length) return null;
  return tasks.filter(t => t.done).length / tasks.length * 100;
}

async function computeStreak(userId) {
  const habits = await col.habits.find({ userId }).toArray();
  let streak = 0;
  for (let i = 0; i < 60; i++) {
    const dt = new Date(); dt.setDate(dt.getDate() - i);
    const d  = dt.toISOString().slice(0, 10);
    const tasks    = await col.tasks.find({ userId, date: d }).toArray();
    const taskOk   = tasks.length > 0 && tasks.some(t => t.done);
    let habitOk = false;
    if (habits.length > 0) {
      const logs  = await col.habitLog.find({ userId, date: d, value: true }).toArray();
      const doneH = logs.filter(l => habits.some(h => h.id === l.habitId)).length;
      habitOk = (doneH / habits.length) >= 0.5;
    }
    if (taskOk || habitOk) streak++;
    else if (i > 0) break;
  }
  return streak;
}

async function disciplineScore(userId) {
  const t  = today();
  const tp = (await taskPct(userId, t)) ?? 0;
  const hp = await habitPct(userId, t);
  const s  = await computeStreak(userId);
  return Math.min(100, Math.round(tp * 0.5 + hp * 0.3 + Math.min(s * 4, 20)));
}

async function avgTaskPct(userId, days) {
  const dates = getLastNDays(days);
  const vals  = await Promise.all(dates.map(d => taskPct(userId, d)));
  const valid = vals.filter(v => v !== null);
  if (!valid.length) return 0;
  return Math.round(valid.reduce((a, b) => a + b, 0) / valid.length);
}

async function avgHabitPct(userId, days) {
  const dates = getLastNDays(days);
  const vals  = await Promise.all(dates.map(d => habitPct(userId, d)));
  return Math.round(vals.reduce((a, b) => a + b, 0) / dates.length);
}

async function userStatsObject(u) {
  const t        = today();
  const dayTasks = await col.tasks.find({ userId: u.id, date: t }).toArray();
  const allTasks = await col.tasks.find({ userId: u.id }).toArray();
  const fd       = await getFriendDoc(u.id);
  return {
    id: u.id, email: u.email, username: u.username,
    avatar: u.avatar, color: u.color,
    score:      await disciplineScore(u.id),
    streak:     await computeStreak(u.id),
    friends:    fd.friends.length,
    taskCount:  dayTasks.length,
    doneCount:  dayTasks.filter(t => t.done).length,
    totalTasks: allTasks.length,
    totalDone:  allTasks.filter(t => t.done).length,
    avg7Task:   await avgTaskPct(u.id, 7),
    avg7Habit:  await avgHabitPct(u.id, 7),
    created:    u.createdAt?.slice(0, 10),
    lastSeen:   u.lastSeen?.slice(0, 10),
  };
}

// ─── STATIC FILES ─────────────────────────────────────────────────────────────
function serveStatic(res, filePath) {
  const resolved = path.resolve(filePath);
  const safeRoot = path.resolve(__dirname);
  if (!resolved.startsWith(safeRoot)) { res.writeHead(403); return res.end('Forbidden'); }
  const blocked = ['.json', '.env', '.key', '.pem'];
  if (blocked.includes(path.extname(resolved))) { res.writeHead(403); return res.end('Forbidden'); }
  try {
    const content = fs.readFileSync(resolved);
    const types   = { '.html': 'text/html', '.js': 'application/javascript', '.css': 'text/css' };
    res.writeHead(200, {
      'Content-Type':          types[path.extname(resolved)] || 'text/plain',
      'X-Content-Type-Options':'nosniff',
      'X-Frame-Options':       'SAMEORIGIN',
    });
    res.end(content);
  } catch { res.writeHead(404); res.end('Not found'); }
}

// ─── ROUTER ───────────────────────────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  const ip = getClientIP(req);
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options',        'DENY');
  res.setHeader('Referrer-Policy',        'no-referrer');

  let url, pathname;
  try {
    url      = new URL(req.url, `http://localhost:${PORT}`);
    pathname = url.pathname;
  } catch { res.writeHead(400); return res.end('Bad request'); }
  const method = req.method;

  if (method === 'OPTIONS') {
    setCORS(req, res);
    res.writeHead(204, {
      'Access-Control-Allow-Methods': 'GET,POST,PATCH,DELETE,OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type,X-Session,X-Admin-Token',
      'Access-Control-Max-Age':       '86400',
    });
    return res.end();
  }
  setCORS(req, res);

  if (pathname === '/' || pathname === '/index.html') return serveStatic(res, path.join(__dirname, 'Index.html'));
  if (pathname === '/admin' || pathname === '/admin.html') return serveStatic(res, path.join(__dirname, 'Admin.html'));

  // ─── AUTH ───────────────────────────────────────────────────────────────────
  if (pathname === '/api/auth/register' && method === 'POST') {
    if (!checkRateLimit(ip, 'auth')) return err(res, 'Too many requests', 429);
    let body; try { body = await parseBody(req); } catch { return err(res, 'Invalid request', 400); }
    const { email, password, username, avatar, color } = body;
    if (!email || !password || !username) return err(res, 'All fields required');
    if (!isValidEmail(email))             return err(res, 'Invalid email format');
    if (typeof password !== 'string' || password.length < 6 || password.length > 128)
      return err(res, 'Password must be 6–128 characters');
    if (!isValidUsername(username)) return err(res, 'Username must be 1–30 alphanumeric characters');

    const emailLower = email.toLowerCase().trim();
    const existing   = await col.users.findOne({ $or: [{ email: emailLower }, { usernameLower: username.trim().toLowerCase() }] });
    if (existing) {
      return err(res, existing.email === emailLower ? 'Email already registered' : 'Username already taken');
    }

    const id    = uid();
    const token = uid() + uid();
    const user  = {
      id, email: emailLower,
      usernameLower: username.trim().toLowerCase(),
      passwordHash:  hashPwd(password),
      username:      username.trim(),
      avatar:        sanitizeText(avatar || '⚡', 8),
      color:         VALID_COLORS.includes(color) ? color : 'neon',
      createdAt:     new Date().toISOString(),
      lastSeen:      new Date().toISOString(),
    };
    await col.users.insertOne(user);
    await col.sessions.insertOne({ token, userId: id, createdAt: new Date() });
    await col.friends.insertOne({ userId: id, friends: [], sent: [], received: [] });

    const u = { ...user }; delete u.passwordHash; delete u.usernameLower; delete u._id;
    return json(res, { token, user: u });
  }

  if (pathname === '/api/auth/login' && method === 'POST') {
    if (!checkRateLimit(ip, 'auth')) return err(res, 'Too many login attempts', 429);
    let body; try { body = await parseBody(req); } catch { return err(res, 'Invalid request', 400); }
    const { email, password } = body;
    if (!email || !password) return err(res, 'Email and password required', 401);

    const emailLower = email.toLowerCase().trim();
    const user       = await col.users.findOne({ email: emailLower });

    let matched = false;
    if (user) {
      const pbkdf2Ok = user.passwordHash === hashPwd(password);
      const legacyOk = !pbkdf2Ok && user.passwordHash === hashPwdLegacy(password);
      if (pbkdf2Ok || legacyOk) {
        matched = true;
        if (legacyOk) {
          // Silently upgrade legacy SHA-256 hash to PBKDF2
          await col.users.updateOne({ id: user.id }, { $set: { passwordHash: hashPwd(password) } });
        }
      }
    }

    if (!matched) {
      await new Promise(r => setTimeout(r, 200));
      return err(res, 'Invalid email or password', 401);
    }

    const token = uid() + uid();
    await col.sessions.insertOne({ token, userId: user.id, createdAt: new Date() });
    await col.users.updateOne({ id: user.id }, { $set: { lastSeen: new Date().toISOString() } });

    const u = { ...user }; delete u.passwordHash; delete u.usernameLower; delete u._id;
    return json(res, { token, user: u });
  }

  if (pathname === '/api/auth/logout' && method === 'POST') {
    const token = req.headers['x-session'] || '';
    if (token) await col.sessions.deleteOne({ token });
    return json(res, { ok: true });
  }

  if (pathname === '/api/auth/me' && method === 'GET') {
    if (!checkRateLimit(ip, 'api')) return err(res, 'Too many requests', 429);
    const user = await getUser(req);
    if (!user) return err(res, 'Not authenticated', 401);
    const u = { ...user }; delete u.passwordHash; delete u.usernameLower; delete u._id;
    return json(res, u);
  }

  if (pathname === '/api/auth/profile' && method === 'PATCH') {
    if (!checkRateLimit(ip, 'api')) return err(res, 'Too many requests', 429);
    const user = await getUser(req);
    if (!user) return err(res, 'Not authenticated', 401);
    let body; try { body = await parseBody(req); } catch { return err(res, 'Invalid request', 400); }
    const updates = {};
    if (body.username) {
      if (!isValidUsername(body.username)) return err(res, 'Invalid username');
      const taken = await col.users.findOne({ usernameLower: body.username.trim().toLowerCase(), id: { $ne: user.id } });
      if (taken) return err(res, 'Username already taken');
      updates.username      = body.username.trim();
      updates.usernameLower = body.username.trim().toLowerCase();
    }
    if (body.avatar) updates.avatar = sanitizeText(body.avatar, 8);
    if (body.color && VALID_COLORS.includes(body.color)) updates.color = body.color;
    if (Object.keys(updates).length) await col.users.updateOne({ id: user.id }, { $set: updates });
    const updated = await col.users.findOne({ id: user.id });
    const u = { ...updated }; delete u.passwordHash; delete u.usernameLower; delete u._id;
    return json(res, u);
  }

  // ─── MAIN DATA ──────────────────────────────────────────────────────────────
  if (pathname === '/api/data' && method === 'GET') {
    if (!checkRateLimit(ip, 'api')) return err(res, 'Too many requests', 429);
    const me = await getUser(req);
    if (!me) return err(res, 'Not authenticated', 401);
    await col.users.updateOne({ id: me.id }, { $set: { lastSeen: new Date().toISOString() } });

    const fd         = await getFriendDoc(me.id);
    const allUserIds = [me.id, ...fd.friends];

    const allUsers = await Promise.all(
      allUserIds.map(async id => {
        const u = await col.users.findOne({ id });
        return u ? userStatsObject(u) : null;
      })
    );

    // Tasks: only for me + friends
    const tasks = {};
    await Promise.all(allUserIds.map(async id => {
      const userTasks = await col.tasks.find({ userId: id }).toArray();
      tasks[id] = userTasks.map(t => { const r = {...t}; delete r._id; return r; });
    }));

    // Habits: only mine (private)
    const habits = await col.habits.find({ userId: me.id }).toArray();
    const habitsSafe = habits.map(h => { const r={...h}; delete r._id; return r; });

    // HabitLog: last 30 days for me only
    const days30   = getLastNDays(30);
    const logDocs  = await col.habitLog.find({ userId: me.id, date: { $in: days30 } }).toArray();
    const habitLog = {};
    logDocs.forEach(l => {
      if (!habitLog[l.date])          habitLog[l.date] = {};
      if (!habitLog[l.date][l.habitId]) habitLog[l.date][l.habitId] = {};
      habitLog[l.date][l.habitId][me.id] = l.value;
    });

    const myDays = await Promise.all(days30.map(async d => ({
      date: d,
      taskPct:  await taskPct(me.id, d),
      habitPct: Math.round(await habitPct(me.id, d)),
    })));

    const u = { ...me }; delete u.passwordHash; delete u.usernameLower; delete u._id;
    return json(res, {
      user: u,
      allUsers: (await Promise.all(allUsers)).filter(Boolean),
      tasks,
      habits:    habitsSafe,
      habitLog,
      friends:   fd,
      analytics: myDays,
    });
  }

  // ─── TASKS ──────────────────────────────────────────────────────────────────
  if (pathname === '/api/tasks' && method === 'POST') {
    if (!checkRateLimit(ip, 'api')) return err(res, 'Too many requests', 429);
    const me = await getUser(req);
    if (!me) return err(res, 'Not authenticated', 401);
    let body; try { body = await parseBody(req); } catch { return err(res, 'Invalid request', 400); }
    const { text, priority, category, notes, date, visibility, likes, supports, reminds, comments } = body;
    if (!text) return err(res, 'Task text required');

    const taskCount = await col.tasks.countDocuments({ userId: me.id });
    if (taskCount >= 5000) return err(res, 'Task limit reached');

    const task = {
      id:         uid(),
      userId:     me.id,
      text:       sanitizeText(text, 500),
      priority:   VALID_PRIORITIES.includes(priority) ? priority : 'med',
      category:   VALID_CATEGORIES.includes(category) ? category : '',
      notes:      sanitizeText(notes || '', 1000),
      date:       isValidDate(date) ? date : today(),
      visibility: visibility === 'public' ? 'public' : 'private',
      likes:      typeof likes === 'number' ? Math.max(0, likes) : 0,
      supports:   typeof supports === 'number' ? Math.max(0, supports) : 0,
      reminds:    typeof reminds === 'number' ? Math.max(0, reminds) : 0,
      comments:   typeof comments === 'number' ? Math.max(0, comments) : 0,
      done:       false,
      created:    Date.now(),
    };
    await col.tasks.insertOne(task);
    const r = {...task}; delete r._id;
    return json(res, r);
  }

  const taskMatch = pathname.match(/^\/api\/tasks\/([a-f0-9]{24})$/);
  if (taskMatch) {
    if (!checkRateLimit(ip, 'api')) return err(res, 'Too many requests', 429);
    const me = await getUser(req);
    if (!me) return err(res, 'Not authenticated', 401);
    const tid  = taskMatch[1];
    const task = await col.tasks.findOne({ id: tid, userId: me.id });
    if (!task) return err(res, 'Task not found', 404);
    if (method === 'PATCH') {
      let body; try { body = await parseBody(req); } catch { return err(res, 'Invalid request', 400); }
      const allowed = {};
      if (typeof body.done === 'boolean')     allowed.done     = body.done;
      if (typeof body.reason === 'string')    allowed.reason   = sanitizeText(body.reason, 200);
      if (typeof body.text === 'string')      allowed.text     = sanitizeText(body.text, 500);
      if (VALID_PRIORITIES.includes(body.priority)) allowed.priority = body.priority;
      if (VALID_CATEGORIES.includes(body.category)) allowed.category = body.category;
      if (typeof body.notes === 'string')     allowed.notes    = sanitizeText(body.notes, 1000);
      if (isValidDate(body.date))             allowed.date     = body.date;
      if (body.visibility === 'public' || body.visibility === 'private') allowed.visibility = body.visibility;
      if (typeof body.likes === 'number')     allowed.likes    = Math.max(0, body.likes);
      if (typeof body.supports === 'number') allowed.supports  = Math.max(0, body.supports);
      if (typeof body.reminds === 'number')   allowed.reminds  = Math.max(0, body.reminds);
      if (typeof body.comments === 'number') allowed.comments = Math.max(0, body.comments);
      await col.tasks.updateOne({ id: tid }, { $set: allowed });
      const updated = await col.tasks.findOne({ id: tid });
      const r = {...updated}; delete r._id;
      return json(res, r);
    }
    if (method === 'DELETE') {
      await col.tasks.deleteOne({ id: tid, userId: me.id });
      return json(res, { ok: true });
    }
  }

  // ─── HABITS ─────────────────────────────────────────────────────────────────
  if (pathname === '/api/habits' && method === 'POST') {
    if (!checkRateLimit(ip, 'api')) return err(res, 'Too many requests', 429);
    const me = await getUser(req);
    if (!me) return err(res, 'Not authenticated', 401);
    let body; try { body = await parseBody(req); } catch { return err(res, 'Invalid request', 400); }
    const { name, icon } = body;
    if (!name) return err(res, 'Habit name required');
    const count = await col.habits.countDocuments({ userId: me.id });
    if (count >= 50) return err(res, 'Habit limit reached (50 max)');
    const habit = {
      id:      uid(),
      userId:  me.id,
      user:    me.id,   // kept for client compatibility
      name:    sanitizeText(name, 100),
      icon:    sanitizeText(icon || '⭐', 8),
      created: today(),
    };
    await col.habits.insertOne(habit);
    const r = {...habit}; delete r._id;
    return json(res, r);
  }

  const habitMatch = pathname.match(/^\/api\/habits\/([a-f0-9]{24})$/);
  if (habitMatch && method === 'DELETE') {
    if (!checkRateLimit(ip, 'api')) return err(res, 'Too many requests', 429);
    const me = await getUser(req);
    if (!me) return err(res, 'Not authenticated', 401);
    const hid   = habitMatch[1];
    const habit = await col.habits.findOne({ id: hid });
    if (!habit)              return err(res, 'Habit not found', 404);
    if (habit.userId !== me.id) return err(res, 'Forbidden', 403);
    await col.habits.deleteOne({ id: hid });
    await col.habitLog.deleteMany({ habitId: hid });
    return json(res, { ok: true });
  }

  if (pathname === '/api/habitLog' && method === 'POST') {
    if (!checkRateLimit(ip, 'api')) return err(res, 'Too many requests', 429);
    const me = await getUser(req);
    if (!me) return err(res, 'Not authenticated', 401);
    let body; try { body = await parseBody(req); } catch { return err(res, 'Invalid request', 400); }
    const { habitId, date, value } = body;
    if (!isValidHexId(habitId) && !/^[a-f0-9]{24}$/.test(habitId) && !/^[a-f0-9]{32}$/.test(habitId))
      return err(res, 'Invalid habitId');
    if (!isValidDate(date))    return err(res, 'Invalid date');
    if (date !== today())      return err(res, 'Can only log habits for today', 403);
    const habit = await col.habits.findOne({ id: habitId, userId: me.id });
    if (!habit) return err(res, 'Habit not found or not yours', 404);

    await col.habitLog.updateOne(
      { habitId, userId: me.id, date },
      { $set: { habitId, userId: me.id, date, value: !!value } },
      { upsert: true }
    );
    // Prune logs older than 30 days
    const cutoff = getLastNDays(31)[0];
    await col.habitLog.deleteMany({ userId: me.id, date: { $lt: cutoff } });
    return json(res, { ok: true });
  }

  // ─── ANALYTICS ──────────────────────────────────────────────────────────────
  if (pathname === '/api/analytics' && method === 'GET') {
    if (!checkRateLimit(ip, 'api')) return err(res, 'Too many requests', 429);
    const me = await getUser(req);
    if (!me) return err(res, 'Not authenticated', 401);
    const fd         = await getFriendDoc(me.id);
    const visibleIds = [me.id, ...fd.friends];
    const days14     = getLastNDays(14);

    const perUser = await Promise.all(visibleIds.map(async id => {
      const u = await col.users.findOne({ id });
      if (!u) return null;
      const days = await Promise.all(days14.map(async d => {
        const tp = (await taskPct(id, d)) ?? 0;
        const hp = await habitPct(id, d);
        return { date: d, taskPct: Math.round(tp), habitPct: Math.round(hp), score: Math.round(tp * 0.6 + hp * 0.4) };
      }));
      const allTasks = await col.tasks.find({ userId: id }).toArray();
      return {
        id: u.id, username: u.username, avatar: u.avatar, color: u.color,
        score:          await disciplineScore(id),
        streak:         await computeStreak(id),
        days,
        avg14Task:      await avgTaskPct(id, 14),
        avg14Habit:     await avgHabitPct(id, 14),
        avg7Task:       await avgTaskPct(id, 7),
        totalTasksDone: allTasks.filter(t => t.done).length,
        totalTasks:     allTasks.length,
      };
    }));

    const categories = {}, missedReasons = {};
    await Promise.all(visibleIds.map(async id => {
      const tasks = await col.tasks.find({ userId: id }).toArray();
      tasks.forEach(t => {
        const c = t.category || 'other';
        if (!categories[c]) categories[c] = { total: 0, done: 0 };
        categories[c].total++;
        if (t.done) categories[c].done++;
        if (!t.done && t.reason) {
          const r = sanitizeText(t.reason, 100);
          missedReasons[r] = (missedReasons[r] || 0) + 1;
        }
      });
    }));

    return json(res, { users: perUser.filter(Boolean), categories, missedReasons, dates: days14 });
  }

  // ─── FRIENDS ────────────────────────────────────────────────────────────────
  if (pathname === '/api/friends/search' && method === 'GET') {
    if (!checkRateLimit(ip, 'api')) return err(res, 'Too many requests', 429);
    const me = await getUser(req);
    if (!me) return err(res, 'Not authenticated', 401);
    const q = (url.searchParams.get('q') || '').toLowerCase().trim();
    if (!q || q.length < 2 || q.length > 30) return json(res, []);
    const fd      = await getFriendDoc(me.id);
    const results = await col.users.find({ usernameLower: { $regex: q, $options: 'i' }, id: { $ne: me.id } }).limit(10).toArray();
    return json(res, results.map(u => {
      const status = fd.friends.includes(u.id) ? 'friend'
        : fd.sent.includes(u.id)     ? 'sent'
        : fd.received.includes(u.id) ? 'received' : 'none';
      return { id: u.id, username: u.username, avatar: u.avatar, color: u.color, status };
    }));
  }

  if (pathname === '/api/friends/request' && method === 'POST') {
    if (!checkRateLimit(ip, 'api')) return err(res, 'Too many requests', 429);
    const me = await getUser(req);
    if (!me) return err(res, 'Not authenticated', 401);
    let body; try { body = await parseBody(req); } catch { return err(res, 'Invalid request', 400); }
    const { targetId } = body;
    const target = await col.users.findOne({ id: targetId });
    if (!target)            return err(res, 'User not found', 404);
    if (targetId === me.id) return err(res, 'Cannot friend yourself');
    const myFd    = await getFriendDoc(me.id);
    const theirFd = await getFriendDoc(targetId);
    if (myFd.friends.length >= 200) return err(res, 'Friend limit reached');
    if (myFd.friends.includes(targetId)) return err(res, 'Already friends');
    if (myFd.sent.includes(targetId))    return err(res, 'Request already sent');
    if (myFd.received.includes(targetId)) {
      await col.friends.updateOne({ userId: me.id },     { $push: { friends: targetId }, $pull: { received: targetId } });
      await col.friends.updateOne({ userId: targetId },  { $push: { friends: me.id },    $pull: { sent: me.id } });
      return json(res, { status: 'accepted' });
    }
    await col.friends.updateOne({ userId: me.id },    { $push: { sent:     targetId } });
    await col.friends.updateOne({ userId: targetId }, { $push: { received: me.id } });
    return json(res, { status: 'sent' });
  }

  if (pathname === '/api/friends/accept' && method === 'POST') {
    if (!checkRateLimit(ip, 'api')) return err(res, 'Too many requests', 429);
    const me = await getUser(req);
    if (!me) return err(res, 'Not authenticated', 401);
    let body; try { body = await parseBody(req); } catch { return err(res, 'Invalid request', 400); }
    const { fromId } = body;
    const myFd = await getFriendDoc(me.id);
    if (!myFd.received.includes(fromId)) return err(res, 'No pending request');
    await col.friends.updateOne({ userId: me.id },  { $push: { friends: fromId }, $pull: { received: fromId } });
    await col.friends.updateOne({ userId: fromId }, { $push: { friends: me.id },  $pull: { sent: me.id } });
    return json(res, { status: 'accepted' });
  }

  if (pathname === '/api/friends/decline' && method === 'POST') {
    if (!checkRateLimit(ip, 'api')) return err(res, 'Too many requests', 429);
    const me = await getUser(req);
    if (!me) return err(res, 'Not authenticated', 401);
    let body; try { body = await parseBody(req); } catch { return err(res, 'Invalid request', 400); }
    const { userId: targetId } = body;
    if (!targetId) return err(res, 'userId required');
    await col.friends.updateOne({ userId: me.id },     { $pull: { received: targetId, sent: targetId } });
    await col.friends.updateOne({ userId: targetId },  { $pull: { sent: me.id, received: me.id } });
    return json(res, { status: 'declined' });
  }

  if (pathname === '/api/friends/remove' && method === 'POST') {
    if (!checkRateLimit(ip, 'api')) return err(res, 'Too many requests', 429);
    const me = await getUser(req);
    if (!me) return err(res, 'Not authenticated', 401);
    let body; try { body = await parseBody(req); } catch { return err(res, 'Invalid request', 400); }
    const { friendId } = body;
    if (!friendId) return err(res, 'friendId required');
    await col.friends.updateOne({ userId: me.id },    { $pull: { friends: friendId } });
    await col.friends.updateOne({ userId: friendId }, { $pull: { friends: me.id } });
    return json(res, { status: 'removed' });
  }

  if (pathname === '/api/friends' && method === 'GET') {
    if (!checkRateLimit(ip, 'api')) return err(res, 'Too many requests', 429);
    const me = await getUser(req);
    if (!me) return err(res, 'Not authenticated', 401);
    const fd    = await getFriendDoc(me.id);
    const t     = today();
    const mapU  = async id => {
      const u = await col.users.findOne({ id });
      if (!u) return null;
      const dayTasks = await col.tasks.find({ userId: id, date: t }).toArray();
      return { id: u.id, username: u.username, avatar: u.avatar, color: u.color,
        score: await disciplineScore(id), streak: await computeStreak(id),
        taskCount: dayTasks.length, doneCount: dayTasks.filter(t => t.done).length };
    };
    return json(res, {
      friends:  (await Promise.all(fd.friends.map(mapU))).filter(Boolean),
      sent:     (await Promise.all(fd.sent.map(mapU))).filter(Boolean),
      received: (await Promise.all(fd.received.map(mapU))).filter(Boolean),
    });
  }

  // ─── TEAMS ──────────────────────────────────────────────────────────────────
  if (pathname === '/api/teams' && method === 'POST') {
    if (!checkRateLimit(ip, 'api')) return err(res, 'Too many requests', 429);
    const me = await getUser(req);
    if (!me) return err(res, 'Not authenticated', 401);
    let body; try { body = await parseBody(req); } catch { return err(res, 'Invalid request', 400); }
    const { name } = body;
    if (!name || name.length < 1 || name.length > 50) return err(res, 'Team name required (1-50 chars)');

    const teamCount = await col.teams.countDocuments({ members: me.id });
    if (teamCount >= 10) return err(res, 'Team limit reached (10 max)');

    const team = {
      id:       uid(),
      name:     sanitizeText(name, 50),
      ownerId:  me.id,
      members:  [me.id],
      created:  Date.now(),
    };
    await col.teams.insertOne(team);
    const r = {...team}; delete r._id;
    return json(res, r);
  }

  if (pathname === '/api/teams' && method === 'GET') {
    if (!checkRateLimit(ip, 'api')) return err(res, 'Too many requests', 429);
    const me = await getUser(req);
    if (!me) return err(res, 'Not authenticated', 401);
    const teams = await col.teams.find({ members: me.id }).toArray();
    const teamsSafe = teams.map(t => { const r = {...t}; delete r._id; return r; });
    return json(res, teamsSafe);
  }

  const teamMatch = pathname.match(/^\/api\/teams\/([a-f0-9]{24})$/);
  if (teamMatch) {
    const teamId = teamMatch[1];
    if (method === 'GET') {
      if (!checkRateLimit(ip, 'api')) return err(res, 'Too many requests', 429);
      const me = await getUser(req);
      if (!me) return err(res, 'Not authenticated', 401);
      const team = await col.teams.findOne({ id: teamId, members: me.id });
      if (!team) return err(res, 'Team not found', 404);
      const r = {...team}; delete r._id;
      return json(res, r);
    }

    if (method === 'PATCH') {
      if (!checkRateLimit(ip, 'api')) return err(res, 'Too many requests', 429);
      const me = await getUser(req);
      if (!me) return err(res, 'Not authenticated', 401);
      let body; try { body = await parseBody(req); } catch { return err(res, 'Invalid request', 400); }
      const { name } = body;
      const team = await col.teams.findOne({ id: teamId, ownerId: me.id });
      if (!team) return err(res, 'Team not found or not owner', 404);
      if (name && name.length >= 1 && name.length <= 50) {
        await col.teams.updateOne({ id: teamId }, { $set: { name: sanitizeText(name, 50) } });
      }
      const updated = await col.teams.findOne({ id: teamId });
      const r = {...updated}; delete r._id;
      return json(res, r);
    }

    if (method === 'DELETE') {
      if (!checkRateLimit(ip, 'api')) return err(res, 'Too many requests', 429);
      const me = await getUser(req);
      if (!me) return err(res, 'Not authenticated', 401);
      const team = await col.teams.findOne({ id: teamId, ownerId: me.id });
      if (!team) return err(res, 'Team not found or not owner', 404);
      await col.teams.deleteOne({ id: teamId });
      await col.teamMessages.deleteMany({ teamId });
      return json(res, { ok: true });
    }
  }

  if (pathname.startsWith('/api/teams/') && method === 'POST') {
    const parts = pathname.split('/');
    if (parts.length === 4 && parts[3] === 'invite') {
      if (!checkRateLimit(ip, 'api')) return err(res, 'Too many requests', 429);
      const me = await getUser(req);
      if (!me) return err(res, 'Not authenticated', 401);
      let body; try { body = await parseBody(req); } catch { return err(res, 'Invalid request', 400); }
      const { teamId, userId } = body;
      const team = await col.teams.findOne({ id: teamId, ownerId: me.id });
      if (!team) return err(res, 'Team not found or not owner', 404);
      if (team.members.length >= 20) return err(res, 'Team member limit reached (20 max)');
      if (team.members.includes(userId)) return err(res, 'User already in team');
      const user = await col.users.findOne({ id: userId });
      if (!user) return err(res, 'User not found', 404);
      await col.teams.updateOne({ id: teamId }, { $push: { members: userId } });
      return json(res, { ok: true });
    }

    if (parts.length === 4 && parts[3] === 'leave') {
      if (!checkRateLimit(ip, 'api')) return err(res, 'Too many requests', 429);
      const me = await getUser(req);
      if (!me) return err(res, 'Not authenticated', 401);
      let body; try { body = await parseBody(req); } catch { return err(res, 'Invalid request', 400); }
      const { teamId } = body;
      const team = await col.teams.findOne({ id: teamId, members: me.id });
      if (!team) return err(res, 'Team not found', 404);
      if (team.ownerId === me.id) return err(res, 'Owner cannot leave team, delete instead');
      await col.teams.updateOne({ id: teamId }, { $pull: { members: me.id } });
      return json(res, { ok: true });
    }

    if (parts.length === 4 && parts[3] === 'messages') {
      if (!checkRateLimit(ip, 'api')) return err(res, 'Too many requests', 429);
      const me = await getUser(req);
      if (!me) return err(res, 'Not authenticated', 401);
      let body; try { body = await parseBody(req); } catch { return err(res, 'Invalid request', 400); }
      const { teamId, text } = body;
      if (!text || text.length > 500) return err(res, 'Message text required (max 500 chars)');
      const team = await col.teams.findOne({ id: teamId, members: me.id });
      if (!team) return err(res, 'Team not found', 404);

      const message = {
        id:       uid(),
        teamId,
        userId:   me.id,
        text:     sanitizeText(text, 500),
        created:  Date.now(),
      };
      await col.teamMessages.insertOne(message);
      const r = {...message}; delete r._id;
      return json(res, r);
    }
  }

  if (pathname.startsWith('/api/teams/') && method === 'GET') {
    const parts = pathname.split('/');
    if (parts.length === 4 && parts[3] === 'messages') {
      if (!checkRateLimit(ip, 'api')) return err(res, 'Too many requests', 429);
      const me = await getUser(req);
      if (!me) return err(res, 'Not authenticated', 401);
      const teamId = parts[2];
      const team = await col.teams.findOne({ id: teamId, members: me.id });
      if (!team) return err(res, 'Team not found', 404);
      const messages = await col.teamMessages.find({ teamId }).sort({ created: 1 }).limit(100).toArray();
      const messagesSafe = messages.map(m => { const r = {...m}; delete r._id; return r; });
      return json(res, messagesSafe);
    }
  }

  // ─── ADMIN ──────────────────────────────────────────────────────────────────
  if (pathname.startsWith('/admin/')) {
    if (!checkRateLimit(ip, 'admin')) return err(res, 'Too many requests', 429);
    const adminToken = req.headers['x-admin-token'] || '';
    try {
      if (!adminToken || !crypto.timingSafeEqual(Buffer.from(adminToken.padEnd(64)), Buffer.from(ADMIN_TOKEN.padEnd(64))))
        return err(res, 'Unauthorized', 401);
    } catch { return err(res, 'Unauthorized', 401); }

    if (pathname === '/admin/stats' && method === 'GET') {
      const users    = await col.users.find({}).toArray();
      const allTasks = await col.tasks.find({}).toArray();
      const todayStr = today();
      let friendshipCount = 0, pendingCount = 0;
      const allFriends = await col.friends.find({}).toArray();
      allFriends.forEach(fd => { friendshipCount += fd.friends.length; pendingCount += fd.sent.length; });
      friendshipCount = Math.round(friendshipCount / 2);

      const userStats  = await Promise.all(users.map(u => userStatsObject(u)));
      const days14     = getLastNDays(14);
      const dailyStats = days14.map(d => {
        const dayTasks    = allTasks.filter(t => t.date === d);
        const done        = dayTasks.filter(t => t.done).length;
        const activeUsers = users.filter(u => allTasks.some(t => t.userId === u.id && t.date === d)).length;
        return { date: d, tasks: dayTasks.length, done, activeUsers, completion: dayTasks.length ? Math.round(done / dayTasks.length * 100) : 0 };
      });

      const tasksByUser = {};
      allTasks.forEach(t => { if (!tasksByUser[t.userId]) tasksByUser[t.userId] = []; tasksByUser[t.userId].push(t); });
      const habits   = await col.habits.find({}).toArray();
      const sessions = await col.sessions.countDocuments({});

      const friendships = (() => {
        const list = [], pending = [];
        allFriends.forEach(fd => {
          fd.friends.forEach(fid => {
            if (fd.userId < fid) {
              const a = users.find(u => u.id === fd.userId);
              const b = users.find(u => u.id === fid);
              if (a && b) list.push({ a: { id:a.id,username:a.username,avatar:a.avatar,color:a.color }, b: { id:b.id,username:b.username,avatar:b.avatar,color:b.color } });
            }
          });
          fd.sent.forEach(tid => {
            const a = users.find(u => u.id === fd.userId);
            const b = users.find(u => u.id === tid);
            if (a && b) pending.push({ from:{id:a.id,username:a.username,avatar:a.avatar}, to:{id:b.id,username:b.username,avatar:b.avatar} });
          });
        });
        return { list, pending };
      })();

      return json(res, {
        stats: {
          totalUsers:      users.length,
          totalTasks:      allTasks.length,
          doneTasks:       allTasks.filter(t => t.done).length,
          todayTasks:      allTasks.filter(t => t.date === todayStr).length,
          todayDone:       allTasks.filter(t => t.date === todayStr && t.done).length,
          totalHabits:     habits.length,
          activeToday:     users.filter(u => u.lastSeen?.startsWith(todayStr)).length,
          activeSessions:  sessions,
          friendshipCount, pendingRequests: pendingCount,
          avgScore:  userStats.length ? Math.round(userStats.reduce((s,u)=>s+u.score,0)/userStats.length) : 0,
          avgStreak: userStats.length ? Math.round(userStats.reduce((s,u)=>s+u.streak,0)/userStats.length) : 0,
        },
        users: userStats,
        full:  { tasks: tasksByUser, habits, habitLog: {} },
        friendships,
        dailyStats,
      });
    }

    if (pathname === '/admin/users' && method === 'GET') {
      const users = await col.users.find({}).toArray();
      return json(res, await Promise.all(users.map(u => userStatsObject(u))));
    }

    const adminUserMatch = pathname.match(/^\/admin\/users\/([a-f0-9]{24})$/);
    if (adminUserMatch) {
      const id   = adminUserMatch[1];
      const user = await col.users.findOne({ id });
      if (method === 'PATCH') {
        let body; try { body = await parseBody(req); } catch { return err(res, 'Invalid request', 400); }
        if (!user) return err(res, 'User not found', 404);
        const updates = {};
        if (body.username && isValidUsername(body.username)) { updates.username = body.username.trim(); updates.usernameLower = body.username.trim().toLowerCase(); }
        if (body.avatar) updates.avatar = sanitizeText(body.avatar, 8);
        if (Object.keys(updates).length) await col.users.updateOne({ id }, { $set: updates });
        return json(res, { ok: true });
      }
      if (method === 'DELETE') {
        await col.users.deleteOne({ id });
        await col.tasks.deleteMany({ userId: id });
        await col.habits.deleteMany({ userId: id });
        await col.habitLog.deleteMany({ userId: id });
        await col.friends.deleteOne({ userId: id });
        await col.sessions.deleteMany({ userId: id });
        await col.friends.updateMany({}, { $pull: { friends: id, sent: id, received: id } });
        return json(res, { ok: true });
      }
    }
    return err(res, 'Not found', 404);
  }

  res.writeHead(404); res.end('Not found');
});

// ─── START ────────────────────────────────────────────────────────────────────
connectDB().then(() => {
  server.listen(PORT, () => {
    console.log(`\n🚀 We Track → http://localhost:${PORT}`);
    console.log(`   Admin    → http://localhost:${PORT}/admin.html\n`);
  });
}).catch(e => {
  console.error('Failed to connect to MongoDB:', e.message);
  process.exit(1);
});
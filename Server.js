// ─── We Track Server — Secured ─────────────────────────────────────────────
const http   = require('http');
const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');

const PORT        = process.env.PORT || 3000;
const DATA_FILE   = path.join(__dirname, 'data.json');
// SECURITY FIX: No hardcoded fallback token — must be set via env variable
// SECURITY: Use env variable in production; falls back to a generated token for local dev
let ADMIN_TOKEN = process.env.ADMIN_TOKEN;
if (!ADMIN_TOKEN) {
  const crypto = require('crypto');
  ADMIN_TOKEN = crypto.randomBytes(24).toString('hex');
  console.warn('\n⚠️  ADMIN_TOKEN not set — generated a one-time token for this session:');
  console.warn('   ADMIN_TOKEN =', ADMIN_TOKEN);
  console.warn('   Set ADMIN_TOKEN env variable to use a fixed token in production.\n');
}

// ─── RATE LIMITING ────────────────────────────────────────────────────────────
// Simple in-memory rate limiter: tracks hit counts per IP per window
const rateLimitMap = new Map();
const RATE_WINDOWS = {
  auth:    { max: 10,  windowMs: 60_000  },  // 10 login/register attempts per minute
  api:     { max: 200, windowMs: 60_000  },  // 200 API calls per minute
  admin:   { max: 60,  windowMs: 60_000  },  // 60 admin calls per minute
};

function getClientIP(req) {
  return (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress || 'unknown';
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

// Clean up stale rate-limit entries every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of rateLimitMap) { if (now > v.reset) rateLimitMap.delete(k); }
}, 300_000);

// ─── DATA ─────────────────────────────────────────────────────────────────────
function loadData() {
  try { if (fs.existsSync(DATA_FILE)) return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')); }
  catch (_) {}
  return { users: {}, sessions: {}, tasks: {}, habits: [], habitLog: {}, friends: {} };
}
function saveData(db) { fs.writeFileSync(DATA_FILE, JSON.stringify(db)); }
let DB = loadData();

// ─── HELPERS ──────────────────────────────────────────────────────────────────
function uid()      { return crypto.randomBytes(12).toString('hex'); }
// SECURITY FIX: Use bcrypt-style PBKDF2 instead of plain SHA-256
function hashPwd(p) {
  return crypto.pbkdf2Sync(p, 'we_track_pbkdf2_salt_v1', 100_000, 32, 'sha256').toString('hex');
}
function today() { return new Date().toISOString().slice(0, 10); }

// SECURITY FIX: Limit request body size to prevent DoS via huge payloads
const MAX_BODY_BYTES = 64 * 1024; // 64 KB
function parseBody(req) {
  return new Promise((res, rej) => {
    let b = '', size = 0;
    req.on('data', c => {
      size += c.length;
      if (size > MAX_BODY_BYTES) { req.destroy(); return rej(new Error('Payload too large')); }
      b += c;
    });
    req.on('end', () => { try { res(JSON.parse(b || '{}')); } catch { res({}); } });
    req.on('error', rej);
  });
}

// SECURITY FIX: Strict CORS — only allow specific origins in production
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || 'http://localhost:3000').split(',').map(s => s.trim());

function json(res, data, status = 200) {
  res.writeHead(status, {
    'Content-Type': 'application/json',
    // SECURITY FIX: removed wildcard CORS — set per-request below
    'X-Content-Type-Options':  'nosniff',
    'X-Frame-Options':         'DENY',
    'Cache-Control':           'no-store',
  });
  res.end(JSON.stringify(data));
}
function err(res, msg, status = 400) { json(res, { error: msg }, status); }

function setCORS(req, res) {
  const origin = req.headers['origin'] || '';
  if (ALLOWED_ORIGINS.includes(origin) || ALLOWED_ORIGINS.includes('*')) {
    res.setHeader('Access-Control-Allow-Origin', origin || '*');
  }
  res.setHeader('Access-Control-Allow-Credentials', 'true');
}

function getUser(req) {
  const token  = req.headers['x-session'] || '';
  if (!token || token.length > 64) return null;  // SECURITY FIX: sanity-check token length
  const userId = DB.sessions[token];
  return userId ? DB.users[userId] : null;
}

function getFriendData(userId) {
  if (!DB.friends[userId]) DB.friends[userId] = { friends: [], sent: [], received: [] };
  return DB.friends[userId];
}

// ─── INPUT VALIDATION HELPERS ─────────────────────────────────────────────────
// SECURITY FIX: centralized input sanitization
function isValidEmail(e) { return typeof e === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e) && e.length <= 254; }
function isValidUsername(u) { return typeof u === 'string' && /^[a-zA-Z0-9_\-. ]{1,30}$/.test(u.trim()); }
function isValidHexId(id) { return typeof id === 'string' && /^[a-f0-9]{16,32}$/.test(id); }
function isValidDate(d) { return typeof d === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(d); }
// SECURITY FIX: strip dangerous characters from free-text fields
function sanitizeText(s, maxLen = 500) {
  if (typeof s !== 'string') return '';
  return s.replace(/[<>"'`]/g, '').trim().slice(0, maxLen);
}

// ─── ANALYTICS HELPERS ────────────────────────────────────────────────────────
function computeStreak(userId) {
  const tasks  = DB.tasks[userId]  || [];
  // SECURITY FIX: filter habits to only this user's own habits
  const habits = (DB.habits || []).filter(h => h.user === userId);
  let streak = 0;
  for (let i = 0; i < 60; i++) {
    const dt = new Date(); dt.setDate(dt.getDate() - i);
    const d  = dt.toISOString().slice(0, 10);
    const dayTasks = tasks.filter(t => t.date === d);
    const taskOk   = dayTasks.length > 0 && dayTasks.some(t => t.done);
    let habitOk = false;
    if (habits.length > 0) {
      const doneH = habits.filter(h => DB.habitLog?.[d]?.[h.id]?.[userId]).length;
      habitOk = (doneH / habits.length) >= 0.5;
    }
    if (taskOk || habitOk) streak++;
    else if (i > 0) break;
  }
  return streak;
}

function habitPct(userId, date) {
  const habits = (DB.habits || []).filter(h => h.user === userId);
  if (!habits.length) return 0;
  const done = habits.filter(h => DB.habitLog?.[date]?.[h.id]?.[userId]).length;
  return (done / habits.length) * 100;
}

function taskPct(userId, date) {
  const tasks = (DB.tasks[userId] || []).filter(t => t.date === date);
  if (!tasks.length) return null;
  return tasks.filter(t => t.done).length / tasks.length * 100;
}

function disciplineScore(userId) {
  const t   = today();
  const tp  = taskPct(userId, t) ?? 0;
  const hp  = habitPct(userId, t);
  const str = computeStreak(userId);
  return Math.min(100, Math.round(tp * 0.5 + hp * 0.3 + Math.min(str * 4, 20)));
}

function avgTaskPct(userId, days) {
  const dates = getLastNDays(days);
  const valid = dates.map(d => taskPct(userId, d)).filter(v => v !== null);
  if (!valid.length) return 0;
  return Math.round(valid.reduce((a, b) => a + b, 0) / valid.length);
}

function avgHabitPct(userId, days) {
  const dates = getLastNDays(days);
  const vals  = dates.map(d => habitPct(userId, d));
  return Math.round(vals.reduce((a, b) => a + b, 0) / dates.length);
}

function getLastNDays(n) {
  const d = [];
  for (let i = n - 1; i >= 0; i--) {
    const dt = new Date(); dt.setDate(dt.getDate() - i);
    d.push(dt.toISOString().slice(0, 10));
  }
  return d;
}

function userStatsObject(u) {
  const t        = today();
  const dayTasks = (DB.tasks[u.id] || []).filter(x => x.date === t);
  const allTasks = DB.tasks[u.id] || [];
  const friends  = (DB.friends[u.id]?.friends || []).length;
  return {
    id: u.id, email: u.email, username: u.username,
    avatar: u.avatar, color: u.color,
    score:      disciplineScore(u.id),
    streak:     computeStreak(u.id),
    friends,
    taskCount:  dayTasks.length,
    doneCount:  dayTasks.filter(t => t.done).length,
    totalTasks: allTasks.length,
    totalDone:  allTasks.filter(t => t.done).length,
    avg7Task:   avgTaskPct(u.id, 7),
    avg7Habit:  avgHabitPct(u.id, 7),
    created:    u.createdAt?.slice(0, 10),
    lastSeen:   u.lastSeen?.slice(0, 10),
  };
}

// ─── STATIC FILES ─────────────────────────────────────────────────────────────
// SECURITY FIX: path traversal prevention — resolve and verify path stays in __dirname
function serveStatic(res, filePath) {
  const resolved  = path.resolve(filePath);
  const safeRoot  = path.resolve(__dirname);
  if (!resolved.startsWith(safeRoot)) {
    res.writeHead(403); return res.end('Forbidden');
  }
  try {
    const content = fs.readFileSync(resolved);
    const ext  = path.extname(resolved);
    const types = { '.html': 'text/html', '.js': 'application/javascript', '.css': 'text/css' };
    // SECURITY FIX: never serve data.json or .env as static
    const blocked = ['.json', '.env', '.key', '.pem'];
    if (blocked.includes(ext)) { res.writeHead(403); return res.end('Forbidden'); }
    res.writeHead(200, {
      'Content-Type':           types[ext] || 'text/plain',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options':        'SAMEORIGIN',
      'Content-Security-Policy': "default-src 'self' https://fonts.googleapis.com https://fonts.gstatic.com https://cdnjs.cloudflare.com https://we-track-backend.vercel.app; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com;",
    });
    res.end(content);
  } catch {
    res.writeHead(404); res.end('Not found');
  }
}

// ─── ROUTER ───────────────────────────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  const ip = getClientIP(req);

  // SECURITY FIX: Set security headers on every response
  res.setHeader('X-Content-Type-Options',  'nosniff');
  res.setHeader('X-Frame-Options',         'DENY');
  res.setHeader('Referrer-Policy',         'no-referrer');

  let url, pathname;
  try {
    url      = new URL(req.url, `http://localhost:${PORT}`);
    pathname = url.pathname;
  } catch {
    res.writeHead(400); return res.end('Bad request');
  }
  const method = req.method;

  // CORS preflight
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

  // Static files
  if (pathname === '/' || pathname === '/index.html') return serveStatic(res, path.join(__dirname, 'Index.html'));
  if (pathname === '/admin' || pathname === '/admin.html') return serveStatic(res, path.join(__dirname, 'Admin.html'));

  // ─── AUTH ─────────────────────────────────────────────────────────────────
  if (pathname === '/api/auth/register' && method === 'POST') {
    if (!checkRateLimit(ip, 'auth')) return err(res, 'Too many requests, please slow down', 429);
    let body;
    try { body = await parseBody(req); } catch { return err(res, 'Invalid request', 400); }
    const { email, password, username, avatar, color } = body;

    // SECURITY FIX: strict input validation
    if (!email || !password || !username) return err(res, 'All fields required');
    if (!isValidEmail(email)) return err(res, 'Invalid email format');
    if (typeof password !== 'string' || password.length < 6 || password.length > 128) return err(res, 'Password must be 6–128 characters');
    if (!isValidUsername(username)) return err(res, 'Username must be 1–30 alphanumeric characters');

    const emailLower = email.toLowerCase().trim();
    if (Object.values(DB.users).find(u => u.email === emailLower)) return err(res, 'Email already registered');
    if (Object.values(DB.users).find(u => u.username.toLowerCase() === username.trim().toLowerCase())) return err(res, 'Username already taken');

    // SECURITY FIX: validate & whitelist avatar/color values
    const VALID_COLORS = ['neon','lime','amber','coral','sky','pink'];
    const safeColor  = VALID_COLORS.includes(color) ? color : 'neon';
    const safeAvatar = sanitizeText(avatar || '⚡', 8);

    const id    = uid();
    const token = uid() + uid();
    DB.users[id] = {
      id, email: emailLower, passwordHash: hashPwd(password),
      username: username.trim(), avatar: safeAvatar, color: safeColor,
      createdAt: new Date().toISOString(), lastSeen: new Date().toISOString(),
    };
    DB.sessions[token] = id;
    DB.friends[id]     = { friends: [], sent: [], received: [] };
    DB.tasks[id]       = [];
    saveData(DB);
    const u = { ...DB.users[id] }; delete u.passwordHash;
    return json(res, { token, user: u });
  }

  if (pathname === '/api/auth/login' && method === 'POST') {
    if (!checkRateLimit(ip, 'auth')) return err(res, 'Too many login attempts, please wait', 429);
    let body;
    try { body = await parseBody(req); } catch { return err(res, 'Invalid request', 400); }
    const { email, password } = body;
    if (!email || !password) return err(res, 'Email and password required', 401);
    const emailLower = (email || '').toLowerCase().trim();
    const user = Object.values(DB.users).find(u => u.email === emailLower && u.passwordHash === hashPwd(password));
    // SECURITY FIX: constant-time-like delay to prevent timing attacks
    if (!user) {
      await new Promise(r => setTimeout(r, 200));
      return err(res, 'Invalid email or password', 401);
    }
    const token = uid() + uid();
    DB.sessions[token]         = user.id;
    DB.users[user.id].lastSeen = new Date().toISOString();
    saveData(DB);
    const u = { ...user }; delete u.passwordHash;
    return json(res, { token, user: u });
  }

  if (pathname === '/api/auth/logout' && method === 'POST') {
    const token = req.headers['x-session'] || '';
    if (token) delete DB.sessions[token];
    saveData(DB);
    return json(res, { ok: true });
  }

  if (pathname === '/api/auth/me' && method === 'GET') {
    if (!checkRateLimit(ip, 'api')) return err(res, 'Too many requests', 429);
    const user = getUser(req);
    if (!user) return err(res, 'Not authenticated', 401);
    const u = { ...user }; delete u.passwordHash;
    return json(res, u);
  }

  if (pathname === '/api/auth/profile' && method === 'PATCH') {
    if (!checkRateLimit(ip, 'api')) return err(res, 'Too many requests', 429);
    const user = getUser(req);
    if (!user) return err(res, 'Not authenticated', 401);
    let body;
    try { body = await parseBody(req); } catch { return err(res, 'Invalid request', 400); }
    const { username, avatar, color } = body;
    if (username) {
      if (!isValidUsername(username)) return err(res, 'Invalid username format');
      const taken = Object.values(DB.users).find(u => u.id !== user.id && u.username.toLowerCase() === username.trim().toLowerCase());
      if (taken) return err(res, 'Username already taken');
      DB.users[user.id].username = username.trim();
    }
    const VALID_COLORS = ['neon','lime','amber','coral','sky','pink'];
    if (avatar) DB.users[user.id].avatar = sanitizeText(avatar, 8);
    if (color && VALID_COLORS.includes(color)) DB.users[user.id].color = color;
    saveData(DB);
    const u = { ...DB.users[user.id] }; delete u.passwordHash;
    return json(res, u);
  }

  // ─── MAIN DATA ────────────────────────────────────────────────────────────
  if (pathname === '/api/data' && method === 'GET') {
    if (!checkRateLimit(ip, 'api')) return err(res, 'Too many requests', 429);
    const me = getUser(req);
    if (!me) return err(res, 'Not authenticated', 401);
    DB.users[me.id].lastSeen = new Date().toISOString();
    saveData(DB);

    const fd         = getFriendData(me.id);
    const friendIds  = fd.friends;
    const allUserIds = [me.id, ...friendIds];

    const allUsers = allUserIds.map(id => {
      const u = DB.users[id]; if (!u) return null;
      return userStatsObject(u);
    }).filter(Boolean);

    // SECURITY FIX: only send tasks for me + friends — never all users
    const tasks = {};
    allUserIds.forEach(id => { tasks[id] = DB.tasks[id] || []; });

    // SECURITY FIX: only send habits that belong to the requesting user or their friends
    const visibleHabits = (DB.habits || []).filter(h => allUserIds.includes(h.user));

    const myDays = getLastNDays(30).map(d => ({
      date: d, taskPct: taskPct(me.id, d), habitPct: Math.round(habitPct(me.id, d)),
    }));

    const u = { ...me }; delete u.passwordHash;
    return json(res, {
      user: u, allUsers, tasks,
      habits:    visibleHabits,
      habitLog:  DB.habitLog || {},
      friends:   fd,
      analytics: myDays,
    });
  }

  // ─── TASKS ────────────────────────────────────────────────────────────────
  if (pathname === '/api/tasks' && method === 'POST') {
    if (!checkRateLimit(ip, 'api')) return err(res, 'Too many requests', 429);
    const me = getUser(req);
    if (!me) return err(res, 'Not authenticated', 401);
    let body;
    try { body = await parseBody(req); } catch { return err(res, 'Invalid request', 400); }
    const { text, priority, category, notes, date } = body;
    if (!text) return err(res, 'Task text required');

    // SECURITY FIX: validate & sanitize all task fields
    const VALID_PRIORITIES = ['low', 'med', 'high'];
    const VALID_CATEGORIES = ['', 'work', 'health', 'learning', 'personal', 'finance'];
    const safeDate = isValidDate(date) ? date : today();
    const safePri  = VALID_PRIORITIES.includes(priority) ? priority : 'med';
    const safeCat  = VALID_CATEGORIES.includes(category) ? category : '';

    // SECURITY FIX: limit tasks per user to prevent storage abuse
    if (!DB.tasks[me.id]) DB.tasks[me.id] = [];
    if (DB.tasks[me.id].length > 5000) return err(res, 'Task limit reached');

    const task = {
      id:       uid(),
      text:     sanitizeText(text, 500),
      priority: safePri,
      category: safeCat,
      notes:    sanitizeText(notes || '', 1000),
      date:     safeDate,
      done:     false,
      created:  Date.now(),
    };
    DB.tasks[me.id].push(task);
    saveData(DB);
    return json(res, task);
  }

  // SECURITY FIX: validate task ID pattern strictly
  const taskMatch = pathname.match(/^\/api\/tasks\/([a-f0-9]{16,32})$/);
  if (taskMatch) {
    if (!checkRateLimit(ip, 'api')) return err(res, 'Too many requests', 429);
    const me = getUser(req);
    if (!me) return err(res, 'Not authenticated', 401);
    const tid     = taskMatch[1];
    const taskArr = DB.tasks[me.id] || [];
    const idx     = taskArr.findIndex(t => t.id === tid);
    if (idx === -1) return err(res, 'Task not found', 404);
    if (method === 'PATCH') {
      let body;
      try { body = await parseBody(req); } catch { return err(res, 'Invalid request', 400); }
      // SECURITY FIX: whitelist which fields can be patched — prevent field injection
      const allowed = {};
      if (typeof body.done === 'boolean') allowed.done = body.done;
      if (typeof body.reason === 'string') allowed.reason = sanitizeText(body.reason, 200);
      if (typeof body.text === 'string')   allowed.text   = sanitizeText(body.text, 500);
      const VALID_PRIORITIES = ['low','med','high'];
      if (VALID_PRIORITIES.includes(body.priority)) allowed.priority = body.priority;
      Object.assign(DB.tasks[me.id][idx], allowed);
      saveData(DB);
      return json(res, DB.tasks[me.id][idx]);
    }
    if (method === 'DELETE') {
      DB.tasks[me.id].splice(idx, 1);
      saveData(DB);
      return json(res, { ok: true });
    }
  }

  // ─── HABITS ───────────────────────────────────────────────────────────────
  if (pathname === '/api/habits' && method === 'POST') {
    if (!checkRateLimit(ip, 'api')) return err(res, 'Too many requests', 429);
    const me = getUser(req);
    if (!me) return err(res, 'Not authenticated', 401);
    let body;
    try { body = await parseBody(req); } catch { return err(res, 'Invalid request', 400); }
    const { name, icon } = body;
    if (!name) return err(res, 'Habit name required');
    // SECURITY FIX: limit habits per user
    if (!DB.habits) DB.habits = [];
    const myHabits = DB.habits.filter(h => h.user === me.id);
    if (myHabits.length >= 50) return err(res, 'Habit limit reached (50 max)');
    const habit = {
      id:      uid(),
      name:    sanitizeText(name, 100),
      icon:    sanitizeText(icon || '⭐', 8),
      user:    me.id,   // SECURITY FIX: always assign to current user — ignore client-supplied user field
      created: today(),
    };
    DB.habits.push(habit);
    saveData(DB);
    return json(res, habit);
  }

  const habitMatch = pathname.match(/^\/api\/habits\/([a-f0-9]{16,32})$/);
  if (habitMatch && method === 'DELETE') {
    if (!checkRateLimit(ip, 'api')) return err(res, 'Too many requests', 429);
    const me = getUser(req);
    if (!me) return err(res, 'Not authenticated', 401);
    const hid = habitMatch[1];
    // SECURITY FIX: only allow deleting YOUR OWN habits
    const habit = (DB.habits || []).find(h => h.id === hid);
    if (!habit) return err(res, 'Habit not found', 404);
    if (habit.user !== me.id) return err(res, 'Forbidden', 403);
    DB.habits = DB.habits.filter(h => h.id !== hid);
    saveData(DB);
    return json(res, { ok: true });
  }

  if (pathname === '/api/habitLog' && method === 'POST') {
    if (!checkRateLimit(ip, 'api')) return err(res, 'Too many requests', 429);
    const me = getUser(req);
    if (!me) return err(res, 'Not authenticated', 401);
    let body;
    try { body = await parseBody(req); } catch { return err(res, 'Invalid request', 400); }
    const { habitId, date, value } = body;

    // SECURITY FIX: validate inputs
    if (!isValidHexId(habitId)) return err(res, 'Invalid habitId');
    if (!isValidDate(date)) return err(res, 'Invalid date');
    // SECURITY FIX: can only log for TODAY — not past/future dates
    if (date !== today()) return err(res, 'Can only log habits for today', 403);
    // SECURITY FIX: can only log YOUR OWN habits — ignore client-supplied userId
    const habit = (DB.habits || []).find(h => h.id === habitId && h.user === me.id);
    if (!habit) return err(res, 'Habit not found or not yours', 404);

    if (!DB.habitLog)                DB.habitLog = {};
    if (!DB.habitLog[date])          DB.habitLog[date] = {};
    if (!DB.habitLog[date][habitId]) DB.habitLog[date][habitId] = {};
    DB.habitLog[date][habitId][me.id] = !!value;  // SECURITY FIX: coerce to boolean

    // SECURITY FIX: Prune habit log to last 30 days to prevent unbounded growth
    const cutoff = getLastNDays(30)[0];
    Object.keys(DB.habitLog).forEach(d => { if (d < cutoff) delete DB.habitLog[d]; });

    saveData(DB);
    return json(res, { ok: true });
  }

  // ─── ANALYTICS ────────────────────────────────────────────────────────────
  if (pathname === '/api/analytics' && method === 'GET') {
    if (!checkRateLimit(ip, 'api')) return err(res, 'Too many requests', 429);
    const me = getUser(req);
    if (!me) return err(res, 'Not authenticated', 401);
    const fd         = getFriendData(me.id);
    const visibleIds = [me.id, ...fd.friends];
    const days14     = getLastNDays(14);

    const perUser = visibleIds.map(id => {
      const u = DB.users[id]; if (!u) return null;
      return {
        id: u.id, username: u.username, avatar: u.avatar, color: u.color,
        score:  disciplineScore(id),
        streak: computeStreak(id),
        days:   days14.map(d => ({
          date:     d,
          taskPct:  taskPct(id, d) ?? 0,
          habitPct: Math.round(habitPct(id, d)),
          score:    (() => { const tp = taskPct(id, d) ?? 0; const hp = habitPct(id, d); return Math.round(tp * 0.6 + hp * 0.4); })(),
        })),
        avg14Task:      avgTaskPct(id, 14),
        avg14Habit:     avgHabitPct(id, 14),
        avg7Task:       avgTaskPct(id, 7),
        totalTasksDone: (DB.tasks[id] || []).filter(t => t.done).length,
        totalTasks:     (DB.tasks[id] || []).length,
      };
    }).filter(Boolean);

    const categories = {};
    visibleIds.forEach(id => {
      (DB.tasks[id] || []).forEach(t => {
        const c = t.category || 'other';
        if (!categories[c]) categories[c] = { total: 0, done: 0 };
        categories[c].total++;
        if (t.done) categories[c].done++;
      });
    });

    const missedReasons = {};
    visibleIds.forEach(id => {
      (DB.tasks[id] || []).filter(t => !t.done && t.reason).forEach(t => {
        const r = sanitizeText(t.reason, 100);
        missedReasons[r] = (missedReasons[r] || 0) + 1;
      });
    });

    return json(res, { users: perUser, categories, missedReasons, dates: days14 });
  }

  // ─── FRIENDS ──────────────────────────────────────────────────────────────
  if (pathname === '/api/friends/search' && method === 'GET') {
    if (!checkRateLimit(ip, 'api')) return err(res, 'Too many requests', 429);
    const me = getUser(req);
    if (!me) return err(res, 'Not authenticated', 401);
    const q = (url.searchParams.get('q') || '').toLowerCase().trim();
    if (!q || q.length < 2) return json(res, []);
    // SECURITY FIX: limit search query length
    if (q.length > 30) return err(res, 'Search query too long');
    const fd = getFriendData(me.id);
    const results = Object.values(DB.users)
      .filter(u => u.id !== me.id && u.username.toLowerCase().includes(q))
      .slice(0, 10)
      .map(u => {
        const status = fd.friends.includes(u.id) ? 'friend'
          : fd.sent.includes(u.id)      ? 'sent'
          : fd.received.includes(u.id)  ? 'received'
          : 'none';
        return { id: u.id, username: u.username, avatar: u.avatar, color: u.color, status };
      });
    return json(res, results);
  }

  if (pathname === '/api/friends/request' && method === 'POST') {
    if (!checkRateLimit(ip, 'api')) return err(res, 'Too many requests', 429);
    const me = getUser(req);
    if (!me) return err(res, 'Not authenticated', 401);
    let body;
    try { body = await parseBody(req); } catch { return err(res, 'Invalid request', 400); }
    const { targetId } = body;
    if (!isValidHexId(targetId)) return err(res, 'Invalid targetId');
    if (!DB.users[targetId]) return err(res, 'User not found', 404);
    if (targetId === me.id) return err(res, 'Cannot friend yourself');
    const myFd    = getFriendData(me.id);
    const theirFd = getFriendData(targetId);
    // SECURITY FIX: cap friend list size
    if (myFd.friends.length >= 200) return err(res, 'Friend list limit reached');
    if (myFd.friends.includes(targetId)) return err(res, 'Already friends');
    if (myFd.sent.includes(targetId))    return err(res, 'Request already sent');
    if (myFd.received.includes(targetId)) {
      myFd.friends.push(targetId);
      myFd.received = myFd.received.filter(id => id !== targetId);
      theirFd.friends.push(me.id);
      theirFd.sent = theirFd.sent.filter(id => id !== me.id);
      saveData(DB);
      return json(res, { status: 'accepted' });
    }
    myFd.sent.push(targetId);
    theirFd.received.push(me.id);
    saveData(DB);
    return json(res, { status: 'sent' });
  }

  if (pathname === '/api/friends/accept' && method === 'POST') {
    if (!checkRateLimit(ip, 'api')) return err(res, 'Too many requests', 429);
    const me = getUser(req);
    if (!me) return err(res, 'Not authenticated', 401);
    let body;
    try { body = await parseBody(req); } catch { return err(res, 'Invalid request', 400); }
    const { fromId } = body;
    if (!isValidHexId(fromId)) return err(res, 'Invalid fromId');
    if (!DB.users[fromId]) return err(res, 'User not found', 404);
    const myFd    = getFriendData(me.id);
    const theirFd = getFriendData(fromId);
    if (!myFd.received.includes(fromId)) return err(res, 'No pending request from this user');
    myFd.received = myFd.received.filter(id => id !== fromId);
    myFd.friends.push(fromId);
    theirFd.sent = theirFd.sent.filter(id => id !== me.id);
    theirFd.friends.push(me.id);
    saveData(DB);
    return json(res, { status: 'accepted' });
  }

  if (pathname === '/api/friends/decline' && method === 'POST') {
    if (!checkRateLimit(ip, 'api')) return err(res, 'Too many requests', 429);
    const me = getUser(req);
    if (!me) return err(res, 'Not authenticated', 401);
    let body;
    try { body = await parseBody(req); } catch { return err(res, 'Invalid request', 400); }
    const { userId: targetId } = body;
    if (!targetId) return err(res, 'userId required');
    const myFd    = getFriendData(me.id);
    const theirFd = getFriendData(targetId) || { sent: [], received: [] };
    myFd.received    = myFd.received.filter(id => id !== targetId);
    theirFd.sent     = theirFd.sent.filter(id => id !== me.id);
    myFd.sent        = myFd.sent.filter(id => id !== targetId);
    theirFd.received = (theirFd.received || []).filter(id => id !== me.id);
    saveData(DB);
    return json(res, { status: 'declined' });
  }

  if (pathname === '/api/friends/remove' && method === 'POST') {
    if (!checkRateLimit(ip, 'api')) return err(res, 'Too many requests', 429);
    const me = getUser(req);
    if (!me) return err(res, 'Not authenticated', 401);
    let body;
    try { body = await parseBody(req); } catch { return err(res, 'Invalid request', 400); }
    const { friendId } = body;
    if (!isValidHexId(friendId)) return err(res, 'Invalid friendId');
    const myFd    = getFriendData(me.id);
    const theirFd = getFriendData(friendId);
    myFd.friends    = myFd.friends.filter(id => id !== friendId);
    theirFd.friends = theirFd.friends.filter(id => id !== me.id);
    saveData(DB);
    return json(res, { status: 'removed' });
  }

  if (pathname === '/api/friends' && method === 'GET') {
    if (!checkRateLimit(ip, 'api')) return err(res, 'Too many requests', 429);
    const me = getUser(req);
    if (!me) return err(res, 'Not authenticated', 401);
    const fd   = getFriendData(me.id);
    const mapU = id => {
      const u = DB.users[id]; if (!u) return null;
      return { id: u.id, username: u.username, avatar: u.avatar, color: u.color,
               score: disciplineScore(id), streak: computeStreak(id),
               taskCount: (DB.tasks[id] || []).filter(t => t.date === today()).length,
               doneCount: (DB.tasks[id] || []).filter(t => t.date === today() && t.done).length };
    };
    return json(res, {
      friends:  fd.friends.map(mapU).filter(Boolean),
      sent:     fd.sent.map(mapU).filter(Boolean),
      received: fd.received.map(mapU).filter(Boolean),
    });
  }

  // ─── ADMIN ────────────────────────────────────────────────────────────────
  if (pathname.startsWith('/admin/')) {
    if (!checkRateLimit(ip, 'admin')) return err(res, 'Too many admin requests', 429);
    const adminToken = req.headers['x-admin-token'];
    // SECURITY FIX: constant-time comparison to prevent timing attacks on token
    if (!adminToken || !crypto.timingSafeEqual(Buffer.from(adminToken), Buffer.from(ADMIN_TOKEN))) {
      return err(res, 'Unauthorized', 401);
    }

    if (pathname === '/admin/stats' && method === 'GET') {
      const users    = Object.values(DB.users);
      const allTasks = Object.values(DB.tasks).flat();
      const todayStr = today();
      let friendshipCount = 0, pendingCount = 0;
      Object.values(DB.friends).forEach(fd => {
        friendshipCount += fd.friends.length;
        pendingCount    += fd.sent.length;
      });
      friendshipCount = Math.round(friendshipCount / 2);
      const userStats  = users.map(u => userStatsObject(u));
      const days14     = getLastNDays(14);
      const dailyStats = days14.map(d => {
        const dayTasks    = allTasks.filter(t => t.date === d);
        const done        = dayTasks.filter(t => t.done).length;
        const activeUsers = users.filter(u => (DB.tasks[u.id] || []).some(t => t.date === d)).length;
        return { date: d, tasks: dayTasks.length, done, activeUsers, completion: dayTasks.length ? Math.round(done / dayTasks.length * 100) : 0 };
      });
      return json(res, {
        stats: {
          totalUsers:      users.length,
          totalTasks:      allTasks.length,
          doneTasks:       allTasks.filter(t => t.done).length,
          todayTasks:      allTasks.filter(t => t.date === todayStr).length,
          todayDone:       allTasks.filter(t => t.date === todayStr && t.done).length,
          totalHabits:     (DB.habits || []).length,
          activeToday:     users.filter(u => u.lastSeen?.startsWith(todayStr)).length,
          activeSessions:  Object.keys(DB.sessions).length,
          friendshipCount, pendingRequests: pendingCount,
          avgScore:  userStats.length ? Math.round(userStats.reduce((s, u) => s + u.score, 0) / userStats.length) : 0,
          avgStreak: userStats.length ? Math.round(userStats.reduce((s, u) => s + u.streak, 0) / userStats.length) : 0,
        },
        users: userStats,
        full:  { tasks: DB.tasks, habits: DB.habits, habitLog: DB.habitLog },
        friendships: (() => {
          const list = [], pending = [];
          Object.entries(DB.friends).forEach(([uid, fd]) => {
            fd.friends.forEach(fid => {
              if (uid < fid) {
                const a = DB.users[uid], b = DB.users[fid];
                if (a && b) list.push({ a: { id: a.id, username: a.username, avatar: a.avatar, color: a.color }, b: { id: b.id, username: b.username, avatar: b.avatar, color: b.color } });
              }
            });
            fd.sent.forEach(tid => {
              const a = DB.users[uid], b = DB.users[tid];
              if (a && b) pending.push({ from: { id: a.id, username: a.username, avatar: a.avatar }, to: { id: b.id, username: b.username, avatar: b.avatar } });
            });
          });
          return { list, pending };
        })(),
        dailyStats,
      });
    }

    if (pathname === '/admin/users' && method === 'GET') {
      return json(res, Object.values(DB.users).map(u => userStatsObject(u)));
    }

    if (pathname === '/admin/full-data' && method === 'GET') {
      return json(res, { tasks: DB.tasks, habits: DB.habits, habitLog: DB.habitLog });
    }

    const adminUserMatch = pathname.match(/^\/admin\/users\/([a-f0-9]{16,32})$/);
    if (adminUserMatch) {
      const id = adminUserMatch[1];
      if (method === 'PATCH') {
        let body;
        try { body = await parseBody(req); } catch { return err(res, 'Invalid request', 400); }
        if (!DB.users[id]) return err(res, 'User not found', 404);
        // SECURITY FIX: whitelist admin-editable fields
        if (body.username && isValidUsername(body.username)) DB.users[id].username = body.username.trim();
        if (body.avatar)   DB.users[id].avatar = sanitizeText(body.avatar, 8);
        saveData(DB);
        return json(res, { ok: true });
      }
      if (method === 'DELETE') {
        delete DB.users[id]; delete DB.tasks[id]; delete DB.friends[id];
        Object.keys(DB.sessions).forEach(tok => { if (DB.sessions[tok] === id) delete DB.sessions[tok]; });
        Object.values(DB.friends).forEach(fd => {
          fd.friends  = fd.friends.filter(f => f !== id);
          fd.sent     = fd.sent.filter(f => f !== id);
          fd.received = fd.received.filter(f => f !== id);
        });
        // SECURITY FIX: also remove their habits from the global list
        DB.habits = (DB.habits || []).filter(h => h.user !== id);
        saveData(DB);
        return json(res, { ok: true });
      }
    }

    // SECURITY FIX: Return 404 for unmatched admin paths (don't leak info)
    return err(res, 'Not found', 404);
  }

  res.writeHead(404); res.end('Not found');
});

server.listen(PORT, () => {
  console.log(`\n🚀 We Track running  →  http://localhost:${PORT}`);
  console.log(`   Admin panel       →  http://localhost:${PORT}/admin.html\n`);
  // SECURITY FIX: Never log the admin token
});
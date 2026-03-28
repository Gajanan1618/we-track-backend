// ─── We Track Server — Fixed Analytics & Real-time Admin ──────────────────────
const http = require('http');
const fs   = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT       = process.env.PORT || 3000;
const DATA_FILE  = path.join(__dirname, 'data.json');
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || 'flowpact-admin-2024';

// ─── DATA ─────────────────────────────────────────────────────────────────────
function loadData() {
  try { if (fs.existsSync(DATA_FILE)) return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')); }
  catch (_) {}
  return { users: {}, sessions: {}, tasks: {}, habits: [], habitLog: {}, friends: {} };
}
function saveData(db) { fs.writeFileSync(DATA_FILE, JSON.stringify(db, null, 2)); }
let DB = loadData();

// ─── HELPERS ──────────────────────────────────────────────────────────────────
function uid()      { return crypto.randomBytes(8).toString('hex'); }
function hashPwd(p) { return crypto.createHash('sha256').update(p + 'fp_salt_2024').digest('hex'); }
function today()    { return new Date().toISOString().slice(0, 10); }

function parseBody(req) {
  return new Promise((res, rej) => {
    let b = '';
    req.on('data', c => b += c);
    req.on('end', () => { try { res(JSON.parse(b || '{}')); } catch { res({}); } });
    req.on('error', rej);
  });
}

function json(res, data, status = 200) {
  res.writeHead(status, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
  res.end(JSON.stringify(data));
}
function err(res, msg, status = 400) { json(res, { error: msg }, status); }

function getUser(req) {
  const token  = req.headers['x-session'] || '';
  const userId = DB.sessions[token];
  return userId ? DB.users[userId] : null;
}

function getFriendData(userId) {
  if (!DB.friends[userId]) DB.friends[userId] = { friends: [], sent: [], received: [] };
  return DB.friends[userId];
}

// ─── ACCURATE ANALYTICS HELPERS ───────────────────────────────────────────────

/**
 * Compute streak: consecutive days (going back from today) where the user
 * completed ≥1 task OR completed ≥50% of their habits.
 */
function computeStreak(userId) {
  const tasks  = DB.tasks[userId]  || [];
  const habits = (DB.habits || []).filter(h => h.user === 'all' || h.user === userId);
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
    else if (i > 0) break; // Allow today to be 0 without breaking
  }
  return streak;
}

/**
 * Habit completion percentage for a user on a given date (0-100).
 */
function habitPct(userId, date) {
  const habits = (DB.habits || []).filter(h => h.user === 'all' || h.user === userId);
  if (!habits.length) return 0;
  const done = habits.filter(h => DB.habitLog?.[date]?.[h.id]?.[userId]).length;
  return (done / habits.length) * 100;
}

/**
 * Task completion percentage for a user on a given date (0-100).
 * Returns null if no tasks exist for that day.
 */
function taskPct(userId, date) {
  const tasks = (DB.tasks[userId] || []).filter(t => t.date === date);
  if (!tasks.length) return null;
  return tasks.filter(t => t.done).length / tasks.length * 100;
}

/**
 * Discipline score for a user today (0-100).
 * Formula: 50% task completion + 30% habit completion + up to 20pts streak bonus.
 */
function disciplineScore(userId) {
  const t   = today();
  const tp  = taskPct(userId, t) ?? 0;
  const hp  = habitPct(userId, t);
  const str = computeStreak(userId);
  return Math.min(100, Math.round(tp * 0.5 + hp * 0.3 + Math.min(str * 4, 20)));
}

/**
 * N-day average task completion rate for a user (0-100).
 */
function avgTaskPct(userId, days) {
  const dates = getLastNDays(days);
  const valid = dates.map(d => taskPct(userId, d)).filter(v => v !== null);
  if (!valid.length) return 0;
  return Math.round(valid.reduce((a, b) => a + b, 0) / valid.length);
}

/**
 * N-day average habit completion rate for a user (0-100).
 */
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

/**
 * Full per-user stats object (no passwordHash).
 */
function userStatsObject(u) {
  const t   = today();
  const dayTasks  = (DB.tasks[u.id] || []).filter(x => x.date === t);
  const allTasks  = DB.tasks[u.id] || [];
  const friends   = (DB.friends[u.id]?.friends || []).length;
  const score     = disciplineScore(u.id);
  const streak    = computeStreak(u.id);
  const avg7Task  = avgTaskPct(u.id, 7);
  const avg7Habit = avgHabitPct(u.id, 7);

  return {
    id: u.id, email: u.email, username: u.username,
    avatar: u.avatar, color: u.color,
    score, streak, friends,
    taskCount: dayTasks.length,
    doneCount: dayTasks.filter(t => t.done).length,
    totalTasks: allTasks.length,
    totalDone:  allTasks.filter(t => t.done).length,
    avg7Task, avg7Habit,
    created:  u.createdAt?.slice(0, 10),
    lastSeen: u.lastSeen?.slice(0, 10),
  };
}

// ─── STATIC FILES ─────────────────────────────────────────────────────────────
function serveStatic(res, filePath) {
  try {
    const content = fs.readFileSync(filePath);
    const ext  = path.extname(filePath);
    const types = { '.html': 'text/html', '.js': 'application/javascript', '.css': 'text/css', '.json': 'application/json' };
    res.writeHead(200, { 'Content-Type': types[ext] || 'text/plain' });
    res.end(content);
  } catch {
    res.writeHead(404); res.end('Not found');
  }
}

// ─── ROUTER ───────────────────────────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  const url      = new URL(req.url, `http://localhost:${PORT}`);
  const pathname = url.pathname;
  const method   = req.method;

  // CORS
  if (method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin':  '*',
      'Access-Control-Allow-Methods': 'GET,POST,PATCH,DELETE,OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type,X-Session,X-Admin-Token',
    });
    return res.end();
  }

  // Static
  if (pathname === '/' || pathname === '/index.html') return serveStatic(res, path.join(__dirname, 'Index.html'));
  if (pathname === '/admin' || pathname === '/admin.html') return serveStatic(res, path.join(__dirname, 'Admin.html'));

  // ─── AUTH ─────────────────────────────────────────────────────────────────
  if (pathname === '/api/auth/register' && method === 'POST') {
    const body = await parseBody(req);
    const { email, password, username, avatar, color } = body;
    if (!email || !password || !username) return err(res, 'All fields required');
    if (password.length < 6) return err(res, 'Password min 6 chars');
    const emailLower = email.toLowerCase().trim();
    if (Object.values(DB.users).find(u => u.email === emailLower)) return err(res, 'Email already registered');
    if (Object.values(DB.users).find(u => u.username.toLowerCase() === username.trim().toLowerCase())) return err(res, 'Username already taken');
    const id    = uid();
    const token = uid() + uid();
    DB.users[id]   = { id, email: emailLower, passwordHash: hashPwd(password), username: username.trim(), avatar: avatar || '⚡', color: color || 'neon', createdAt: new Date().toISOString(), lastSeen: new Date().toISOString() };
    DB.sessions[token] = id;
    DB.friends[id] = { friends: [], sent: [], received: [] };
    DB.tasks[id]   = [];
    saveData(DB);
    const u = { ...DB.users[id] }; delete u.passwordHash;
    return json(res, { token, user: u });
  }

  if (pathname === '/api/auth/login' && method === 'POST') {
    const body = await parseBody(req);
    const { email, password } = body;
    const emailLower = (email || '').toLowerCase().trim();
    const user = Object.values(DB.users).find(u => u.email === emailLower && u.passwordHash === hashPwd(password));
    if (!user) return err(res, 'Invalid email or password', 401);
    const token = uid() + uid();
    DB.sessions[token]    = user.id;
    DB.users[user.id].lastSeen = new Date().toISOString();
    saveData(DB);
    const u = { ...user }; delete u.passwordHash;
    return json(res, { token, user: u });
  }

  if (pathname === '/api/auth/logout' && method === 'POST') {
    const token = req.headers['x-session'] || '';
    delete DB.sessions[token];
    saveData(DB);
    return json(res, { ok: true });
  }

  if (pathname === '/api/auth/me' && method === 'GET') {
    const user = getUser(req);
    if (!user) return err(res, 'Not authenticated', 401);
    const u = { ...user }; delete u.passwordHash;
    return json(res, u);
  }

  if (pathname === '/api/auth/profile' && method === 'PATCH') {
    const user = getUser(req);
    if (!user) return err(res, 'Not authenticated', 401);
    const body = await parseBody(req);
    const { username, avatar, color } = body;
    if (username) {
      const taken = Object.values(DB.users).find(u => u.id !== user.id && u.username.toLowerCase() === username.trim().toLowerCase());
      if (taken) return err(res, 'Username already taken');
      DB.users[user.id].username = username.trim();
    }
    if (avatar) DB.users[user.id].avatar = avatar;
    if (color)  DB.users[user.id].color  = color;
    saveData(DB);
    const u = { ...DB.users[user.id] }; delete u.passwordHash;
    return json(res, u);
  }

  // ─── MAIN DATA ────────────────────────────────────────────────────────────
  if (pathname === '/api/data' && method === 'GET') {
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

    const tasks = {};
    allUserIds.forEach(id => { tasks[id] = DB.tasks[id] || []; });

    // Per-day analytics for the current user (last 30 days)
    const myDays = getLastNDays(30).map(d => ({
      date: d,
      taskPct:  taskPct(me.id, d),
      habitPct: Math.round(habitPct(me.id, d)),
    }));

    const u = { ...me }; delete u.passwordHash;
    return json(res, {
      user: u,
      allUsers,
      tasks,
      habits:    DB.habits  || [],
      habitLog:  DB.habitLog || {},
      friends:   fd,
      analytics: myDays,   // accurate per-day data for the logged-in user
    });
  }

  // ─── TASKS ────────────────────────────────────────────────────────────────
  if (pathname === '/api/tasks' && method === 'POST') {
    const me = getUser(req);
    if (!me) return err(res, 'Not authenticated', 401);
    const body = await parseBody(req);
    const { text, priority, category, notes, date } = body;
    if (!text) return err(res, 'Task text required');
    if (!DB.tasks[me.id]) DB.tasks[me.id] = [];
    const task = { id: uid(), text, priority: priority || 'med', category: category || '', notes: notes || '', date: date || today(), done: false, created: Date.now() };
    DB.tasks[me.id].push(task);
    saveData(DB);
    return json(res, task);
  }

  const taskMatch = pathname.match(/^\/api\/tasks\/([a-f0-9]+)$/);
  if (taskMatch) {
    const me = getUser(req);
    if (!me) return err(res, 'Not authenticated', 401);
    const tid      = taskMatch[1];
    const taskArr  = DB.tasks[me.id] || [];
    const idx      = taskArr.findIndex(t => t.id === tid);
    if (idx === -1) return err(res, 'Task not found', 404);
    if (method === 'PATCH') {
      const body = await parseBody(req);
      Object.assign(DB.tasks[me.id][idx], body);
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
    const me = getUser(req);
    if (!me) return err(res, 'Not authenticated', 401);
    const body = await parseBody(req);
    const { name, icon, user: huser } = body;
    if (!name) return err(res, 'Habit name required');
    const habit = { id: uid(), name, icon: icon || '⭐', user: huser || 'all', created: today() };
    if (!DB.habits) DB.habits = [];
    DB.habits.push(habit);
    saveData(DB);
    return json(res, habit);
  }

  const habitMatch = pathname.match(/^\/api\/habits\/([a-f0-9]+)$/);
  if (habitMatch && method === 'DELETE') {
    const me = getUser(req);
    if (!me) return err(res, 'Not authenticated', 401);
    DB.habits = (DB.habits || []).filter(h => h.id !== habitMatch[1]);
    saveData(DB);
    return json(res, { ok: true });
  }

  if (pathname === '/api/habitLog' && method === 'POST') {
    const me = getUser(req);
    if (!me) return err(res, 'Not authenticated', 401);
    const body = await parseBody(req);
    const { habitId, userId, date, value } = body;
    if (!DB.habitLog)                DB.habitLog = {};
    if (!DB.habitLog[date])          DB.habitLog[date] = {};
    if (!DB.habitLog[date][habitId]) DB.habitLog[date][habitId] = {};
    DB.habitLog[date][habitId][userId] = value;
    saveData(DB);
    return json(res, { ok: true });
  }

  // ─── ANALYTICS ENDPOINT (fresh accurate data) ─────────────────────────────
  if (pathname === '/api/analytics' && method === 'GET') {
    const me = getUser(req);
    if (!me) return err(res, 'Not authenticated', 401);
    const fd        = getFriendData(me.id);
    const visibleIds = [me.id, ...fd.friends];
    const days14    = getLastNDays(14);

    const perUser = visibleIds.map(id => {
      const u = DB.users[id]; if (!u) return null;
      return {
        id: u.id, username: u.username, avatar: u.avatar, color: u.color,
        score:   disciplineScore(id),
        streak:  computeStreak(id),
        days: days14.map(d => ({
          date:     d,
          taskPct:  taskPct(id, d) ?? 0,
          habitPct: Math.round(habitPct(id, d)),
          score:    (() => {
            const tp = taskPct(id, d) ?? 0;
            const hp = habitPct(id, d);
            return Math.round(tp * 0.6 + hp * 0.4);
          })(),
        })),
        avg14Task:  avgTaskPct(id, 14),
        avg14Habit: avgHabitPct(id, 14),
        avg7Task:   avgTaskPct(id, 7),
        totalTasksDone: (DB.tasks[id] || []).filter(t => t.done).length,
        totalTasks:     (DB.tasks[id] || []).length,
      };
    }).filter(Boolean);

    // Category breakdown
    const categories = {};
    visibleIds.forEach(id => {
      (DB.tasks[id] || []).forEach(t => {
        const c = t.category || 'other';
        if (!categories[c]) categories[c] = { total: 0, done: 0 };
        categories[c].total++;
        if (t.done) categories[c].done++;
      });
    });

    // Missed reasons
    const missedReasons = {};
    visibleIds.forEach(id => {
      (DB.tasks[id] || []).filter(t => !t.done && t.reason).forEach(t => {
        const r = t.reason;
        missedReasons[r] = (missedReasons[r] || 0) + 1;
      });
    });

    return json(res, { users: perUser, categories, missedReasons, dates: days14 });
  }

  // ─── FRIENDS ──────────────────────────────────────────────────────────────
  if (pathname === '/api/friends/search' && method === 'GET') {
    const me = getUser(req);
    if (!me) return err(res, 'Not authenticated', 401);
    const q  = (url.searchParams.get('q') || '').toLowerCase().trim();
    if (!q) return json(res, []);
    const fd = getFriendData(me.id);
    const results = Object.values(DB.users)
      .filter(u => u.id !== me.id && u.username.toLowerCase().includes(q))
      .slice(0, 10)
      .map(u => {
        const status = fd.friends.includes(u.id) ? 'friend'
          : fd.sent.includes(u.id)     ? 'sent'
          : fd.received.includes(u.id) ? 'received'
          : 'none';
        return { id: u.id, username: u.username, avatar: u.avatar, color: u.color, status };
      });
    return json(res, results);
  }

  if (pathname === '/api/friends/request' && method === 'POST') {
    const me = getUser(req);
    if (!me) return err(res, 'Not authenticated', 401);
    const body = await parseBody(req);
    const { targetId } = body;
    if (!targetId || !DB.users[targetId]) return err(res, 'User not found', 404);
    if (targetId === me.id) return err(res, 'Cannot friend yourself');
    const myFd    = getFriendData(me.id);
    const theirFd = getFriendData(targetId);
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
    const me = getUser(req);
    if (!me) return err(res, 'Not authenticated', 401);
    const body = await parseBody(req);
    const { fromId } = body;
    if (!fromId || !DB.users[fromId]) return err(res, 'User not found', 404);
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
    const me = getUser(req);
    if (!me) return err(res, 'Not authenticated', 401);
    const body = await parseBody(req);
    const { userId: targetId } = body;
    if (!targetId) return err(res, 'userId required');
    const myFd    = getFriendData(me.id);
    const theirFd = getFriendData(targetId);
    myFd.received    = myFd.received.filter(id => id !== targetId);
    theirFd.sent     = theirFd.sent.filter(id => id !== me.id);
    myFd.sent        = myFd.sent.filter(id => id !== targetId);
    theirFd.received = theirFd.received.filter(id => id !== me.id);
    saveData(DB);
    return json(res, { status: 'declined' });
  }

  if (pathname === '/api/friends/remove' && method === 'POST') {
    const me = getUser(req);
    if (!me) return err(res, 'Not authenticated', 401);
    const body = await parseBody(req);
    const { friendId } = body;
    if (!friendId) return err(res, 'friendId required');
    const myFd    = getFriendData(me.id);
    const theirFd = getFriendData(friendId);
    myFd.friends    = myFd.friends.filter(id => id !== friendId);
    theirFd.friends = theirFd.friends.filter(id => id !== me.id);
    saveData(DB);
    return json(res, { status: 'removed' });
  }

  if (pathname === '/api/friends' && method === 'GET') {
    const me = getUser(req);
    if (!me) return err(res, 'Not authenticated', 401);
    const fd    = getFriendData(me.id);
    const mapU  = id => {
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
    const adminToken = req.headers['x-admin-token'];
    if (adminToken !== ADMIN_TOKEN) return err(res, 'Unauthorized', 401);

    // GET /admin/stats — returns { stats, users, full, friendships }
    if (pathname === '/admin/stats' && method === 'GET') {
      const users    = Object.values(DB.users);
      const allTasks = Object.values(DB.tasks).flat();
      const todayStr = today();

      // Friendship count
      let friendshipCount = 0, pendingCount = 0;
      Object.values(DB.friends).forEach(fd => {
        friendshipCount += fd.friends.length;
        pendingCount    += fd.sent.length;
      });
      friendshipCount = Math.round(friendshipCount / 2); // each pair counted twice

      const userStats = users.map(u => userStatsObject(u));

      // Per-day platform stats for the last 14 days
      const days14 = getLastNDays(14);
      const dailyStats = days14.map(d => {
        const dayTasks   = allTasks.filter(t => t.date === d);
        const done       = dayTasks.filter(t => t.done).length;
        const activeUsers = users.filter(u => (DB.tasks[u.id] || []).some(t => t.date === d)).length;
        return { date: d, tasks: dayTasks.length, done, activeUsers, completion: dayTasks.length ? Math.round(done / dayTasks.length * 100) : 0 };
      });

      return json(res, {
        stats: {
          totalUsers:       users.length,
          totalTasks:       allTasks.length,
          doneTasks:        allTasks.filter(t => t.done).length,
          todayTasks:       allTasks.filter(t => t.date === todayStr).length,
          todayDone:        allTasks.filter(t => t.date === todayStr && t.done).length,
          totalHabits:      (DB.habits || []).length,
          activeToday:      users.filter(u => u.lastSeen?.startsWith(todayStr)).length,
          activeSessions:   Object.keys(DB.sessions).length,
          friendshipCount,
          pendingRequests:  pendingCount,
          avgScore:         userStats.length ? Math.round(userStats.reduce((s, u) => s + u.score, 0) / userStats.length) : 0,
          avgStreak:        userStats.length ? Math.round(userStats.reduce((s, u) => s + u.streak, 0) / userStats.length) : 0,
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

    const adminUserMatch = pathname.match(/^\/admin\/users\/([a-f0-9]+)$/);
    if (adminUserMatch) {
      const id = adminUserMatch[1];
      if (method === 'PATCH') {
        const body = await parseBody(req);
        if (!DB.users[id]) return err(res, 'User not found', 404);
        if (body.username) DB.users[id].username = body.username;
        if (body.avatar)   DB.users[id].avatar   = body.avatar;
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
        saveData(DB);
        return json(res, { ok: true });
      }
    }
  }

  res.writeHead(404); res.end('Not found');
});

server.listen(PORT, () => {
  console.log(`\n🚀 We Track running  →  http://localhost:${PORT}`);
  console.log(`   Admin panel       →  http://localhost:${PORT}/admin.html`);
  console.log(`   Admin token       →  ${ADMIN_TOKEN}\n`);
});
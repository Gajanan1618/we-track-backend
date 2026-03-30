// ─── We Track Server — MongoDB Edition ────────────────────────────────────────
const http    = require('http');
const crypto  = require('crypto');
const { MongoClient } = require('mongodb');

const PORT         = process.env.PORT || 3000;
const ADMIN_TOKEN  = process.env.ADMIN_TOKEN || 'wetrack-admin-2024';
const MONGO_URI    = process.env.MONGO_URI;

// ─── DATABASE ─────────────────────────────────────────────────────────────────
let db;
let users, sessions, tasks, habits, habitLog, friends;

async function connectDB() {
  const client = new MongoClient(MONGO_URI);
  await client.connect();
  db         = client.db('wetrack');
  users      = db.collection('users');
  sessions   = db.collection('sessions');
  tasks      = db.collection('tasks');
  habits     = db.collection('habits');
  habitLog   = db.collection('habitLog');
  friends    = db.collection('friends');
  console.log('✅ MongoDB connected');
}

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
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type,X-Session,X-Admin-Token',
  });
  res.end(JSON.stringify(data));
}
function err(res, msg, status = 400) { json(res, { error: msg }, status); }

async function getUser(req) {
  const token = req.headers['x-session'] || '';
  if (!token) return null;
  const session = await sessions.findOne({ token });
  if (!session) return null;
  return users.findOne({ id: session.userId });
}

async function getFriendData(userId) {
  let fd = await friends.findOne({ userId });
  if (!fd) {
    fd = { userId, friends: [], sent: [], received: [] };
    await friends.insertOne(fd);
  }
  return fd;
}

// ─── ANALYTICS HELPERS ────────────────────────────────────────────────────────
function getLastNDays(n) {
  const d = [];
  for (let i = n - 1; i >= 0; i--) {
    const dt = new Date(); dt.setDate(dt.getDate() - i);
    d.push(dt.toISOString().slice(0, 10));
  }
  return d;
}

async function computeStreak(userId) {
  const userTasks = await tasks.find({ userId }).toArray();
  const allHabits = await habits.find({ $or: [{ user: 'all' }, { user: userId }] }).toArray();
  let streak = 0;
  for (let i = 0; i < 60; i++) {
    const dt = new Date(); dt.setDate(dt.getDate() - i);
    const d  = dt.toISOString().slice(0, 10);
    const dayTasks = userTasks.filter(t => t.date === d);
    const taskOk   = dayTasks.length > 0 && dayTasks.some(t => t.done);
    let habitOk = false;
    if (allHabits.length > 0) {
      const logEntries = await habitLog.find({ date: d, userId }).toArray();
      const doneH = logEntries.filter(l => l.value).length;
      habitOk = (doneH / allHabits.length) >= 0.5;
    }
    if (taskOk || habitOk) streak++;
    else if (i > 0) break;
  }
  return streak;
}

async function habitPct(userId, date) {
  const allHabits = await habits.find({ $or: [{ user: 'all' }, { user: userId }] }).toArray();
  if (!allHabits.length) return 0;
  const logEntries = await habitLog.find({ date, userId, value: true }).toArray();
  return (logEntries.length / allHabits.length) * 100;
}

async function taskPct(userId, date) {
  const dayTasks = await tasks.find({ userId, date }).toArray();
  if (!dayTasks.length) return null;
  return dayTasks.filter(t => t.done).length / dayTasks.length * 100;
}

async function disciplineScore(userId) {
  const t   = today();
  const tp  = (await taskPct(userId, t)) ?? 0;
  const hp  = await habitPct(userId, t);
  const str = await computeStreak(userId);
  return Math.min(100, Math.round(tp * 0.5 + hp * 0.3 + Math.min(str * 4, 20)));
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
  const dayTasks = await tasks.find({ userId: u.id, date: t }).toArray();
  const allTasks = await tasks.find({ userId: u.id }).toArray();
  const fd       = await getFriendData(u.id);
  const score    = await disciplineScore(u.id);
  const streak   = await computeStreak(u.id);
  const avg7Task  = await avgTaskPct(u.id, 7);
  const avg7Habit = await avgHabitPct(u.id, 7);
  return {
    id: u.id, email: u.email, username: u.username,
    avatar: u.avatar, color: u.color,
    score, streak, friends: fd.friends.length,
    taskCount:  dayTasks.length,
    doneCount:  dayTasks.filter(t => t.done).length,
    totalTasks: allTasks.length,
    totalDone:  allTasks.filter(t => t.done).length,
    avg7Task, avg7Habit,
    created:  u.createdAt?.slice(0, 10),
    lastSeen: u.lastSeen?.slice(0, 10),
  };
}

// ─── SERVER ───────────────────────────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  const url      = new URL(req.url, `http://localhost:${PORT}`);
  const pathname = url.pathname;
  const method   = req.method;

  if (method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin':  '*',
      'Access-Control-Allow-Methods': 'GET,POST,PATCH,DELETE,OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type,X-Session,X-Admin-Token',
    });
    return res.end();
  }

  // ─── AUTH ───────────────────────────────────────────────────────────────────
  if (pathname === '/api/auth/register' && method === 'POST') {
    const body = await parseBody(req);
    const { email, password, username, avatar, color } = body;
    if (!email || !password || !username) return err(res, 'All fields required');
    if (password.length < 6) return err(res, 'Password min 6 chars');
    const emailLower = email.toLowerCase().trim();
    if (await users.findOne({ email: emailLower })) return err(res, 'Email already registered');
    if (await users.findOne({ usernameLower: username.trim().toLowerCase() })) return err(res, 'Username already taken');
    const id    = uid();
    const token = uid() + uid();
    const user  = { id, email: emailLower, usernameLower: username.trim().toLowerCase(), passwordHash: hashPwd(password), username: username.trim(), avatar: avatar || '⚡', color: color || 'neon', createdAt: new Date().toISOString(), lastSeen: new Date().toISOString() };
    await users.insertOne(user);
    await sessions.insertOne({ token, userId: id });
    await friends.insertOne({ userId: id, friends: [], sent: [], received: [] });
    const u = { ...user }; delete u.passwordHash; delete u._id; delete u.usernameLower;
    return json(res, { token, user: u });
  }

  if (pathname === '/api/auth/login' && method === 'POST') {
    const body = await parseBody(req);
    const { email, password } = body;
    const emailLower = (email || '').toLowerCase().trim();
    const user = await users.findOne({ email: emailLower, passwordHash: hashPwd(password) });
    if (!user) return err(res, 'Invalid email or password', 401);
    const token = uid() + uid();
    await sessions.insertOne({ token, userId: user.id });
    await users.updateOne({ id: user.id }, { $set: { lastSeen: new Date().toISOString() } });
    const u = { ...user }; delete u.passwordHash; delete u._id; delete u.usernameLower;
    return json(res, { token, user: u });
  }

  if (pathname === '/api/auth/logout' && method === 'POST') {
    const token = req.headers['x-session'] || '';
    await sessions.deleteOne({ token });
    return json(res, { ok: true });
  }

  if (pathname === '/api/auth/me' && method === 'GET') {
    const user = await getUser(req);
    if (!user) return err(res, 'Not authenticated', 401);
    const u = { ...user }; delete u.passwordHash; delete u._id; delete u.usernameLower;
    return json(res, u);
  }

  if (pathname === '/api/auth/profile' && method === 'PATCH') {
    const user = await getUser(req);
    if (!user) return err(res, 'Not authenticated', 401);
    const body = await parseBody(req);
    const { username, avatar, color } = body;
    const update = {};
    if (username) {
      const taken = await users.findOne({ usernameLower: username.trim().toLowerCase(), id: { $ne: user.id } });
      if (taken) return err(res, 'Username already taken');
      update.username = username.trim();
      update.usernameLower = username.trim().toLowerCase();
    }
    if (avatar) update.avatar = avatar;
    if (color)  update.color  = color;
    await users.updateOne({ id: user.id }, { $set: update });
    const updated = await users.findOne({ id: user.id });
    const u = { ...updated }; delete u.passwordHash; delete u._id; delete u.usernameLower;
    return json(res, u);
  }

  // ─── MAIN DATA ──────────────────────────────────────────────────────────────
  if (pathname === '/api/data' && method === 'GET') {
    const me = await getUser(req);
    if (!me) return err(res, 'Not authenticated', 401);
    await users.updateOne({ id: me.id }, { $set: { lastSeen: new Date().toISOString() } });

    const fd         = await getFriendData(me.id);
    const friendIds  = fd.friends;
    const allUserIds = [me.id, ...friendIds];

    const allUsers = (await Promise.all(allUserIds.map(async id => {
      const u = await users.findOne({ id }); if (!u) return null;
      return userStatsObject(u);
    }))).filter(Boolean);

    const taskMap = {};
    await Promise.all(allUserIds.map(async id => {
      taskMap[id] = (await tasks.find({ userId: id }).toArray()).map(t => { const x = {...t}; delete x._id; return x; });
    }));

    const allHabits = (await habits.find({}).toArray()).map(h => { const x = {...h}; delete x._id; return x; });

    const logDocs = await habitLog.find({}).toArray();
    const habitLogMap = {};
    logDocs.forEach(l => {
      if (!habitLogMap[l.date]) habitLogMap[l.date] = {};
      if (!habitLogMap[l.date][l.habitId]) habitLogMap[l.date][l.habitId] = {};
      habitLogMap[l.date][l.habitId][l.userId] = l.value;
    });

    const myDays = await Promise.all(getLastNDays(30).map(async d => ({
      date: d,
      taskPct:  await taskPct(me.id, d),
      habitPct: Math.round(await habitPct(me.id, d)),
    })));

    const u = { ...me }; delete u.passwordHash; delete u._id; delete u.usernameLower;
    return json(res, {
      user: u,
      allUsers: await Promise.all(allUsers),
      tasks:    taskMap,
      habits:   allHabits,
      habitLog: habitLogMap,
      friends:  fd,
      analytics: myDays,
    });
  }

  // ─── TASKS ──────────────────────────────────────────────────────────────────
  if (pathname === '/api/tasks' && method === 'POST') {
    const me = await getUser(req);
    if (!me) return err(res, 'Not authenticated', 401);
    const body = await parseBody(req);
    const { text, priority, category, notes, date } = body;
    if (!text) return err(res, 'Task text required');
    const task = { id: uid(), userId: me.id, text, priority: priority || 'med', category: category || '', notes: notes || '', date: date || today(), done: false, created: Date.now() };
    await tasks.insertOne(task);
    const t = { ...task }; delete t._id;
    return json(res, t);
  }

  const taskMatch = pathname.match(/^\/api\/tasks\/([a-f0-9]+)$/);
  if (taskMatch) {
    const me = await getUser(req);
    if (!me) return err(res, 'Not authenticated', 401);
    const tid  = taskMatch[1];
    const task = await tasks.findOne({ id: tid, userId: me.id });
    if (!task) return err(res, 'Task not found', 404);
    if (method === 'PATCH') {
      const body = await parseBody(req);
      await tasks.updateOne({ id: tid }, { $set: body });
      const updated = await tasks.findOne({ id: tid });
      const t = { ...updated }; delete t._id;
      return json(res, t);
    }
    if (method === 'DELETE') {
      await tasks.deleteOne({ id: tid });
      return json(res, { ok: true });
    }
  }

  // ─── HABITS ─────────────────────────────────────────────────────────────────
  if (pathname === '/api/habits' && method === 'POST') {
    const me = await getUser(req);
    if (!me) return err(res, 'Not authenticated', 401);
    const body = await parseBody(req);
    const { name, icon, user: huser } = body;
    if (!name) return err(res, 'Habit name required');
    const habit = { id: uid(), name, icon: icon || '⭐', user: huser || 'all', created: today() };
    await habits.insertOne(habit);
    const h = { ...habit }; delete h._id;
    return json(res, h);
  }

  const habitMatch = pathname.match(/^\/api\/habits\/([a-f0-9]+)$/);
  if (habitMatch && method === 'DELETE') {
    const me = await getUser(req);
    if (!me) return err(res, 'Not authenticated', 401);
    await habits.deleteOne({ id: habitMatch[1] });
    return json(res, { ok: true });
  }

  if (pathname === '/api/habitLog' && method === 'POST') {
    const me = await getUser(req);
    if (!me) return err(res, 'Not authenticated', 401);
    const body = await parseBody(req);
    const { habitId, userId, date, value } = body;
    await habitLog.updateOne(
      { habitId, userId, date },
      { $set: { habitId, userId, date, value } },
      { upsert: true }
    );
    return json(res, { ok: true });
  }

  // ─── ANALYTICS ──────────────────────────────────────────────────────────────
  if (pathname === '/api/analytics' && method === 'GET') {
    const me = await getUser(req);
    if (!me) return err(res, 'Not authenticated', 401);
    const fd         = await getFriendData(me.id);
    const visibleIds = [me.id, ...fd.friends];
    const days14     = getLastNDays(14);

    const perUser = (await Promise.all(visibleIds.map(async id => {
      const u = await users.findOne({ id }); if (!u) return null;
      const dayData = await Promise.all(days14.map(async d => {
        const tp = (await taskPct(id, d)) ?? 0;
        const hp = await habitPct(id, d);
        return { date: d, taskPct: tp, habitPct: Math.round(hp), score: Math.round(tp * 0.6 + hp * 0.4) };
      }));
      return {
        id: u.id, username: u.username, avatar: u.avatar, color: u.color,
        score:   await disciplineScore(id),
        streak:  await computeStreak(id),
        days:    dayData,
        avg14Task:  await avgTaskPct(id, 14),
        avg14Habit: await avgHabitPct(id, 14),
        avg7Task:   await avgTaskPct(id, 7),
        totalTasksDone: await tasks.countDocuments({ userId: id, done: true }),
        totalTasks:     await tasks.countDocuments({ userId: id }),
      };
    }))).filter(Boolean);

    const categories = {};
    await Promise.all(visibleIds.map(async id => {
      const userTasks = await tasks.find({ userId: id }).toArray();
      userTasks.forEach(t => {
        const c = t.category || 'other';
        if (!categories[c]) categories[c] = { total: 0, done: 0 };
        categories[c].total++;
        if (t.done) categories[c].done++;
      });
    }));

    const missedReasons = {};
    await Promise.all(visibleIds.map(async id => {
      const missed = await tasks.find({ userId: id, done: false, reason: { $exists: true } }).toArray();
      missed.forEach(t => { missedReasons[t.reason] = (missedReasons[t.reason] || 0) + 1; });
    }));

    return json(res, { users: perUser, categories, missedReasons, dates: days14 });
  }

  // ─── FRIENDS ────────────────────────────────────────────────────────────────
  if (pathname === '/api/friends/search' && method === 'GET') {
    const me = await getUser(req);
    if (!me) return err(res, 'Not authenticated', 401);
    const q  = (url.searchParams.get('q') || '').toLowerCase().trim();
    if (!q) return json(res, []);
    const fd      = await getFriendData(me.id);
    const results = await users.find({ usernameLower: { $regex: q }, id: { $ne: me.id } }).limit(10).toArray();
    return json(res, results.map(u => {
      const status = fd.friends.includes(u.id) ? 'friend'
        : fd.sent.includes(u.id)     ? 'sent'
        : fd.received.includes(u.id) ? 'received'
        : 'none';
      return { id: u.id, username: u.username, avatar: u.avatar, color: u.color, status };
    }));
  }

  if (pathname === '/api/friends/request' && method === 'POST') {
    const me = await getUser(req);
    if (!me) return err(res, 'Not authenticated', 401);
    const body = await parseBody(req);
    const { targetId } = body;
    if (!targetId || !(await users.findOne({ id: targetId }))) return err(res, 'User not found', 404);
    if (targetId === me.id) return err(res, 'Cannot friend yourself');
    const myFd = await getFriendData(me.id);
    if (myFd.friends.includes(targetId)) return err(res, 'Already friends');
    if (myFd.sent.includes(targetId))    return err(res, 'Request already sent');
    if (myFd.received.includes(targetId)) {
      await friends.updateOne({ userId: me.id },    { $push: { friends: targetId }, $pull: { received: targetId } });
      await friends.updateOne({ userId: targetId }, { $push: { friends: me.id },   $pull: { sent: me.id } });
      return json(res, { status: 'accepted' });
    }
    await friends.updateOne({ userId: me.id },    { $push: { sent: targetId } });
    await friends.updateOne({ userId: targetId }, { $push: { received: me.id } });
    return json(res, { status: 'sent' });
  }

  if (pathname === '/api/friends/accept' && method === 'POST') {
    const me = await getUser(req);
    if (!me) return err(res, 'Not authenticated', 401);
    const body = await parseBody(req);
    const { fromId } = body;
    const myFd = await getFriendData(me.id);
    if (!myFd.received.includes(fromId)) return err(res, 'No pending request from this user');
    await friends.updateOne({ userId: me.id },  { $push: { friends: fromId }, $pull: { received: fromId } });
    await friends.updateOne({ userId: fromId }, { $push: { friends: me.id }, $pull: { sent: me.id } });
    return json(res, { status: 'accepted' });
  }

  if (pathname === '/api/friends/decline' && method === 'POST') {
    const me = await getUser(req);
    if (!me) return err(res, 'Not authenticated', 401);
    const body = await parseBody(req);
    const { userId: targetId } = body;
    await friends.updateOne({ userId: me.id },    { $pull: { received: targetId, sent: targetId } });
    await friends.updateOne({ userId: targetId }, { $pull: { sent: me.id, received: me.id } });
    return json(res, { status: 'declined' });
  }

  if (pathname === '/api/friends/remove' && method === 'POST') {
    const me = await getUser(req);
    if (!me) return err(res, 'Not authenticated', 401);
    const body = await parseBody(req);
    const { friendId } = body;
    await friends.updateOne({ userId: me.id },    { $pull: { friends: friendId } });
    await friends.updateOne({ userId: friendId }, { $pull: { friends: me.id } });
    return json(res, { status: 'removed' });
  }

  if (pathname === '/api/friends' && method === 'GET') {
    const me = await getUser(req);
    if (!me) return err(res, 'Not authenticated', 401);
    const fd   = await getFriendData(me.id);
    const mapU = async id => {
      const u = await users.findOne({ id }); if (!u) return null;
      return { id: u.id, username: u.username, avatar: u.avatar, color: u.color,
               score: await disciplineScore(id), streak: await computeStreak(id),
               taskCount: await tasks.countDocuments({ userId: id, date: today() }),
               doneCount: await tasks.countDocuments({ userId: id, date: today(), done: true }) };
    };
    return json(res, {
      friends:  (await Promise.all(fd.friends.map(mapU))).filter(Boolean),
      sent:     (await Promise.all(fd.sent.map(mapU))).filter(Boolean),
      received: (await Promise.all(fd.received.map(mapU))).filter(Boolean),
    });
  }

  // ─── ADMIN ──────────────────────────────────────────────────────────────────
  if (pathname.startsWith('/admin/')) {
    const adminToken = req.headers['x-admin-token'];
    if (adminToken !== ADMIN_TOKEN) return err(res, 'Unauthorized', 401);

    if (pathname === '/admin/stats' && method === 'GET') {
      const allUsers   = await users.find({}).toArray();
      const allTasks   = await tasks.find({}).toArray();
      const todayStr   = today();
      const allFriends = await friends.find({}).toArray();

      let friendshipCount = 0, pendingCount = 0;
      allFriends.forEach(fd => { friendshipCount += fd.friends.length; pendingCount += fd.sent.length; });
      friendshipCount = Math.round(friendshipCount / 2);

      const userStats  = await Promise.all(allUsers.map(u => userStatsObject(u)));
      const days14     = getLastNDays(14);
      const dailyStats = days14.map(d => {
        const dayTasks = allTasks.filter(t => t.date === d);
        const done     = dayTasks.filter(t => t.done).length;
        return { date: d, tasks: dayTasks.length, done, completion: dayTasks.length ? Math.round(done / dayTasks.length * 100) : 0 };
      });

      const allHabits = await habits.find({}).toArray();
      const logDocs   = await habitLog.find({}).toArray();
      const habitLogMap = {};
      logDocs.forEach(l => {
        if (!habitLogMap[l.date]) habitLogMap[l.date] = {};
        if (!habitLogMap[l.date][l.habitId]) habitLogMap[l.date][l.habitId] = {};
        habitLogMap[l.date][l.habitId][l.userId] = l.value;
      });
      const taskMap = {};
      allTasks.forEach(t => { if (!taskMap[t.userId]) taskMap[t.userId] = []; taskMap[t.userId].push(t); });

      const friendships = (() => {
        const list = [], pending = [];
        allFriends.forEach(fd => {
          fd.friends.forEach(fid => {
            if (fd.userId < fid) {
              const a = allUsers.find(u => u.id === fd.userId);
              const b = allUsers.find(u => u.id === fid);
              if (a && b) list.push({ a: { id: a.id, username: a.username, avatar: a.avatar, color: a.color }, b: { id: b.id, username: b.username, avatar: b.avatar, color: b.color } });
            }
          });
          fd.sent.forEach(tid => {
            const a = allUsers.find(u => u.id === fd.userId);
            const b = allUsers.find(u => u.id === tid);
            if (a && b) pending.push({ from: { id: a.id, username: a.username, avatar: a.avatar }, to: { id: b.id, username: b.username, avatar: b.avatar } });
          });
        });
        return { list, pending };
      })();

      return json(res, {
        stats: {
          totalUsers:      allUsers.length,
          totalTasks:      allTasks.length,
          doneTasks:       allTasks.filter(t => t.done).length,
          todayTasks:      allTasks.filter(t => t.date === todayStr).length,
          todayDone:       allTasks.filter(t => t.date === todayStr && t.done).length,
          totalHabits:     allHabits.length,
          activeToday:     allUsers.filter(u => u.lastSeen?.startsWith(todayStr)).length,
          activeSessions:  await sessions.countDocuments(),
          friendshipCount, pendingRequests: pendingCount,
          avgScore:  userStats.length ? Math.round(userStats.reduce((s, u) => s + u.score, 0) / userStats.length) : 0,
          avgStreak: userStats.length ? Math.round(userStats.reduce((s, u) => s + u.streak, 0) / userStats.length) : 0,
        },
        users: userStats,
        full:  { tasks: taskMap, habits: allHabits, habitLog: habitLogMap },
        friendships, dailyStats,
      });
    }

    if (pathname === '/admin/users' && method === 'GET') {
      const allUsers = await users.find({}).toArray();
      return json(res, await Promise.all(allUsers.map(u => userStatsObject(u))));
    }

    const adminUserMatch = pathname.match(/^\/admin\/users\/([a-f0-9]+)$/);
    if (adminUserMatch) {
      const id = adminUserMatch[1];
      if (method === 'PATCH') {
        const body = await parseBody(req);
        const update = {};
        if (body.username) { update.username = body.username; update.usernameLower = body.username.toLowerCase(); }
        if (body.avatar)   update.avatar = body.avatar;
        await users.updateOne({ id }, { $set: update });
        return json(res, { ok: true });
      }
      if (method === 'DELETE') {
        await users.deleteOne({ id });
        await tasks.deleteMany({ userId: id });
        await friends.deleteOne({ userId: id });
        await sessions.deleteMany({ userId: id });
        await friends.updateMany({}, { $pull: { friends: id, sent: id, received: id } });
        return json(res, { ok: true });
      }
    }
  }

  res.writeHead(404); res.end('Not found');
});

// ─── START ───────────────────────────────────────────────────────────────────
connectDB().then(() => {
  server.listen(PORT, () => {
    console.log(`\n🚀 We Track running  →  http://localhost:${PORT}`);
    console.log(`   Admin token       →  ${ADMIN_TOKEN}\n`);
  });
}).catch(e => {
  console.error('❌ Failed to connect to MongoDB:', e.message);
  process.exit(1);
});

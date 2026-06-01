require('dotenv').config();

const express = require('express');
const path = require('path');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const rateLimit = require('express-rate-limit');

const app = express();

// =========================
// 環境変数チェック
// =========================
if (!process.env.SESSION_SECRET) {
  throw new Error('SESSION_SECRET が設定されていません');
}

if (!process.env.INIT_ADMIN_PASSWORD) {
  throw new Error('INIT_ADMIN_PASSWORD が設定されていません');
}

// =========================
// Render / Railway / Heroku
// =========================
app.set('trust proxy', 1);

// =========================
// Body Parser
// =========================
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100, standardHeaders: true, legacyHeaders: false });
app.use(limiter);

// =========================
// セッション
// =========================
app.use(session({
  name: 'aichart.sid',
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  rolling: true,
  proxy: true,
  cookie: {
    maxAge: 1000 * 60 * 60 * 24,
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production'
  }
}));

// =========================
// 静的ファイル
// =========================
app.use(express.static(__dirname));

// =========================
// TOP
// =========================
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index-5-linked-1.html'));
});

// =========================
// DB操作
// =========================
const readDB = () => {
  if (!fs.existsSync('./db.json')) {
    fs.writeFileSync(
      './db.json',
      JSON.stringify({ users: [] }, null, 2)
    );
  }

  return JSON.parse(fs.readFileSync('./db.json'));
};

const writeDB = (data) => {
  fs.writeFileSync('./db.json', JSON.stringify(data, null, 2));
};

// =========================
// SUPPORT DB
// =========================
const readSupport = () => {
  if (!fs.existsSync('./support.json')) {
    fs.writeFileSync(
      './support.json',
      JSON.stringify({ tickets: [] }, null, 2)
    );
  }

  return JSON.parse(fs.readFileSync('./support.json'));
};

const writeSupport = (data) => {
  fs.writeFileSync('./support.json', JSON.stringify(data, null, 2));
};

// =========================
// 初期管理者
// =========================
const initAdmin = async () => {
  const db = readDB();

  if (db.users.length === 0) {

    const adminPassword =
      process.env.INIT_ADMIN_PASSWORD;

    const hash = await bcrypt.hash(adminPassword, 10);

    db.users.push({
      id: Date.now(),
      email: 'admin@test.com',
      password: hash,
      plan: 'premium',
      // SUBSCRIPTION SYSTEM
      active: true,
      expireAt: null,
      source: 'system',
      isAdmin: true,
      createdAt: new Date().toISOString()
    });

    writeDB(db);

    console.log('✅ 初期管理者作成：admin@test.com');
  }
};

// =========================
// ミドルウェア
// =========================
const auth = (req, res, next) => {

  if (!req.session.user) {
    return res.redirect('/login.html?error=auth');
  }

  next();
};

const adminOnly = (req, res, next) => {

  if (!req.session.user) {
    return res.redirect('/login.html?error=auth');
  }

  if (!req.session.user.isAdmin) {
    return res.redirect('/dashboard.html?error=forbidden');
  }

  next();
};

// =========================
// SIGNUP
// =========================
app.post('/signup', async (req, res) => {

  const { email, password } = req.body;

  if (!email || !password) {
    return res.redirect('/signup.html?error=missing');
  }

  if (password.length < 6) {
    return res.redirect('/signup.html?error=short');
  }

  const db = readDB();

  const exists = db.users.find(
    u => u.email === email
  );

  if (exists) {
    return res.redirect('/signup.html?error=exists');
  }

  const hash = await bcrypt.hash(password, 10);

  db.users.push({
    id: Date.now(),
    email,
    password: hash,
    plan: 'free',
    // SUBSCRIPTION SYSTEM
    active: true,
    expireAt: null,
    source: 'signup',
    isAdmin: false,
    createdAt: new Date().toISOString()
  });

  writeDB(db);

  res.redirect('/login.html?success=registered');
});

// =========================
// LOGIN
// =========================
app.post('/login', async (req, res) => {

  const { email, password } = req.body;

  if (!email || !password) {
    return res.redirect('/login.html?error=missing');
  }

  const db = readDB();

  const user = db.users.find(
    u => u.email === email
  );

  if (!user) {
    return res.redirect('/login.html?error=notfound');
  }

  const ok = await bcrypt.compare(
    password,
    user.password
  );

  if (!ok) {
    return res.redirect('/login.html?error=wrong');
  }

  // SUBSCRIPTION SYSTEM - アクティブ状態チェック
  if (!user.active) {
    return res.redirect('/login.html?error=inactive');
  }

  // SUBSCRIPTION SYSTEM - 期限チェック
  if (user.expireAt) {
    const now = new Date();
    const expireDate = new Date(user.expireAt);
    if (now > expireDate) {
      return res.redirect('/login.html?error=expired');
    }
  }

  const { password: _, ...safeUser } = user;

  req.session.user = safeUser;

  res.redirect('/dashboard.html');
});

// =========================
// LOGOUT
// =========================
app.get('/logout', (req, res) => {

  req.session.destroy(() => {
    res.redirect('/login.html?success=logout');
  });

});

// =========================
// DASHBOARD
// =========================
app.get('/dashboard.html', auth, (req, res) => {
  res.sendFile(path.join(__dirname, 'dashboard.html'));
});

// =========================
// ADMIN
// =========================
app.get('/admin.html', adminOnly, (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});

// =========================
// API - 自分情報
// =========================
app.get('/api/me', auth, (req, res) => {
  res.json(req.session.user);
});

// =========================
// API - SUPPORT送信
// =========================
app.post('/api/support', auth, (req, res) => {

  const { message } = req.body;

  if (!message || !message.trim()) {
    return res.status(400).json({
      error: 'メッセージは空白にできません'
    });
  }

  const support = readSupport();

  const now = new Date().toISOString();

  const ticket = {
    id: Date.now(),
    userId: req.session.user.id,
    email: req.session.user.email,
    message: message.trim(),
    reply: '',
    status: 'open',
    createdAt: now,
    updatedAt: now
  };

  support.tickets.push(ticket);

  writeSupport(support);

  res.json({ success: true });

});

// =========================
// API - MY SUPPORT
// =========================
app.get('/api/support/my', auth, (req, res) => {

  const support = readSupport();

  const myTickets = support.tickets.filter(
    t => t.userId === req.session.user.id
  );

  res.json(myTickets);

});

// =========================
// API - ADMIN SUPPORT
// =========================
app.get('/api/admin/support', adminOnly, (req, res) => {

  const support = readSupport();

  const recentTickets =
    support.tickets.slice(-100).reverse();

  res.json(recentTickets);

});

// =========================
// API - REPLY
// =========================
app.post('/api/admin/support/:id/reply', adminOnly, (req, res) => {

  const { id } = req.params;
  const { reply } = req.body;

  if (!reply || !reply.trim()) {
    return res.status(400).json({
      error: '返信は空白にできません'
    });
  }

  const support = readSupport();

  const ticket = support.tickets.find(
    t => t.id == id
  );

  if (!ticket) {
    return res.status(404).json({
      error: 'チケットが見つかりません'
    });
  }

  ticket.reply = reply.trim();
  ticket.status = 'closed';
  ticket.updatedAt = new Date().toISOString();

  writeSupport(support);

  res.json({ success: true });

});

// =========================
// API - USERS (SUBSCRIPTION SYSTEM対応)
// =========================
app.get('/api/users', adminOnly, (req, res) => {

  const db = readDB();

  const safeUsers = db.users.map(
    ({ password, ...u }) => u
  );

  res.json(safeUsers);

});

// =========================
// API - PLAN変更
// =========================
app.put('/api/users/:id/plan', adminOnly, (req, res) => {

  const { id } = req.params;
  const { plan } = req.body;

  const validPlans = [
    'free',
    'premium',
    'enterprise'
  ];

  if (!validPlans.includes(plan)) {
    return res.status(400).json({
      error: '無効なプランです'
    });
  }

  const db = readDB();

  const user = db.users.find(
    u => u.id == id
  );

  if (!user) {
    return res.status(404).json({
      error: 'ユーザーが見つかりません'
    });
  }

  user.plan = plan;

  writeDB(db);

  if (req.session.user.id == id) {
    req.session.user.plan = plan;
  }

  res.json({
    success: true,
    plan
  });

});

// =========================
// API - USER削除
// =========================
app.delete('/api/users/:id', adminOnly, (req, res) => {

  const { id } = req.params;

  if (req.session.user.id == id) {
    return res.status(400).json({
      error: '自分自身は削除できません'
    });
  }

  const db = readDB();

  const index = db.users.findIndex(
    u => u.id == id
  );

  if (index === -1) {
    return res.status(404).json({
      error: 'ユーザーが見つかりません'
    });
  }

  db.users.splice(index, 1);

  writeDB(db);

  res.json({ success: true });

});

// =========================
// API - ADMIN切替
// =========================
app.put('/api/users/:id/admin', adminOnly, (req, res) => {

  const { id } = req.params;

  if (req.session.user.id == id) {
    return res.status(400).json({
      error: '自分の管理者権限は変更できません'
    });
  }

  const db = readDB();

  const user = db.users.find(
    u => u.id == id
  );

  if (!user) {
    return res.status(404).json({
      error: 'ユーザーが見つかりません'
    });
  }

  user.isAdmin = !user.isAdmin;

  writeDB(db);

  res.json({
    success: true,
    isAdmin: user.isAdmin
  });

});

// =========================
// API - SUBSCRIPTION管理 (SUBSCRIPTION SYSTEM)
// =========================
app.put('/api/users/:id/subscription', adminOnly, (req, res) => {

  const { id } = req.params;
  const { active, expireAt, source } = req.body;

  // バリデーション
  if (typeof active !== 'boolean') {
    return res.status(400).json({
      error: 'active は boolean である必要があります'
    });
  }

  const validSources = [
    'signup',
    'coconala',
    'hp',
    'system'
  ];

  if (source && !validSources.includes(source)) {
    return res.status(400).json({
      error: '無効なsourceです。signup / coconala / hp / system のいずれかを指定してください'
    });
  }

  if (expireAt && isNaN(new Date(expireAt).getTime())) {
    return res.status(400).json({
      error: 'expireAt は有効なISO datetime形式である必要があります'
    });
  }

  const db = readDB();

  const user = db.users.find(
    u => u.id == id
  );

  if (!user) {
    return res.status(404).json({
      error: 'ユーザーが見つかりません'
    });
  }

  // SUBSCRIPTION SYSTEM - 更新
  user.active = active;
  if (expireAt === null || expireAt === undefined) {
    user.expireAt = null;
  } else {
    user.expireAt = new Date(expireAt).toISOString();
  }
  if (source) {
    user.source = source;
  }

  writeDB(db);

  // セッション中のユーザーの場合、セッション情報も更新
  if (req.session.user.id == id) {
    req.session.user.active = user.active;
    req.session.user.expireAt = user.expireAt;
    req.session.user.source = user.source;
  }

  res.json({
    success: true,
    active: user.active,
    expireAt: user.expireAt,
    source: user.source
  });

});

// =========================
// START
// =========================
const start = async () => {

  await initAdmin();

  const PORT = process.env.PORT || 3000;

  app.listen(PORT, '0.0.0.0', () => {

    console.log(`🚀 http://localhost:${PORT}`);
    console.log(`🌐 http://127.0.0.1:${PORT}`);

  });

};

start();
require('dotenv').config();

const path = require('node:path');
const express = require('express');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const db = require('./db');

const JWT_SECRET = process.env.JWT_SECRET;
const PORT = process.env.PORT || 3000;
const COOKIE_NAME = 'kakeibo_token';
const TOKEN_TTL = '30d';

if (!JWT_SECRET) {
  console.error('JWT_SECRET is not set. Create a .env file (see .env.example).');
  process.exit(1);
}

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '2mb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function issueToken(res, userId) {
  const token = jwt.sign({ uid: userId }, JWT_SECRET, { expiresIn: TOKEN_TTL });
  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 30 * 24 * 60 * 60 * 1000,
  });
}

function requireAuth(req, res, next) {
  const token = req.cookies[COOKIE_NAME];
  if (!token) return res.status(401).json({ error: 'ログインが必要です' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.userId = payload.uid;
    next();
  } catch {
    return res.status(401).json({ error: 'ログインが必要です' });
  }
}

// ── Auth routes ────────────────────────────────────────────
app.post('/api/auth/register', async (req, res, next) => {
  try {
    const { email, password } = req.body || {};

    if (typeof email !== 'string' || !EMAIL_RE.test(email.trim())) {
      return res.status(400).json({ error: 'メールアドレスの形式が正しくありません' });
    }
    if (typeof password !== 'string' || password.length < 8) {
      return res.status(400).json({ error: 'パスワードは8文字以上で入力してください' });
    }

    const normalizedEmail = email.trim().toLowerCase();
    if (await db.findUserByEmail(normalizedEmail)) {
      return res.status(409).json({ error: 'このメールアドレスは既に登録されています' });
    }

    const passwordHash = bcrypt.hashSync(password, 12);
    const userId = await db.createUser(normalizedEmail, passwordHash);
    issueToken(res, userId);
    res.json({ email: normalizedEmail });
  } catch (err) { next(err); }
});

app.post('/api/auth/login', async (req, res, next) => {
  try {
    const { email, password } = req.body || {};
    if (typeof email !== 'string' || typeof password !== 'string') {
      return res.status(400).json({ error: 'メールアドレスとパスワードを入力してください' });
    }

    const normalizedEmail = email.trim().toLowerCase();
    const user = await db.findUserByEmail(normalizedEmail);
    if (!user || !bcrypt.compareSync(password, user.password_hash)) {
      return res.status(401).json({ error: 'メールアドレスまたはパスワードが違います' });
    }

    issueToken(res, user.id);
    res.json({ email: user.email });
  } catch (err) { next(err); }
});

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie(COOKIE_NAME);
  res.json({ ok: true });
});

app.get('/api/me', requireAuth, async (req, res, next) => {
  try {
    const user = await db.findUserById(req.userId);
    if (!user) return res.status(401).json({ error: 'ログインが必要です' });
    res.json({ email: user.email });
  } catch (err) { next(err); }
});

// ── User data routes ───────────────────────────────────────
app.get('/api/data', requireAuth, async (req, res, next) => {
  try {
    res.json(await db.getUserData(req.userId));
  } catch (err) { next(err); }
});

app.put('/api/data', requireAuth, async (req, res, next) => {
  try {
    const { transactions, settings } = req.body || {};
    if (!Array.isArray(transactions) || typeof settings !== 'object' || settings === null) {
      return res.status(400).json({ error: '不正なデータ形式です' });
    }
    await db.saveUserData(req.userId, transactions, settings);
    res.json({ ok: true });
  } catch (err) { next(err); }
});

// SPA-ish fallback for the two pages we serve
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/login.html', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));

app.listen(PORT, () => {
  console.log(`家計簿サーバーが起動しました: http://localhost:${PORT}`);
});

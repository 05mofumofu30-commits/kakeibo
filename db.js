const { createClient } = require('@libsql/client');

const url = process.env.TURSO_DATABASE_URL;
const authToken = process.env.TURSO_AUTH_TOKEN;

if (!url) {
  console.error('TURSO_DATABASE_URL is not set. Create a .env file (see .env.example).');
  process.exit(1);
}

const db = createClient({ url, authToken });

async function init() {
  await db.execute(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TEXT NOT NULL
    )
  `);
  await db.execute(`
    CREATE TABLE IF NOT EXISTS user_data (
      user_id INTEGER PRIMARY KEY REFERENCES users(id),
      transactions TEXT NOT NULL DEFAULT '[]',
      settings TEXT NOT NULL DEFAULT '{}',
      updated_at TEXT NOT NULL
    )
  `);
}
const ready = init();

async function createUser(email, passwordHash) {
  await ready;
  const now = new Date().toISOString();
  const result = await db.execute({
    sql: 'INSERT INTO users (email, password_hash, created_at) VALUES (?, ?, ?)',
    args: [email, passwordHash, now],
  });
  const userId = Number(result.lastInsertRowid);
  await db.execute({
    sql: 'INSERT INTO user_data (user_id, transactions, settings, updated_at) VALUES (?, ?, ?, ?)',
    args: [userId, '[]', '{}', now],
  });
  return userId;
}

async function findUserByEmail(email) {
  await ready;
  const result = await db.execute({ sql: 'SELECT * FROM users WHERE email = ?', args: [email] });
  return result.rows[0] || null;
}

async function findUserById(id) {
  await ready;
  const result = await db.execute({ sql: 'SELECT * FROM users WHERE id = ?', args: [id] });
  return result.rows[0] || null;
}

async function getUserData(userId) {
  await ready;
  const result = await db.execute({
    sql: 'SELECT transactions, settings FROM user_data WHERE user_id = ?',
    args: [userId],
  });
  const row = result.rows[0];
  if (!row) return { transactions: [], settings: {} };
  return {
    transactions: JSON.parse(row.transactions),
    settings: JSON.parse(row.settings),
  };
}

async function saveUserData(userId, transactions, settings) {
  await ready;
  const now = new Date().toISOString();
  await db.execute({
    sql: 'UPDATE user_data SET transactions = ?, settings = ?, updated_at = ? WHERE user_id = ?',
    args: [JSON.stringify(transactions), JSON.stringify(settings), now, userId],
  });
}

module.exports = { createUser, findUserByEmail, findUserById, getUserData, saveUserData };

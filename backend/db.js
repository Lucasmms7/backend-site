const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcryptjs");

const DB_PATH = "./database.sqlite";
const db = new sqlite3.Database(DB_PATH);

function run(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) reject(err);
      else resolve(this);
    });
  });
}

function get(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) reject(err);
      else resolve(row);
    });
  });
}

function all(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) reject(err);
      else resolve(rows);
    });
  });
}

// Migração simples: cria coluna se não existir
async function ensureColumn(table, column, type, defaultSql = "") {
  const cols = await all(`PRAGMA table_info(${table})`);
  const exists = cols.some(c => c.name === column);

  if (!exists) {
    const def = defaultSql ? ` ${defaultSql}` : "";
    await run(`ALTER TABLE ${table} ADD COLUMN ${column} ${type}${def}`);
  }
}

async function init() {
  await run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TEXT DEFAULT (datetime('now'))
    )
  `);

  // Adiciona campos para multiusuário (se não existirem)
  await ensureColumn("users", "nome", "TEXT", "DEFAULT ''");
  await ensureColumn("users", "role", "TEXT", "DEFAULT 'user'");

  await run(`
    CREATE TABLE IF NOT EXISTS despesas (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      data TEXT NOT NULL,            -- YYYY-MM-DD
      valor REAL NOT NULL,
      responsavel TEXT NOT NULL,
      categoria TEXT NOT NULL,
      descricao TEXT,
      local TEXT NOT NULL,
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (user_id) REFERENCES users(id)
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS cad_responsaveis (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      nome TEXT NOT NULL,
      UNIQUE(user_id, nome)
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS cad_categorias (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      nome TEXT NOT NULL,
      UNIQUE(user_id, nome)
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS cad_locais (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      nome TEXT NOT NULL,
      UNIQUE(user_id, nome)
    )
  `);

  // cria admin se não existir
  const adminEmail = (process.env.ADMIN_EMAIL || "").trim().toLowerCase();
  const adminPass = (process.env.ADMIN_PASSWORD || "").trim();

  const admin = await get("SELECT id, email, nome, role FROM users WHERE email = ?", [adminEmail]);

  if (!admin) {
    const hash = await bcrypt.hash(adminPass, 10);
    await run(
      "INSERT INTO users(email, password_hash, nome, role) VALUES(?,?,?,?)",
      [adminEmail, hash, "Administrador", "admin"]
    );
    console.log("✅ Usuário admin criado:", adminEmail);
  } else {
    // garante admin como admin
    await run("UPDATE users SET role='admin' WHERE email=?", [adminEmail]);

    // se nome estiver vazio, coloca "Administrador"
    await run(
      "UPDATE users SET nome = CASE WHEN nome IS NULL OR nome = '' THEN 'Administrador' ELSE nome END WHERE email=?",
      [adminEmail]
    );
  }
}

module.exports = { db, run, get, all, init };

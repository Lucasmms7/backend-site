require("dotenv").config();
const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

const { init, get, all, run } = require("./db");
const { auth } = require("./middlewareAuth");

const app = express();
app.use(express.json());

// Libera o front (Live Server)
app.use(cors({ origin: true, credentials: true }));

// ====== Helpers ======
async function isAdmin(userId) {
  const u = await get("SELECT id, role FROM users WHERE id=?", [userId]);
  return !!u && u.role === "admin";
}

// ====== AUTH ======
app.post("/api/auth/login", async (req, res) => {
  const email = (req.body?.email || "").trim().toLowerCase();
  const password = (req.body?.password || "").trim();

  if (!email || !password) return res.status(400).json({ error: "Dados inválidos" });

  const user = await get("SELECT * FROM users WHERE email = ?", [email]);
  if (!user) return res.status(401).json({ error: "Credenciais inválidas" });

  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(401).json({ error: "Credenciais inválidas" });

  const token = jwt.sign(
    { id: user.id, email: user.email },
    process.env.JWT_SECRET,
    { expiresIn: "8h" }
  );

  res.json({
    token,
    user: {
      id: user.id,
      email: user.email,
      nome: user.nome || "",
      role: user.role || "user"
    }
  });
});

app.get("/api/auth/me", auth, async (req, res) => {
  // buscar dados completos (nome/role) do usuário logado
  const u = await get("SELECT id, email, nome, role FROM users WHERE id=?", [req.user.id]);
  if (!u) return res.status(401).json({ error: "Usuário não encontrado" });

  res.json({ user: u });
});

// ====== USUÁRIOS (ADMIN) ======
app.get("/api/users", auth, async (req, res) => {
  const admin = await isAdmin(req.user.id);
  if (!admin) return res.status(403).json({ error: "Apenas admin" });

  const users = await all(
    "SELECT id, nome, email, role, created_at FROM users ORDER BY id DESC"
  );

  res.json({ users });
});

app.post("/api/users", auth, async (req, res) => {
  const admin = await isAdmin(req.user.id);
  if (!admin) return res.status(403).json({ error: "Apenas admin" });

  const nome = (req.body?.nome || "").trim();
  const email = (req.body?.email || "").trim().toLowerCase();
  const password = (req.body?.password || "").trim();
  const role = (req.body?.role || "user").trim();

  if (!nome) return res.status(400).json({ error: "Nome é obrigatório" });
  if (!email) return res.status(400).json({ error: "E-mail é obrigatório" });
  if (!password || password.length < 4) {
    return res.status(400).json({ error: "Senha precisa ter pelo menos 4 caracteres" });
  }
  if (!["admin", "user"].includes(role)) {
    return res.status(400).json({ error: "Perfil inválido" });
  }

  const exists = await get("SELECT id FROM users WHERE email=?", [email]);
  if (exists) return res.status(409).json({ error: "Este e-mail já está cadastrado" });

  const hash = await bcrypt.hash(password, 10);
  await run(
    "INSERT INTO users(nome, email, password_hash, role) VALUES(?,?,?,?)",
    [nome, email, hash, role]
  );

  res.json({ ok: true });
});

app.delete("/api/users/:id", auth, async (req, res) => {
  const admin = await isAdmin(req.user.id);
  if (!admin) return res.status(403).json({ error: "Apenas admin" });

  const id = Number(req.params.id);
  if (!Number.isFinite(id)) return res.status(400).json({ error: "ID inválido" });

  // não permite deletar a si mesmo
  if (id === req.user.id) {
    return res.status(400).json({ error: "Você não pode excluir seu próprio usuário" });
  }

  // apaga tudo do usuário (para não sobrar dados no banco)
  await run("DELETE FROM despesas WHERE user_id=?", [id]);
  await run("DELETE FROM cad_responsaveis WHERE user_id=?", [id]);
  await run("DELETE FROM cad_categorias WHERE user_id=?", [id]);
  await run("DELETE FROM cad_locais WHERE user_id=?", [id]);
  await run("DELETE FROM users WHERE id=?", [id]);

  res.json({ ok: true });
});

// ====== CADASTROS (responsáveis, categorias, locais) ======
async function listCadastro(table, userId) {
  return all(`SELECT id, nome FROM ${table} WHERE user_id=? ORDER BY nome ASC`, [userId]);
}

async function addCadastro(table, userId, nome) {
  await run(`INSERT OR IGNORE INTO ${table}(user_id, nome) VALUES(?,?)`, [userId, nome]);
}

async function delCadastro(table, userId, id) {
  await run(`DELETE FROM ${table} WHERE user_id=? AND id=?`, [userId, id]);
}

app.get("/api/cadastros", auth, async (req, res) => {
  const userId = req.user.id;
  const responsaveis = await listCadastro("cad_responsaveis", userId);
  const categorias = await listCadastro("cad_categorias", userId);
  const locais = await listCadastro("cad_locais", userId);
  res.json({ responsaveis, categorias, locais });
});

app.post("/api/cadastros/responsaveis", auth, async (req, res) => {
  const nome = (req.body?.nome || "").trim();
  if (!nome) return res.status(400).json({ error: "Nome obrigatório" });
  await addCadastro("cad_responsaveis", req.user.id, nome);
  res.json({ ok: true });
});

app.post("/api/cadastros/categorias", auth, async (req, res) => {
  const nome = (req.body?.nome || "").trim();
  if (!nome) return res.status(400).json({ error: "Nome obrigatório" });
  await addCadastro("cad_categorias", req.user.id, nome);
  res.json({ ok: true });
});

app.post("/api/cadastros/locais", auth, async (req, res) => {
  const nome = (req.body?.nome || "").trim();
  if (!nome) return res.status(400).json({ error: "Nome obrigatório" });
  await addCadastro("cad_locais", req.user.id, nome);
  res.json({ ok: true });
});

app.delete("/api/cadastros/:tipo/:id", auth, async (req, res) => {
  const { tipo, id } = req.params;
  const map = {
    responsaveis: "cad_responsaveis",
    categorias: "cad_categorias",
    locais: "cad_locais",
  };

  const table = map[tipo];
  if (!table) return res.status(400).json({ error: "Tipo inválido" });

  await delCadastro(table, req.user.id, Number(id));
  res.json({ ok: true });
});

// ====== EDITAR CADASTROS (PUT) ======
app.put("/api/cadastros/:tipo/:id", auth, async (req, res) => {
  const { tipo, id } = req.params;
  const nome = (req.body?.nome || "").trim();

  if (!nome) return res.status(400).json({ error: "Nome obrigatório" });

  const map = {
    responsaveis: "cad_responsaveis",
    categorias: "cad_categorias",
    locais: "cad_locais",
  };

  const table = map[tipo];
  if (!table) return res.status(400).json({ error: "Tipo inválido" });

  await run(`UPDATE ${table} SET nome=? WHERE user_id=? AND id=?`, [
    nome,
    req.user.id,
    Number(id),
  ]);

  res.json({ ok: true });
});

// ====== DESPESAS ======
app.post("/api/despesas", auth, async (req, res) => {
  const userId = req.user.id;
  const { data, valor, responsavel, categoria, descricao, local } = req.body || {};

  if (!data || !responsavel || !categoria || !local) {
    return res.status(400).json({ error: "Campos obrigatórios faltando" });
  }

  const v = Number(valor);
  if (!Number.isFinite(v) || v <= 0) return res.status(400).json({ error: "Valor inválido" });

  await run(
    `INSERT INTO despesas(user_id, data, valor, responsavel, categoria, descricao, local)
     VALUES(?,?,?,?,?,?,?)`,
    [userId, data, v, responsavel, categoria, (descricao || "").trim(), local]
  );

  res.json({ ok: true });
});

app.get("/api/despesas", auth, async (req, res) => {
  const userId = req.user.id;
  const { ano, mes } = req.query;

  let where = "WHERE user_id=?";
  const params = [userId];

  if (ano) {
    where += " AND substr(data,1,4)=?";
    params.push(String(ano));
  }

  if (mes) {
    const mm = String(mes).padStart(2, "0");
    where += " AND substr(data,6,2)=?";
    params.push(mm);
  }

  const rows = await all(
    `SELECT id, data, valor, responsavel, categoria, descricao, local
     FROM despesas
     ${where}
     ORDER BY data DESC, id DESC`,
    params
  );

  res.json({ despesas: rows });
});

// EDITAR DESPESA (PUT)
app.put("/api/despesas/:id", auth, async (req, res) => {
  const userId = req.user.id;
  const id = Number(req.params.id);

  const { data, valor, responsavel, categoria, descricao, local } = req.body || {};

  if (!data || !responsavel || !categoria || !local) {
    return res.status(400).json({ error: "Campos obrigatórios faltando" });
  }

  const v = Number(valor);
  if (!Number.isFinite(v) || v <= 0) {
    return res.status(400).json({ error: "Valor inválido" });
  }

  await run(
    `UPDATE despesas
     SET data=?, valor=?, responsavel=?, categoria=?, descricao=?, local=?
     WHERE user_id=? AND id=?`,
    [data, v, responsavel, categoria, (descricao || "").trim(), local, userId, id]
  );

  res.json({ ok: true });
});

// EXCLUIR DESPESA (DELETE)
app.delete("/api/despesas/:id", auth, async (req, res) => {
  const userId = req.user.id;
  const id = Number(req.params.id);

  await run("DELETE FROM despesas WHERE user_id=? AND id=?", [userId, id]);
  res.json({ ok: true });
});

// ====== START ======
init().then(() => {
  app.listen(process.env.PORT || 3000, () => {
    console.log(`✅ Backend rodando em http://localhost:${process.env.PORT || 3000}`);
  });
});

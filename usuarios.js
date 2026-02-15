// ===== Tema (Auto / Escuro / Claro) =====
const btnTema = document.getElementById("btnTema");

function temaAtualDoSistema() {
  return window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

function atualizarTextoBotaoTema() {
  if (!btnTema) return;

  const atual = document.documentElement.getAttribute("data-theme"); // "dark" | "light" | null
  if (!atual) {
    btnTema.textContent = "Tema: Auto";
    return;
  }

  if (atual === "dark") {
    btnTema.textContent = "Tema: Escuro";
    return;
  }

  if (atual === "light") {
    btnTema.textContent = "Tema: Claro";
    return;
  }

  btnTema.textContent = "Tema: Auto";
}

function aplicarTema(tema) {
  if (tema === "dark" || tema === "light") {
    document.documentElement.setAttribute("data-theme", tema);
  } else {
    document.documentElement.removeAttribute("data-theme");
  }
  atualizarTextoBotaoTema();
}

function carregarTema() {
  const salvo = localStorage.getItem("theme"); // "dark" | "light" | null

  if (salvo === "dark" || salvo === "light") {
    aplicarTema(salvo);
    return;
  }

  aplicarTema(null); // Auto
}

function alternarTema() {
  const atual = document.documentElement.getAttribute("data-theme"); // "dark" | "light" | null
  const sistema = temaAtualDoSistema();

  // Auto -> oposto do sistema -> igual ao sistema -> Auto
  if (!atual) {
    const prox = sistema === "dark" ? "light" : "dark";
    localStorage.setItem("theme", prox);
    aplicarTema(prox);
    return;
  }

  if (atual === "dark") {
    localStorage.setItem("theme", "light");
    aplicarTema("light");
    return;
  }

  if (atual === "light") {
    localStorage.removeItem("theme");
    aplicarTema(null);
    return;
  }

  localStorage.removeItem("theme");
  aplicarTema(null);
}

carregarTema();

if (btnTema) {
  btnTema.addEventListener("click", alternarTema);
}

const mediaTema = window.matchMedia ? window.matchMedia("(prefers-color-scheme: dark)") : null;
if (mediaTema && typeof mediaTema.addEventListener === "function") {
  mediaTema.addEventListener("change", () => {
    const salvo = localStorage.getItem("theme");
    if (!salvo) aplicarTema(null);
  });
}


const API = "http://localhost:3000";
const token = localStorage.getItem("token");

if (!token) window.location.href = "login.html";

function authHeaders() {
  return {
    "Content-Type": "application/json",
    "Authorization": `Bearer ${token}`
  };
}

const btnSair = document.getElementById("btnSair");
const formUser = document.getElementById("formUser");
const msg = document.getElementById("msg");

const elNome = document.getElementById("nome");
const elEmail = document.getElementById("email");
const elPass = document.getElementById("password");
const elRole = document.getElementById("role");

const listaUsers = document.getElementById("listaUsers");

function setMsg(text, type) {
  msg.textContent = text || "";
  msg.classList.remove("msg--error", "msg--ok");
  if (type === "error") msg.classList.add("msg--error");
  if (type === "ok") msg.classList.add("msg--ok");
}

btnSair.addEventListener("click", () => {
  localStorage.removeItem("token");
  window.location.href = "login.html";
});

async function apiGet(path) {
  const r = await fetch(`${API}${path}`, { headers: authHeaders() });
  const data = await r.json().catch(() => ({}));
  return { ok: r.ok, status: r.status, data };
}

async function apiPost(path, body) {
  const r = await fetch(`${API}${path}`, {
    method: "POST",
    headers: authHeaders(),
    body: JSON.stringify(body)
  });
  const data = await r.json().catch(() => ({}));
  return { ok: r.ok, status: r.status, data };
}

async function apiDel(path) {
  const r = await fetch(`${API}${path}`, {
    method: "DELETE",
    headers: authHeaders()
  });
  const data = await r.json().catch(() => ({}));
  return { ok: r.ok, status: r.status, data };
}

function renderUsers(users) {
  listaUsers.innerHTML = "";

  if (!users.length) {
    listaUsers.innerHTML = `<div class="muted">Nenhum usuário cadastrado.</div>`;
    return;
  }

  users.forEach(u => {
    const row = document.createElement("div");
    row.className = "listRow";

    row.innerHTML = `
      <div>
        <div style="font-weight:900;">
          ${u.nome || "(Sem nome)"} <span class="muted" style="font-weight:600;">(${u.role})</span>
        </div>
        <div class="muted">${u.email}</div>
        <div class="muted" style="font-size:12px;">Criado em: ${u.created_at || "-"}</div>
      </div>
      <div class="actions">
        <button class="pill pill--danger" data-del="${u.id}">Excluir</button>
      </div>
    `;

    listaUsers.appendChild(row);
  });

  listaUsers.querySelectorAll("[data-del]").forEach(btn => {
    btn.addEventListener("click", async () => {
      const id = btn.getAttribute("data-del");

      const ok = confirm("Tem certeza que deseja excluir este usuário?\n\nAtenção: isso também apaga as despesas e cadastros desse usuário.");
      if (!ok) return;

      const r = await apiDel(`/api/users/${id}`);
      if (!r.ok) {
        alert(r.data?.error || "Erro ao excluir usuário.");
        return;
      }

      await carregar();
    });
  });
}

async function carregar() {
  setMsg("", "");

  const r = await apiGet("/api/users");

  if (!r.ok) {
    if (r.status === 401) {
      localStorage.removeItem("token");
      window.location.href = "login.html";
      return;
    }

    listaUsers.innerHTML = `<div class="muted">Você precisa ser admin para acessar esta tela.</div>`;
    return;
  }

  renderUsers(r.data.users || []);
}

formUser.addEventListener("submit", async (e) => {
  e.preventDefault();

  const nome = (elNome.value || "").trim();
  const email = (elEmail.value || "").trim().toLowerCase();
  const password = (elPass.value || "").trim();
  const role = (elRole.value || "user").trim();

  if (!nome) return setMsg("Informe o nome.", "error");
  if (!email) return setMsg("Informe o e-mail.", "error");
  if (!password || password.length < 4) return setMsg("A senha precisa ter pelo menos 4 caracteres.", "error");
  if (!["admin", "user"].includes(role)) return setMsg("Perfil inválido.", "error");

  setMsg("Cadastrando usuário...", "ok");

  const r = await apiPost("/api/users", { nome, email, password, role });

  if (!r.ok) {
    setMsg(r.data?.error || "Erro ao cadastrar usuário.", "error");
    return;
  }

  setMsg("Usuário cadastrado com sucesso!", "ok");
  formUser.reset();
  elRole.value = "user";

  await carregar();
});

carregar();

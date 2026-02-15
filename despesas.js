const API = "http://localhost:3000";
const token = localStorage.getItem("token");

if (!token) window.location.href = "login.html";

function authHeaders() {
  return { "Content-Type": "application/json", "Authorization": `Bearer ${token}` };
}

document.getElementById("btnSair").addEventListener("click", () => {
  localStorage.removeItem("token");
  window.location.href = "login.html";
});

// ===== DOM =====
const formDespesa = document.getElementById("formDespesa");
const msgDespesa = document.getElementById("msgDespesa");

const elData = document.getElementById("data");
const elValor = document.getElementById("valor");
const elResp = document.getElementById("responsavel");
const elCat = document.getElementById("categoria");
const elLocal = document.getElementById("local");
const elDesc = document.getElementById("descricao");

const tbody = document.getElementById("tbodyRelatorio");
const totalFiltro = document.getElementById("totalFiltro");
const ultimaDespesa = document.getElementById("ultimaDespesa");

const filtroMes = document.getElementById("filtroMes");
const filtroAno = document.getElementById("filtroAno");
const btnFiltrar = document.getElementById("btnFiltrar");

const btnCsv = document.getElementById("btnCsv");
const btnPdf = document.getElementById("btnPdf");

// Botão "Usuários" (aparece só para admin)
const btnUsuarios = document.getElementById("btnUsuarios");
const infoUsuario = document.getElementById("infoUsuario");

// Botão de Tema
const btnTema = document.getElementById("btnTema");

const gridMeses = document.getElementById("gridMeses");
const totalAnoLabel = document.getElementById("totalAnoLabel");
const qtdAnoLabel = document.getElementById("qtdAnoLabel");
const anoLabel = document.getElementById("anoLabel");
const exercicioLabel = document.getElementById("exercicioLabel");

const formResp = document.getElementById("formResp");
const formCat = document.getElementById("formCat");
const formLocal = document.getElementById("formLocal");

const novoResp = document.getElementById("novoResp");
const novaCat = document.getElementById("novaCat");
const novoLocal = document.getElementById("novoLocal");

const listaCategorias = document.getElementById("listaCategorias");
const listaResponsaveis = document.getElementById("listaResponsaveis");
const listaLocais = document.getElementById("listaLocais");

const btnSalvarDespesa = document.getElementById("btnSalvarDespesa");
const btnCancelarEdicao = document.getElementById("btnCancelarEdicao");

// ===== Charts DOM =====
const chartMesesEl = document.getElementById("chartMeses");
const chartCategoriasEl = document.getElementById("chartCategorias");
const chartResponsaveisEl = document.getElementById("chartResponsaveis");

let chartMeses = null;
let chartCategorias = null;
let chartResponsaveis = null;

// ===== Estado =====
let despesaEmEdicaoId = null;
let cacheDespesasAno = [];

// ===== Config do PDF (empresa e logo) =====
const NOME_EMPRESA = "CONTROLE DE DESPESAS";
const SUBTITULO_EMPRESA = "ATHOS GESTÃO CONTABILIDADE E ACESSORIA";
const LOGO_PATH = "athos.png";

// ===== Tema (Auto / Escuro / Claro) =====
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
    // Auto: remove para usar o CSS com prefers-color-scheme
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

  // Ciclo:
  // Auto -> (oposto do sistema) -> (igual ao sistema) -> Auto
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

if (btnTema) {
  btnTema.addEventListener("click", alternarTema);
}

// Se o tema do sistema mudar enquanto estiver em Auto, atualiza automaticamente
const mediaTema = window.matchMedia ? window.matchMedia("(prefers-color-scheme: dark)") : null;
if (mediaTema && typeof mediaTema.addEventListener === "function") {
  mediaTema.addEventListener("change", () => {
    const salvo = localStorage.getItem("theme");
    if (!salvo) aplicarTema(null);
  });
}

// ===== Utils =====
function setMsg(el, text, type) {
  el.textContent = text || "";
  el.classList.remove("msg--error", "msg--ok");
  if (type === "error") el.classList.add("msg--error");
  if (type === "ok") el.classList.add("msg--ok");
}

function brMoneyToNumber(v) {
  const s = (v || "").toString().trim().replace(/\./g, "").replace(",", ".");
  const n = Number(s);
  return Number.isFinite(n) ? n : NaN;
}

function numberToBRMoney(n) {
  const v = Number(n) || 0;
  return v.toLocaleString("pt-BR", { style: "currency", currency: "BRL" });
}

function pad2(n) { return String(n).padStart(2, "0"); }

function todayISO() {
  const d = new Date();
  return `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())}`;
}

const meses = ["Jan","Fev","Mar","Abr","Mai","Jun","Jul","Ago","Set","Out","Nov","Dez"];

function destroyChart(ch) {
  if (ch && typeof ch.destroy === "function") ch.destroy();
}

function groupSumBy(list, key) {
  const map = new Map();
  (list || []).forEach(item => {
    const k = (item?.[key] || "Não informado").toString();
    const v = Number(item?.valor) || 0;
    map.set(k, (map.get(k) || 0) + v);
  });
  return map;
}

function mapToSortedArrays(map) {
  const arr = Array.from(map.entries()).map(([label, total]) => ({ label, total }));
  arr.sort((a, b) => b.total - a.total);
  return {
    labels: arr.map(x => x.label),
    values: arr.map(x => x.total),
  };
}

// ===== Render selects (cadastros) =====
function renderSelect(selectEl, items, placeholder) {
  selectEl.innerHTML = "";
  const opt0 = document.createElement("option");
  opt0.value = "";
  opt0.textContent = placeholder;
  selectEl.appendChild(opt0);

  (items || []).forEach(it => {
    const opt = document.createElement("option");
    opt.value = it.nome;
    opt.textContent = it.nome;
    selectEl.appendChild(opt);
  });
}

// ===== API =====
async function apiGet(path) {
  const r = await fetch(`${API}${path}`, { headers: authHeaders() });
  if (r.status === 401) { localStorage.removeItem("token"); window.location.href = "login.html"; }
  return r.json();
}

async function apiPost(path, body) {
  const r = await fetch(`${API}${path}`, { method: "POST", headers: authHeaders(), body: JSON.stringify(body) });
  if (r.status === 401) { localStorage.removeItem("token"); window.location.href = "login.html"; }
  return { ok: r.ok, data: await r.json() };
}

async function apiDel(path) {
  const r = await fetch(`${API}${path}`, { method: "DELETE", headers: authHeaders() });
  if (r.status === 401) { localStorage.removeItem("token"); window.location.href = "login.html"; }
  return r.json();
}

async function apiPut(path, body) {
  const r = await fetch(`${API}${path}`, { method: "PUT", headers: authHeaders(), body: JSON.stringify(body) });
  if (r.status === 401) { localStorage.removeItem("token"); window.location.href = "login.html"; }
  return { ok: r.ok, data: await r.json() };
}

// ===== Permissões: mostrar botão Usuários apenas para admin =====
async function aplicarPermissoes() {
  if (!btnUsuarios && !infoUsuario) return;

  try {
    const data = await apiGet("/api/auth/me");
    const user = data?.user || {};
    const nome = user.nome || user.email || "Usuário";
    const role = user.role || "user";

    if (infoUsuario) {
      infoUsuario.textContent = `Usuário: ${nome} (${role})`;
    }

    if (btnUsuarios) {
      btnUsuarios.style.display = role === "admin" ? "inline-flex" : "none";
    }

  } catch (e) {
    if (btnUsuarios) btnUsuarios.style.display = "none";
  }
}

// ===== Modo edição de despesa =====
function entrarModoEdicaoDespesa(d) {
  despesaEmEdicaoId = d.id;

  elData.value = d.data;
  elValor.value = String(d.valor).replace(".", ",");
  elDesc.value = d.descricao || "";

  elResp.value = d.responsavel;
  elCat.value = d.categoria;
  elLocal.value = d.local;

  if (btnSalvarDespesa) btnSalvarDespesa.textContent = "Salvar alterações";
  if (btnCancelarEdicao) btnCancelarEdicao.style.display = "block";

  setMsg(msgDespesa, "Modo edição ativado. Altere os campos e clique em Salvar alterações ou Cancelar edição.", "ok");
  window.scrollTo({ top: 0, behavior: "smooth" });
}

function sairModoEdicaoDespesa() {
  despesaEmEdicaoId = null;

  formDespesa.reset();
  elData.value = todayISO();

  if (btnSalvarDespesa) btnSalvarDespesa.textContent = "Salvar despesa";
  if (btnCancelarEdicao) btnCancelarEdicao.style.display = "none";

  setMsg(msgDespesa, "", "");
}

if (btnCancelarEdicao) {
  btnCancelarEdicao.addEventListener("click", () => {
    sairModoEdicaoDespesa();
  });
}

// ===== CADASTROS (listas com editar/excluir) =====
function renderListaCadastro(tipo, itens, container, msgVazio) {
  container.innerHTML = "";

  if (!itens || !itens.length) {
    container.innerHTML = `<div class="muted">${msgVazio}</div>`;
    return;
  }

  itens.forEach(item => {
    const row = document.createElement("div");
    row.className = "listRow";

    row.innerHTML = `
      <div>${item.nome}</div>
      <div class="actions">
        <button class="pill" data-edit="${tipo}:${item.id}:${encodeURIComponent(item.nome)}">Editar</button>
        <button class="pill pill--danger" data-del="${tipo}:${item.id}">Excluir</button>
      </div>
    `;

    container.appendChild(row);
  });

  container.querySelectorAll("[data-del]").forEach(btn => {
    btn.addEventListener("click", async () => {
      const [t, id] = btn.getAttribute("data-del").split(":");
      await apiDel(`/api/cadastros/${t}/${id}`);
      await refreshUI();
    });
  });

  container.querySelectorAll("[data-edit]").forEach(btn => {
    btn.addEventListener("click", async () => {
      const raw = btn.getAttribute("data-edit");
      const [t, id, nomeEncoded] = raw.split(":");
      const nomeAtual = decodeURIComponent(nomeEncoded);

      const novoNome = prompt(
        `Modificar ${t}:\n\nNome atual: ${nomeAtual}\n\nDigite o novo nome:`,
        nomeAtual
      );
      if (novoNome === null) return;

      const nomeFinal = (novoNome || "").trim();
      if (!nomeFinal) return;

      const r = await apiPut(`/api/cadastros/${t}/${id}`, { nome: nomeFinal });
      if (!r.ok) {
        alert(r.data?.error || "Erro ao modificar.");
        return;
      }

      await refreshUI();
    });
  });
}

async function carregarCadastros() {
  const data = await apiGet("/api/cadastros");
  if (!data) return;

  renderSelect(elResp, data.responsaveis, "Selecione ou cadastre um responsável");
  renderSelect(elCat, data.categorias, "Selecione a categoria");
  renderSelect(elLocal, data.locais, "Selecione o local");

  renderListaCadastro("responsaveis", data.responsaveis, listaResponsaveis, "Nenhum responsável cadastrado ainda.");
  renderListaCadastro("categorias", data.categorias, listaCategorias, "Nenhuma categoria cadastrada ainda.");
  renderListaCadastro("locais", data.locais, listaLocais, "Nenhum local cadastrado ainda.");
}

// ===== Despesas =====
async function carregarAnos() {
  const nowY = new Date().getFullYear();
  filtroAno.innerHTML = `<option value="${nowY}">${nowY}</option>`;
  filtroAno.value = String(nowY);
}

async function carregarDespesas() {
  const ano = filtroAno.value;
  const mes = filtroMes.value || "";

  const q = new URLSearchParams();
  if (ano) q.set("ano", ano);
  if (mes) q.set("mes", mes);

  const data = await apiGet(`/api/despesas?${q.toString()}`);
  return data.despesas || [];
}

function renderMonthCards(despesasAno) {
  gridMeses.innerHTML = "";

  const stats = Array.from({ length: 12 }, (_, i) => ({ month: i + 1, total: 0, qtd: 0 }));

  (despesasAno || []).forEach(d => {
    const m = Number((d.data || "").split("-")[1]);
    if (m >= 1 && m <= 12) {
      stats[m - 1].total += Number(d.valor) || 0;
      stats[m - 1].qtd += 1;
    }
  });

  stats.forEach((s, idx) => {
    const div = document.createElement("div");
    div.className = "month";
    div.dataset.month = String(s.month);
    div.innerHTML = `
      <div class="m">${meses[idx]}</div>
      <div class="s">${numberToBRMoney(s.total)} • ${s.qtd} despesa(s)</div>
    `;

    div.addEventListener("click", async () => {
      filtroMes.value = String(s.month);
      await refreshRelatorio();
    });

    gridMeses.appendChild(div);
  });

  const totalAno = stats.reduce((a, s) => a + s.total, 0);
  const qtdAno = stats.reduce((a, s) => a + s.qtd, 0);

  totalAnoLabel.textContent = numberToBRMoney(totalAno);
  qtdAnoLabel.textContent = String(qtdAno);
  anoLabel.textContent = filtroAno.value;
  exercicioLabel.textContent = filtroAno.value;
}

function renderTabela(list) {
  tbody.innerHTML = "";

  if (!list || !list.length) {
    tbody.innerHTML = `<tr><td colspan="7" class="muted">Sem registros para o filtro selecionado.</td></tr>`;
    totalFiltro.textContent = numberToBRMoney(0);
    ultimaDespesa.textContent = "Nenhuma despesa cadastrada neste exercício.";
    ultimaDespesa.className = "muted";
    return;
  }

  const total = list.reduce((acc, d) => acc + (Number(d.valor) || 0), 0);
  totalFiltro.textContent = numberToBRMoney(total);

  const u = list[0];
  ultimaDespesa.className = "";
  ultimaDespesa.innerHTML = `
    <b>${u.data}</b> — ${u.categoria} — ${numberToBRMoney(u.valor)}<br>
    <span class="muted">${u.responsavel} • ${u.local}${u.descricao ? " • " + u.descricao : ""}</span>
  `;

  list.forEach(d => {
    const tr = document.createElement("tr");
    const dJson = encodeURIComponent(JSON.stringify(d));

    tr.innerHTML = `
      <td>${d.data}</td>
      <td>${d.categoria}</td>
      <td>${d.descricao || ""}</td>
      <td>${d.local}</td>
      <td>${d.responsavel}</td>
      <td>${numberToBRMoney(d.valor)}</td>
      <td>
        <div class="actions">
          <button class="pill" data-edit-desp="${dJson}">Editar</button>
          <button class="pill pill--danger" data-del="${d.id}">Excluir</button>
        </div>
      </td>
    `;

    tbody.appendChild(tr);
  });

  tbody.querySelectorAll("[data-del]").forEach(btn => {
    btn.addEventListener("click", async () => {
      const id = btn.getAttribute("data-del");
      await apiDel(`/api/despesas/${id}`);
      await refreshRelatorio();
      await refreshResumo();

      if (despesaEmEdicaoId && String(despesaEmEdicaoId) === String(id)) {
        sairModoEdicaoDespesa();
      }
    });
  });

  tbody.querySelectorAll("[data-edit-desp]").forEach(btn => {
    btn.addEventListener("click", async () => {
      const raw = btn.getAttribute("data-edit-desp");
      const d = JSON.parse(decodeURIComponent(raw));

      await carregarCadastros();
      entrarModoEdicaoDespesa(d);
    });
  });
}

// ===== Gráficos =====
function renderGraficos(despesasAno, despesasFiltradas) {
  const totalsMes = Array.from({ length: 12 }, () => 0);
  (despesasAno || []).forEach(d => {
    const m = Number((d.data || "").split("-")[1]);
    if (m >= 1 && m <= 12) totalsMes[m - 1] += Number(d.valor) || 0;
  });

  destroyChart(chartMeses);
  if (chartMesesEl && typeof Chart !== "undefined") {
    chartMeses = new Chart(chartMesesEl, {
      type: "bar",
      data: { labels: meses, datasets: [{ label: "Total por mês (R$)", data: totalsMes }] },
      options: {
        responsive: true,
        plugins: {
          legend: { display: false },
          tooltip: { callbacks: { label: (ctx) => numberToBRMoney(ctx.parsed.y) } }
        },
        scales: {
          y: { ticks: { callback: (v) => numberToBRMoney(v) } }
        }
      }
    });
  }

  const base = (filtroMes && filtroMes.value) ? (despesasFiltradas || []) : (despesasAno || []);

  const catMap = groupSumBy(base, "categoria");
  const cat = mapToSortedArrays(catMap);

  destroyChart(chartCategorias);
  if (chartCategoriasEl && typeof Chart !== "undefined") {
    chartCategorias = new Chart(chartCategoriasEl, {
      type: "doughnut",
      data: { labels: cat.labels, datasets: [{ label: "Categorias", data: cat.values }] },
      options: {
        responsive: true,
        plugins: {
          legend: { position: "bottom" },
          tooltip: { callbacks: { label: (ctx) => `${ctx.label}: ${numberToBRMoney(ctx.parsed)}` } }
        }
      }
    });
  }

  const respMap = groupSumBy(base, "responsavel");
  const resp = mapToSortedArrays(respMap);

  destroyChart(chartResponsaveis);
  if (chartResponsaveisEl && typeof Chart !== "undefined") {
    chartResponsaveis = new Chart(chartResponsaveisEl, {
      type: "bar",
      data: { labels: resp.labels, datasets: [{ label: "Responsáveis (R$)", data: resp.values }] },
      options: {
        indexAxis: "y",
        responsive: true,
        plugins: {
          legend: { display: false },
          tooltip: { callbacks: { label: (ctx) => numberToBRMoney(ctx.parsed.x) } }
        },
        scales: {
          x: { ticks: { callback: (v) => numberToBRMoney(v) } }
        }
      }
    });
  }
}

// ===== Resumo / Relatório / UI =====
async function refreshResumo() {
  const ano = filtroAno.value;
  const data = await apiGet(`/api/despesas?ano=${ano}`);
  cacheDespesasAno = data.despesas || [];
  renderMonthCards(cacheDespesasAno);
}

async function refreshRelatorio() {
  const list = await carregarDespesas();
  renderTabela(list);

  document.querySelectorAll(".month").forEach(el => {
    const m = Number(el.dataset.month);
    el.classList.toggle("is-active", filtroMes.value ? m === Number(filtroMes.value) : false);
  });

  renderGraficos(cacheDespesasAno, list);
}

async function refreshUI() {
  await carregarCadastros();
  await refreshResumo();
  await refreshRelatorio();
}

// ===== Exportação CSV =====
function exportarCSV(despesas) {
  if (!despesas || !despesas.length) {
    alert("Não há dados para exportar.");
    return;
  }

  const linhas = [
    ["Data", "Categoria", "Descrição", "Local", "Responsável", "Valor"]
  ];

  despesas.forEach(d => {
    linhas.push([
      d.data,
      d.categoria,
      d.descricao || "",
      d.local,
      d.responsavel,
      String(d.valor).replace(".", ",")
    ]);
  });

  const csv = linhas.map(l => l.join(";")).join("\n");
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);

  const a = document.createElement("a");
  a.href = url;
  a.download = "relatorio_despesas.csv";
  a.click();

  URL.revokeObjectURL(url);
}

// ===== PDF com logo + nome da empresa =====
function getImageTypeFromPath(path) {
  const p = (path || "").toLowerCase();
  if (p.endsWith(".png")) return "PNG";
  return "JPEG";
}

function carregarImagemComoDataURL(src) {
  return new Promise((resolve, reject) => {
    const img = new Image();
    img.crossOrigin = "anonymous";

    img.onload = () => {
      const canvas = document.createElement("canvas");
      canvas.width = img.width;
      canvas.height = img.height;
      const ctx = canvas.getContext("2d");
      ctx.drawImage(img, 0, 0);

      const type = getImageTypeFromPath(src) === "PNG" ? "image/png" : "image/jpeg";
      const dataURL = canvas.toDataURL(type, 0.92);

      resolve({ dataURL, type: getImageTypeFromPath(src) });
    };

    img.onerror = () => reject(new Error("Não foi possível carregar a imagem da logo."));
    img.src = src;
  });
}

function exportarPDFComLogo(despesas, logoData) {
  if (!despesas || !despesas.length) {
    alert("Não há dados para exportar.");
    return;
  }

  const { jsPDF } = window.jspdf;
  const doc = new jsPDF({ orientation: "landscape", unit: "mm", format: "a4" });

  const ano = filtroAno?.value || "";
  const mes = filtroMes?.value || "";
  const mesNome = mes ? meses[Number(mes) - 1] : "Todos";

  const agora = new Date();
  const dataHora = agora.toLocaleString("pt-BR");

  const pageW = 297;

  if (logoData && logoData.dataURL) {
    const logoW = 28;
    const logoH = 28;
    const xLogo = pageW - 14 - logoW;
    const yLogo = 8;
    doc.addImage(logoData.dataURL, logoData.type || "JPEG", xLogo, yLogo, logoW, logoH);
  }

  doc.setFont("helvetica", "bold");
  doc.setFontSize(15);
  doc.text(NOME_EMPRESA, 14, 12);

  doc.setFont("helvetica", "normal");
  doc.setFontSize(11);
  doc.text(SUBTITULO_EMPRESA, 14, 18);

  doc.setFont("helvetica", "bold");
  doc.setFontSize(14);
  doc.text("Relatório de Despesas", 14, 28);

  doc.setFont("helvetica", "normal");
  doc.setFontSize(10);
  doc.text(`Filtro: Ano ${ano} | Mês ${mesNome}`, 14, 34);
  doc.text(`Gerado em: ${dataHora}`, 14, 39);

  const total = despesas.reduce((acc, d) => acc + (Number(d.valor) || 0), 0);
  doc.setFont("helvetica", "bold");
  doc.text(`Total: ${numberToBRMoney(total)}`, 14, 45);

  const linhas = despesas.map(d => ([
    d.data,
    d.categoria,
    d.descricao || "",
    d.local,
    d.responsavel,
    numberToBRMoney(d.valor)
  ]));

  doc.autoTable({
    startY: 50,
    head: [["Data", "Categoria", "Descrição", "Local", "Responsável", "Valor"]],
    body: linhas,
    styles: { fontSize: 9, cellPadding: 2 },
    headStyles: { fontStyle: "bold" },
    columnStyles: {
      0: { cellWidth: 25 },
      1: { cellWidth: 40 },
      2: { cellWidth: 90 },
      3: { cellWidth: 45 },
      4: { cellWidth: 50 },
      5: { cellWidth: 30 }
    }
  });

  const sufixoMes = mes ? `_${pad2(Number(mes))}` : "";
  doc.save(`relatorio_despesas_${ano}${sufixoMes}.pdf`);
}

// ===== Eventos =====
formDespesa.addEventListener("submit", async (e) => {
  e.preventDefault();

  const data = elData.value;
  const valorN = brMoneyToNumber(elValor.value);

  if (!data) return setMsg(msgDespesa, "Informe a data.", "error");
  if (!Number.isFinite(valorN) || valorN <= 0) return setMsg(msgDespesa, "Informe um valor válido.", "error");
  if (!elResp.value) return setMsg(msgDespesa, "Selecione um responsável.", "error");
  if (!elCat.value) return setMsg(msgDespesa, "Selecione uma categoria.", "error");
  if (!elLocal.value) return setMsg(msgDespesa, "Selecione um local.", "error");

  const payload = {
    data,
    valor: valorN,
    responsavel: elResp.value,
    categoria: elCat.value,
    descricao: (elDesc.value || "").trim(),
    local: elLocal.value
  };

  let r;
  if (despesaEmEdicaoId) {
    r = await apiPut(`/api/despesas/${despesaEmEdicaoId}`, payload);
  } else {
    r = await apiPost("/api/despesas", payload);
  }

  if (!r.ok) return setMsg(msgDespesa, r.data?.error || "Erro ao salvar.", "error");

  setMsg(msgDespesa, despesaEmEdicaoId ? "Despesa atualizada com sucesso!" : "Despesa salva com sucesso!", "ok");

  sairModoEdicaoDespesa();
  await refreshRelatorio();
  await refreshResumo();
});

btnFiltrar.addEventListener("click", async () => {
  await refreshRelatorio();
});

formResp.addEventListener("submit", async (e) => {
  e.preventDefault();
  const nome = (novoResp.value || "").trim();
  if (!nome) return;

  await apiPost("/api/cadastros/responsaveis", { nome });
  novoResp.value = "";
  await refreshUI();
});

formCat.addEventListener("submit", async (e) => {
  e.preventDefault();
  const nome = (novaCat.value || "").trim();
  if (!nome) return;

  await apiPost("/api/cadastros/categorias", { nome });
  novaCat.value = "";
  await refreshUI();
});

formLocal.addEventListener("submit", async (e) => {
  e.preventDefault();
  const nome = (novoLocal.value || "").trim();
  if (!nome) return;

  await apiPost("/api/cadastros/locais", { nome });
  novoLocal.value = "";
  await refreshUI();
});

if (btnCsv) {
  btnCsv.addEventListener("click", async () => {
    const despesas = await carregarDespesas();
    exportarCSV(despesas);
  });
}

if (btnPdf) {
  btnPdf.addEventListener("click", async () => {
    const despesas = await carregarDespesas();

    try {
      const logoData = await carregarImagemComoDataURL(LOGO_PATH);
      exportarPDFComLogo(despesas, logoData);
    } catch (err) {
      console.log(err);
      exportarPDFComLogo(despesas, null);
      alert("Não consegui carregar a logo. O PDF foi gerado sem a logo. Confira o nome do arquivo e se ele está na pasta do projeto.");
    }
  });
}

// ===== Init =====
(async function init() {
  // Tema primeiro (para não piscar)
  carregarTema();

  elData.value = todayISO();
  await carregarAnos();
  await refreshUI();

  await aplicarPermissoes();

  if (btnCancelarEdicao) btnCancelarEdicao.style.display = "none";

  // garante texto correto no botão
  atualizarTextoBotaoTema();
})();

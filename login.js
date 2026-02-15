const form = document.getElementById("loginForm");
const msg  = document.getElementById("msg");
const email = document.getElementById("email");
const password = document.getElementById("password");

const API = "http://localhost:3000";

function setMsg(text, type) {
  msg.textContent = text || "";
  msg.classList.remove("msg--error", "msg--ok");
  if (type === "error") msg.classList.add("msg--error");
  if (type === "ok") msg.classList.add("msg--ok");
}

form.addEventListener("submit", async (e) => {
  e.preventDefault();

  const evalue = email.value.trim();
  const pvalue = password.value.trim();

  if (!evalue || !pvalue) {
    setMsg("Preencha e-mail e senha.", "error");
    return;
  }

  setMsg("Conectando ao servidor...", "ok");

  try {
    const r = await fetch(`${API}/api/auth/login`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        email: evalue,
        password: pvalue
      })
    });

    const data = await r.json();

    if (!r.ok) {
      setMsg(data.error || "Falha no login.", "error");
      return;
    }

    // guarda o token (crachá digital)
    localStorage.setItem("token", data.token);

    setMsg("Login realizado com sucesso!", "ok");

    // vai para a tela de despesas
    window.location.href = "despesas.html";

  } catch (err) {
    setMsg("Erro ao conectar no backend. Verifique se o server está rodando.", "error");
  }
});

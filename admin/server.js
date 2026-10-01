const express = require("express");
const session = require("express-session");
const helmet = require("helmet");
const bcrypt = require("bcryptjs");

const app = express();
const PORT = process.env.PORT || 10000;
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || "peaceandunity42@gmail.com";
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH || "";
const SESSION_SECRET = process.env.SESSION_SECRET || "";

app.set("trust proxy", 1);
app.use(helmet());
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

app.use(session({
  secret: SESSION_SECRET || "disabled-until-session-secret-is-configured",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: 1000 * 60 * 60 * 8
  }
}));

function configured() {
  return Boolean(ADMIN_PASSWORD_HASH && SESSION_SECRET);
}

function requireAuth(req, res, next) {
  if (!req.session.authenticated) return res.redirect("/login");
  next();
}

app.get("/health", (req, res) => {
  res.status(200).json({
    ok: true,
    service: "Peace & Unity Admin",
    configured: configured()
  });
});

app.get("/", (req, res) => {
  if (req.session.authenticated) return res.redirect("/dashboard");
  return res.redirect("/login");
});

app.get("/login", (req, res) => {
  res.type("html").send(`<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Peace & Unity — Admin Login</title>
<style>
body{margin:0;background:#f5f2e9;color:#17352d;font-family:Arial,sans-serif;min-height:100vh;display:grid;place-items:center;padding:20px}
.card{width:min(420px,100%);background:#fffdf8;padding:34px;border-radius:20px;box-shadow:0 18px 50px #17352d18}
h1{font:40px Georgia,serif;margin:0 0 8px}.muted{color:#69766e;line-height:1.6;font-size:14px}
label{display:block;font-size:12px;font-weight:700;margin:20px 0 7px}input{width:100%;box-sizing:border-box;padding:13px;border:1px solid #dfe4d8;border-radius:9px;font-size:14px}
button{width:100%;margin-top:22px;padding:14px;border:0;border-radius:999px;background:#27634e;color:#fff;font-weight:700;cursor:pointer}
.note{margin-top:18px;font-size:11px;color:#69766e}
</style></head>
<body><main class="card"><div style="font-size:28px">🌱</div><h1>Admin login</h1>
<p class="muted">Private management area for Peace &amp; Unity.</p>
${configured() ? `<form method="post" action="/login">
<label for="email">Email</label><input id="email" name="email" type="email" autocomplete="username" required>
<label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password" required>
<button type="submit">Sign in</button></form>` : `<p class="muted"><strong>Admin setup is not finished yet.</strong><br>Please configure the admin password and session secret in Render before signing in.</p>`}
<p class="note">Your password is never stored in this website's public files.</p></main></body></html>`);
});

app.post("/login", async (req, res) => {
  if (!configured()) return res.status(503).send("Admin setup is incomplete.");
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  const emailOk = email === ADMIN_EMAIL.toLowerCase();
  const passwordOk = emailOk && await bcrypt.compare(password, ADMIN_PASSWORD_HASH);
  if (!passwordOk) return res.status(401).send("Invalid login details. <a href="/login">Try again</a>.");
  req.session.authenticated = true;
  res.redirect("/dashboard");
});

app.post("/logout", requireAuth, (req, res) => {
  req.session.destroy(() => res.redirect("/login"));
});

app.get("/dashboard", requireAuth, (req, res) => {
  res.type("html").send(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Peace & Unity — Dashboard</title>
<style>
body{margin:0;background:#f5f2e9;color:#17352d;font-family:Arial,sans-serif}.wrap{max-width:900px;margin:auto;padding:30px 22px}
header{display:flex;justify-content:space-between;align-items:center;gap:20px}h1{font:46px Georgia,serif;margin:0}.muted{color:#69766e}
.grid{display:grid;grid-template-columns:repeat(2,1fr);gap:18px;margin-top:30px}.card{background:#fffdf8;border:1px solid #dfe4d8;border-radius:18px;padding:25px}.card h2{font:25px Georgia,serif;margin:0 0 8px}
button{padding:10px 17px;border:0;border-radius:999px;background:#27634e;color:white;font-weight:700}@media(max-width:650px){.grid{grid-template-columns:1fr}h1{font-size:38px}}
</style></head><body><div class="wrap"><header><div><div style="font-size:26px">🌱</div><h1>Admin Dashboard</h1><p class="muted">Welcome to the private Peace &amp; Unity management area.</p></div>
<form method="post" action="/logout"><button type="submit">Log out</button></form></header>
<div class="grid">
<div class="card"><h2>Stories</h2><p class="muted">Manage Peace &amp; Unity stories. Editing tools will be added next.</p></div>
<div class="card"><h2>Media</h2><p class="muted">Manage pictures and videos. Upload tools will be added next.</p></div>
<div class="card"><h2>Contact</h2><p class="muted">Manage public contact information.</p></div>
<div class="card"><h2>Donations</h2><p class="muted">Manage donation information and payment details.</p></div>
</div></div></body></html>`);
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Peace & Unity Admin listening on port ${PORT}`);
});

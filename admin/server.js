const express = require("express");
const session = require("express-session");
const helmet = require("helmet");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");

const app = express();
const PORT = process.env.PORT || 10000;
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || "peaceandunity42@gmail.com";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";
const SESSION_SECRET = process.env.SESSION_SECRET || require("crypto").randomBytes(32).toString("hex");
const DATABASE_URL = process.env.DATABASE_URL || "";

const pool = DATABASE_URL ? new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : false
}) : null;

const DEFAULT_STORY = `I was raised by a single mother in very difficult circumstances. We lived in a small house, school was far away, and paying school fees was often a struggle. Sometimes we walked barefoot. I watched my mother work hard and sometimes cry silently because there was simply not enough.

Later, my sister got an opportunity to travel to Saudi Arabia. After about two months, she changed in ways we did not understand. Eventually she was deported, and we took her to the hospital, but things did not change. Our family struggled with her condition for about five years.

Today, my sister is doing well. But that experience stayed with me. It showed me how difficult life can become when a family has nowhere to turn and cannot afford the help it needs.

That is one of the reasons I created Peace & Unity: to help people who cannot afford basic necessities, vulnerable families, children, and communities. I believe that when we stand together, we can give hope where it is needed most.

Peace & Unity — Together We Can Make a Difference.`;

const DEFAULT_CONTACT = JSON.stringify({ email: "peaceandunity42@gmail.com", whatsapp: "+256 742 119 378" });
const DEFAULT_DONATIONS = JSON.stringify({ airtelMoney: "+256 742 119 378", accountName: "Ivan Kayizzi", bank: "Equity Bank", accountNumber: "1003101355426", currency: "UGX" });

app.set("trust proxy", 1);
app.use(helmet());
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "https://peace-and-unity-website.onrender.com");
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  next();
});
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, secure: process.env.NODE_ENV === "production", sameSite: "lax", maxAge: 1000 * 60 * 60 * 8 }
}));

function configured() { return Boolean(ADMIN_PASSWORD && SESSION_SECRET); }
function requireAuth(req, res, next) { if (!req.session.authenticated) return res.redirect("/login"); next(); }

async function initDatabase() {
  if (!pool) return;
  await pool.query(`CREATE TABLE IF NOT EXISTS content (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`);
  await pool.query("INSERT INTO content(key,value) VALUES($1,$2) ON CONFLICT(key) DO NOTHING", ["story", DEFAULT_STORY]);
  await pool.query("INSERT INTO content(key,value) VALUES($1,$2) ON CONFLICT(key) DO NOTHING", ["contact", DEFAULT_CONTACT]);
  await pool.query("INSERT INTO content(key,value) VALUES($1,$2) ON CONFLICT(key) DO NOTHING", ["donations", DEFAULT_DONATIONS]);
}

async function getContent(key) {
  if (!pool) throw new Error("DATABASE_URL is not configured");
  const result = await pool.query("SELECT value FROM content WHERE key=$1", [key]);
  return result.rows[0]?.value ?? "";
}

async function saveContent(key, value) {
  if (!pool) throw new Error("DATABASE_URL is not configured");
  await pool.query("INSERT INTO content(key,value,updated_at) VALUES($1,$2,NOW()) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value, updated_at=NOW()", [key, value]);
}

app.get("/health", async (req, res) => {
  let database = false;
  if (pool) { try { await pool.query("SELECT 1"); database = true; } catch (_) {} }
  res.status(200).json({ ok: true, service: "Peace & Unity Admin", configured: configured(), database });
});

app.get("/api/content", async (req, res) => {
  if (!pool) return res.status(503).json({ error: "Content storage is not configured." });
  try {
    const result = await pool.query("SELECT key,value,updated_at FROM content ORDER BY key");
    res.json(Object.fromEntries(result.rows.map(row => [row.key, row.value])));
  } catch (error) { res.status(500).json({ error: "Unable to load content." }); }
});

app.get("/", (req, res) => req.session.authenticated ? res.redirect("/dashboard") : res.redirect("/login"));

app.get("/login", (req, res) => {
  res.type("html").send(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Peace & Unity — Admin Login</title>
<style>body{margin:0;background:#f5f2e9;color:#17352d;font-family:Arial,sans-serif;min-height:100vh;display:grid;place-items:center;padding:20px}.card{width:min(420px,100%);background:#fffdf8;padding:34px;border-radius:20px;box-shadow:0 18px 50px #17352d18}h1{font:40px Georgia,serif;margin:0 0 8px}.muted{color:#69766e;line-height:1.6;font-size:14px}label{display:block;font-size:12px;font-weight:700;margin:20px 0 7px}input{width:100%;box-sizing:border-box;padding:13px;border:1px solid #dfe4d8;border-radius:9px;font-size:14px}button{width:100%;margin-top:22px;padding:14px;border:0;border-radius:999px;background:#27634e;color:#fff;font-weight:700;cursor:pointer}.note{margin-top:18px;font-size:11px;color:#69766e}</style></head><body><main class="card"><div style="font-size:28px">🌱</div><h1>Admin login</h1><p class="muted">Private management area for Peace &amp; Unity.</p>
${configured() ? `<form method="post" action="/login"><label for="email">Email</label><input id="email" name="email" type="email" autocomplete="username" required><label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password" required><button type="submit">Sign in</button></form>` : `<p class="muted"><strong>Admin setup is not finished yet.</strong><br>Please configure the admin password in Render before signing in.</p>`}<p class="note">Your password is never stored in this website's public files.</p></main></body></html>`);
});

app.post("/login", async (req, res) => {
  if (!configured()) return res.status(503).send("Admin setup is incomplete.");
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  const emailOk = email === ADMIN_EMAIL.toLowerCase();
  const passwordOk = emailOk && await bcrypt.compare(password, await bcrypt.hash(ADMIN_PASSWORD, 12));
  if (!passwordOk) return res.status(401).send('Invalid login details. <a href="/login">Try again</a>.');
  req.session.authenticated = true;
  res.redirect("/dashboard");
});

app.post("/logout", requireAuth, (req, res) => req.session.destroy(() => res.redirect("/login")));

app.get("/dashboard", requireAuth, async (req, res) => {
  let story = "", contact = DEFAULT_CONTACT, donations = DEFAULT_DONATIONS, storageReady = Boolean(pool);
  if (pool) { try { story = await getContent("story"); contact = await getContent("contact"); donations = await getContent("donations"); } catch (_) { storageReady = false; } }
  const safeStory = String(story || "").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
  res.type("html").send(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Peace & Unity — Dashboard</title>
<style>body{margin:0;background:#f5f2e9;color:#17352d;font-family:Arial,sans-serif}.wrap{max-width:1000px;margin:auto;padding:30px 22px}h1{font:46px Georgia,serif;margin:0}.muted{color:#69766e;line-height:1.6}.card{background:#fffdf8;border:1px solid #dfe4d8;border-radius:18px;padding:25px;margin-top:22px}.card h2{font:28px Georgia,serif;margin:0 0 8px}input{width:100%;box-sizing:border-box;padding:12px;border:1px solid #dfe4d8;border-radius:9px;font-size:14px;margin:5px 0 10px}label{display:block;font-size:12px;font-weight:700;margin-top:10px}textarea{width:100%;box-sizing:border-box;min-height:360px;padding:16px;border:1px solid #dfe4d8;border-radius:12px;font:15px/1.7 Arial,sans-serif;resize:vertical}button{padding:11px 18px;border:0;border-radius:999px;background:#27634e;color:white;font-weight:700;cursor:pointer}.top{display:flex;justify-content:space-between;align-items:center;gap:15px}.notice{padding:12px 15px;border-radius:10px;background:#fff5d8;margin:15px 0}@media(max-width:650px){h1{font-size:38px}.top{align-items:flex-start;flex-direction:column}}</style></head><body><div class="wrap">
<div class="top"><div><div style="font-size:26px">🌱</div><h1>Admin Dashboard</h1><p class="muted">Private Peace &amp; Unity management area.</p></div><form method="post" action="/logout"><button type="submit">Log out</button></form></div>
${storageReady ? "" : `<div class="notice">Content storage is not connected yet. The database must be linked to this Render service.</div>`}
<div class="card"><h2>Stories</h2><p class="muted">Edit the main story shown on the Peace &amp; Unity website.</p><form method="post" action="/admin/story"><textarea name="story" required>${safeStory}</textarea><br><button type="submit">Save story</button></form></div>
<div class="card"><h2>Contact</h2><p class="muted">Update the public email address and WhatsApp number.</p><form method="post" action="/admin/contact"><label>Email</label><input name="email" type="email" value="${JSON.parse(contact).email || ""}" required><label>WhatsApp</label><input name="whatsapp" value="${JSON.parse(contact).whatsapp || ""}" required><br><button type="submit">Save contact</button></form></div>
<div class="card"><h2>Donations</h2><p class="muted">Update the public bank and mobile money donation details.</p><form method="post" action="/admin/donations"><label>Airtel Money</label><input name="airtelMoney" value="${JSON.parse(donations).airtelMoney || ""}" required><label>Account name</label><input name="accountName" value="${JSON.parse(donations).accountName || ""}" required><label>Bank</label><input name="bank" value="${JSON.parse(donations).bank || ""}" required><label>Account number</label><input name="accountNumber" value="${JSON.parse(donations).accountNumber || ""}" required><label>Currency</label><input name="currency" value="${JSON.parse(donations).currency || ""}" required><br><button type="submit">Save donation details</button></form></div><div class="card"><h2>Media</h2><p class="muted">Photo and video management is the next section we will add.</p></div>
</div></body></html>`);
});

app.post("/admin/story", requireAuth, async (req, res) => {
  try { await saveContent("story", String(req.body.story || "").trim()); res.redirect("/dashboard?saved=story"); }
  catch (error) { res.status(503).send('Content storage is not connected yet. <a href="/dashboard">Back to dashboard</a>.'); }
});

app.post("/admin/contact", requireAuth, async (req, res) => {
  try { await saveContent("contact", JSON.stringify({ email: String(req.body.email || "").trim(), whatsapp: String(req.body.whatsapp || "").trim() })); res.redirect("/dashboard?saved=contact"); }
  catch (error) { res.status(503).send('Content storage is not connected yet. <a href="/dashboard">Back to dashboard</a>.'); }
});

app.post("/admin/donations", requireAuth, async (req, res) => {
  try { await saveContent("donations", JSON.stringify({ airtelMoney: String(req.body.airtelMoney || "").trim(), accountName: String(req.body.accountName || "").trim(), bank: String(req.body.bank || "").trim(), accountNumber: String(req.body.accountNumber || "").trim(), currency: String(req.body.currency || "").trim() })); res.redirect("/dashboard?saved=donations"); }
  catch (error) { res.status(503).send('Content storage is not connected yet. <a href="/dashboard">Back to dashboard</a>.'); }
});

initDatabase()
  .then(() => app.listen(PORT, "0.0.0.0", () => console.log(`Peace & Unity Admin listening on port ${PORT}`)))
  .catch(error => { console.error("Database initialization failed:", error.message); app.listen(PORT, "0.0.0.0", () => console.log(`Peace & Unity Admin listening on port ${PORT}`)); });

const express = require("express");
const session = require("express-session");
const helmet = require("helmet");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const PgSession = require("connect-pg-simple")(session);
const { Pool } = require("pg");

const app = express();
const PORT = process.env.PORT || 10000;
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || "peaceandunity42@gmail.com";
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH || "";
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
const DEFAULT_DONATIONS = JSON.stringify({ airtelMoney: "+256 742 119 378", mtnMoney: "", accountName: "Ivan Kayizzi", bank: "Equity Bank", accountNumber: "1003101355426", currency: "UGX" });

app.set("trust proxy", 1);
app.use(helmet());
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "https://peace-and-unity-website.onrender.com");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: pool ? new PgSession({ pool, tableName: "admin_sessions", createTableIfMissing: true }) : undefined,
  cookie: { httpOnly: true, secure: process.env.NODE_ENV === "production", sameSite: "strict", maxAge: 1000 * 60 * 60 * 8 }
}));

function ensureCsrf(req, res, next) {
  if (!req.session.csrfToken) req.session.csrfToken = crypto.randomBytes(32).toString("hex");
  next();
}
app.use(ensureCsrf);

function requireCsrf(req, res, next) {
  const token = String(req.body?._csrf || "");
  if (!token || token !== req.session.csrfToken) return res.status(403).send("Security check failed. Please go back and try again.");
  next();
}

function requireSameOrigin(req, res, next) {
  const origin = String(req.get("origin") || "").replace(/\/$/, "");
  const referer = String(req.get("referer") || "");
  const allowed = "https://peace-and-unity-admin.onrender.com";
  if (origin && origin !== allowed) return res.status(403).send("Security check failed. Please go back and try again.");
  if (!origin && referer && !referer.startsWith(allowed + "/")) return res.status(403).send("Security check failed. Please go back and try again.");
  next();
}

const loginAttempts = new Map();
const enquiryAttempts = new Map();
const acknowledgementAttempts = new Map();
function enquiryRateLimit(req, res, next) {
  const now = Date.now();
  const key = req.ip || "unknown";
  const entry = enquiryAttempts.get(key) || { count: 0, resetAt: now + 15 * 60 * 1000 };
  if (now > entry.resetAt) { entry.count = 0; entry.resetAt = now + 15 * 60 * 1000; }
  if (entry.count >= 5) return res.status(429).json({ error: "Too many messages. Please try again later." });
  entry.count += 1;
  enquiryAttempts.set(key, entry);
  next();
}
function acknowledgementRateLimit(req, res, next) {
  const now = Date.now();
  const key = req.ip || "unknown";
  const entry = acknowledgementAttempts.get(key) || { count: 0, resetAt: now + 15 * 60 * 1000 };
  if (now > entry.resetAt) { entry.count = 0; entry.resetAt = now + 15 * 60 * 1000; }
  if (entry.count >= 10) return res.status(429).json({ error: "Too many acknowledgement attempts. Please try again later." });
  entry.count += 1;
  acknowledgementAttempts.set(key, entry);
  next();
}
function loginRateLimit(req, res, next) {
  const now = Date.now();
  const key = req.ip || "unknown";
  const entry = loginAttempts.get(key) || { count: 0, resetAt: now + 15 * 60 * 1000 };
  if (now > entry.resetAt) { entry.count = 0; entry.resetAt = now + 15 * 60 * 1000; }
  if (entry.count >= 10) return res.status(429).send("Too many login attempts. Please wait 15 minutes and try again.");
  entry.count += 1;
  loginAttempts.set(key, entry);
  next();
}

async function configured() { return Boolean((await hasAdminPassword()) && SESSION_SECRET); }
function requireAuth(req, res, next) { if (!req.session.authenticated) return res.redirect("/login"); next(); }

async function initDatabase() {
  if (!pool) return;
  await pool.query(`CREATE TABLE IF NOT EXISTS content (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`);
  await pool.query(`CREATE TABLE IF NOT EXISTS admin_config (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`);
  await pool.query("INSERT INTO content(key,value) VALUES($1,$2) ON CONFLICT(key) DO NOTHING", ["story", DEFAULT_STORY]);
  await pool.query("INSERT INTO content(key,value) VALUES($1,$2) ON CONFLICT(key) DO NOTHING", ["contact", DEFAULT_CONTACT]);
  await pool.query("INSERT INTO content(key,value) VALUES($1,$2) ON CONFLICT(key) DO NOTHING", ["donations", DEFAULT_DONATIONS]);
  await pool.query("INSERT INTO content(key,value) VALUES($1,$2) ON CONFLICT(key) DO NOTHING", ["media", "[]"]);
  await pool.query("INSERT INTO content(key,value) VALUES($1,$2) ON CONFLICT(key) DO NOTHING", ["enquiries", "[]"]);
  await pool.query("INSERT INTO content(key,value) VALUES($1,$2) ON CONFLICT(key) DO NOTHING", ["acknowledgements", "[]"]);
}

async function getStoredPasswordHash() {
  if (!pool) return "";
  const result = await pool.query("SELECT value FROM admin_config WHERE key=$1", ["password_hash"]);
  return result.rows[0]?.value ?? "";
}

async function setStoredPasswordHash(hash) {
  if (!pool) return;
  await pool.query("INSERT INTO admin_config(key,value,updated_at) VALUES($1,$2,NOW()) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value, updated_at=NOW()", ["password_hash", hash]);
}

async function hasAdminPassword() {
  if (ADMIN_PASSWORD_HASH || ADMIN_PASSWORD) return true;
  try { return Boolean(await getStoredPasswordHash()); } catch (_) { return false; }
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
  res.status(200).json({ ok: true, service: "Peace & Unity Admin", configured: await configured(), database, passwordHashConfigured: Boolean(ADMIN_PASSWORD_HASH || (await getStoredPasswordHash().catch(() => ""))), sessionStore: pool ? "postgres" : "memory" });
});

app.post("/api/enquiries", enquiryRateLimit, async (req, res) => {
  try {
    if (!pool) return res.status(503).json({ error: "Message storage is not configured." });
    if (String(req.body.website || "").trim()) return res.status(400).json({ error: "Unable to send message." });
    const name = String(req.body.name || "").trim().slice(0, 100);
    const email = String(req.body.email || "").trim().slice(0, 160);
    const message = String(req.body.message || "").trim().slice(0, 2000);
    if (!name || !email || !message) return res.status(400).json({ error: "Name, email and message are required." });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: "Please enter a valid email address." });
    let items = [];
    try { items = JSON.parse(await getContent("enquiries") || "[]"); } catch (_) {}
    items.unshift({ id: crypto.randomUUID(), name, email, message, createdAt: new Date().toISOString(), status: "new" });
    await saveContent("enquiries", JSON.stringify(items.slice(0, 200)));
    res.status(201).json({ ok: true });
  } catch (error) {
    res.status(503).json({ error: "Unable to save your message right now." });
  }
});

app.post("/api/acknowledgements", acknowledgementRateLimit, async (req, res) => {
  try {
    if (!pool) return res.status(503).json({ error: "Acknowledgement storage is not configured." });
    if (req.body.acknowledged !== true) return res.status(400).json({ error: "Acknowledgement is required." });
    let items = [];
    try { items = JSON.parse(await getContent("acknowledgements") || "[]"); } catch (_) {}
    const id = crypto.randomUUID();
    items.unshift({ id, acknowledgedAt: new Date().toISOString(), source: "website" });
    await saveContent("acknowledgements", JSON.stringify(items.slice(0, 500)));
    res.status(201).json({ ok: true, id });
  } catch (error) {
    res.status(503).json({ error: "Unable to record acknowledgement right now." });
  }
});

app.get("/api/content", async (req, res) => {
  if (!pool) return res.status(503).json({ error: "Content storage is not configured." });
  try {
    const result = await pool.query("SELECT key,value,updated_at FROM content WHERE key = ANY($1) ORDER BY key", [["story","contact","donations","media"]]);
    res.json(Object.fromEntries(result.rows.map(row => [row.key, row.value])));
  } catch (error) { res.status(500).json({ error: "Unable to load content." }); }
});

app.get("/", (req, res) => req.session.authenticated ? res.redirect("/dashboard") : res.redirect("/login"));

app.get("/login", async (req, res) => {
  res.type("html").send(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Peace & Unity — Admin Login</title>
<style>body{margin:0;background:#f5f2e9;color:#17352d;font-family:Arial,sans-serif;min-height:100vh;display:grid;place-items:center;padding:20px}.card{width:min(420px,100%);background:#fffdf8;padding:34px;border-radius:20px;box-shadow:0 18px 50px #17352d18}h1{font:40px Georgia,serif;margin:0 0 8px}.muted{color:#69766e;line-height:1.6;font-size:14px}label{display:block;font-size:12px;font-weight:700;margin:20px 0 7px}input{width:100%;box-sizing:border-box;padding:13px;border:1px solid #dfe4d8;border-radius:9px;font-size:14px}button{width:100%;margin-top:22px;padding:14px;border:0;border-radius:999px;background:#27634e;color:#fff;font-weight:700;cursor:pointer}.note{margin-top:18px;font-size:11px;color:#69766e}</style></head><body><main class="card"><div style="font-size:28px">🌱</div><h1>Admin login</h1>
${String(req.query.changed || "") === "1" ? `<div style="padding:12px 15px;border-radius:10px;background:#e7f4e8;margin:15px 0">Password changed successfully. Please sign in with your new password.</div>` : ""}<p class="muted">Private management area for Peace &amp; Unity.</p>
${(await configured()) ? `<form method="post" action="/login"><input type="hidden" name="_csrf" value="${req.session.csrfToken}"><label for="email">Email</label><input id="email" name="email" type="email" autocomplete="username" required><label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password" required><button type="submit">Sign in</button></form>` : `<p class="muted"><strong>Admin setup is not finished yet.</strong><br>Please configure the admin password in Render before signing in.</p>`}<p class="note">Your password is never stored in this website's public files.</p></main></body></html>`);
});

app.post("/login", loginRateLimit, async (req, res) => {
  if (!(await configured())) return res.status(503).send("Admin setup is incomplete.");
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  const emailOk = email === ADMIN_EMAIL.toLowerCase();
  let passwordOk = false;
  if (emailOk) {
    const storedHash = await getStoredPasswordHash().catch(() => "");
    if (storedHash) passwordOk = await bcrypt.compare(password, storedHash);
    else if (ADMIN_PASSWORD_HASH) passwordOk = await bcrypt.compare(password, ADMIN_PASSWORD_HASH);
    else if (ADMIN_PASSWORD) passwordOk = password === ADMIN_PASSWORD;
  }
  if (!passwordOk) return res.status(401).send('Invalid login details. <a href="/login">Try again</a>.');
  if (!await getStoredPasswordHash().catch(() => "")) {
    try { await setStoredPasswordHash(await bcrypt.hash(password, 12)); } catch (_) {}
  }
  loginAttempts.delete(req.ip || "unknown");
  req.session.regenerate(error => {
    if (error) return res.status(500).send("Unable to start a secure session.");
    req.session.authenticated = true;
    req.session.csrfToken = crypto.randomBytes(32).toString("hex");
    res.redirect("/dashboard");
  });
});

app.post("/logout", requireAuth, requireCsrf, (req, res) => req.session.destroy(() => res.redirect("/login")));

app.get("/admin/backup", requireAuth, async (req, res) => {
  try {
    const backup = {
      exportedAt: new Date().toISOString(),
      service: "Peace & Unity Admin",
      content: {
        story: await getContent("story"),
        contact: JSON.parse(await getContent("contact")),
        donations: JSON.parse(await getContent("donations")),
        media: JSON.parse(await getContent("media") || "[]"),
        acknowledgements: JSON.parse(await getContent("acknowledgements") || "[]")
      }
    };
    const filename = `peace-unity-backup-${new Date().toISOString().slice(0,10)}.json`;
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
    res.send(JSON.stringify(backup, null, 2));
  } catch (error) {
    res.status(503).send('Unable to create backup. <a href="/dashboard">Back to dashboard</a>.');
  }
});

app.post("/admin/change-password", requireAuth, requireCsrf, async (req, res) => {
  try {
    const currentPassword = String(req.body.currentPassword || "");
    const newPassword = String(req.body.newPassword || "");
    const confirmPassword = String(req.body.confirmPassword || "");
    const storedHash = await getStoredPasswordHash();
    if (!storedHash || !(await bcrypt.compare(currentPassword, storedHash))) {
      return res.status(400).send('Current password is incorrect. <a href="/dashboard">Back to dashboard</a>.');
    }
    if (newPassword.length < 12) {
      return res.status(400).send('New password must be at least 12 characters long. <a href="/dashboard">Back to dashboard</a>.');
    }
    if (newPassword !== confirmPassword) {
      return res.status(400).send('New passwords do not match. <a href="/dashboard">Back to dashboard</a>.');
    }
    await setStoredPasswordHash(await bcrypt.hash(newPassword, 12));
    req.session.destroy(() => res.redirect("/login?changed=1"));
  } catch (error) {
    res.status(500).send('Unable to change password. <a href="/dashboard">Back to dashboard</a>.');
  }
});

app.get("/dashboard", requireAuth, async (req, res) => {
  let story = "", contact = DEFAULT_CONTACT, donations = DEFAULT_DONATIONS, media = "[]", enquiries = "[]", acknowledgements = "[]", storageReady = Boolean(pool), saved = String(req.query.saved || "");
  if (pool) { try { story = await getContent("story"); contact = await getContent("contact"); donations = await getContent("donations"); media = await getContent("media"); enquiries = await getContent("enquiries"); acknowledgements = await getContent("acknowledgements"); } catch (_) { storageReady = false; } }
  const safeStory = String(story || "").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
  let mediaItems = []; try { mediaItems = JSON.parse(media || "[]"); } catch (_) { mediaItems = []; }
  let enquiryItems = []; try { enquiryItems = JSON.parse(enquiries || "[]"); } catch (_) { enquiryItems = []; }
  let acknowledgementItems = []; try { acknowledgementItems = JSON.parse(acknowledgements || "[]"); } catch (_) { acknowledgementItems = []; }
  let donationData = {}; try { donationData = JSON.parse(donations || "{}"); } catch (_) { donationData = {}; }
  const donationMethods = [donationData.airtelMoney, donationData.mtnMoney, donationData.bank, donationData.accountNumber].filter(Boolean).length > 0 ? [donationData.airtelMoney, donationData.mtnMoney, donationData.bank && donationData.accountNumber ? "bank" : ""].filter(Boolean).length : 0;
  let lastUpdated = null;
  if (pool) { try { const updated = await pool.query("SELECT MAX(updated_at) AS last_updated FROM content"); lastUpdated = updated.rows[0]?.last_updated || null; } catch (_) {} }
  const esc = value => String(value ?? "").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
  const acknowledgementRows = acknowledgementItems.length ? acknowledgementItems.slice(0,50).map(item => `<div class="media-item"><div><strong>Terms &amp; Privacy acknowledged</strong><div class="media-url">${esc(item.acknowledgedAt ? new Date(item.acknowledgedAt).toLocaleString("en-GB", { timeZone: "Africa/Kampala" }) : "")}</div></div><span class="tag">recorded</span></div>`).join("") : `<p class="muted">No acknowledgements recorded yet.</p>`;
  const enquiryRows = enquiryItems.length ? enquiryItems.map((item,index) => `<div class="media-item"><div><strong>${esc(item.name)}</strong><span class="tag">${esc(item.status || "new")}</span><div class="media-url">${esc(item.email)} · ${esc(item.createdAt ? new Date(item.createdAt).toLocaleString("en-GB", { timeZone: "Africa/Kampala" }) : "")}</div><div class="muted">${esc(item.message)}</div></div><form method="post" action="/admin/enquiries/delete"><input type="hidden" name="_csrf" value="${req.session.csrfToken}"><input type="hidden" name="index" value="${index}"><button class="danger" type="submit">Delete</button></form></div>`).join("") : `<p class="muted">No enquiries yet.</p>`;
  const mediaRows = mediaItems.length ? mediaItems.map((item,index) => `<div class="media-item"><div><strong>${esc(item.title)}</strong><span class="tag">${esc(item.type === "news" ? "News / Update" : item.type)}</span><div class="media-url">${esc(item.url)}</div><div class="muted">${esc(item.description)}</div></div><form method="post" action="/admin/media/delete"><input type="hidden" name="_csrf" value="${req.session.csrfToken}"><input type="hidden" name="index" value="${index}"><button class="danger" type="submit">Delete</button></form></div>`).join("") : `<p class="muted">No media has been added yet.</p>`;
  res.type("html").send(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Peace & Unity — Dashboard</title>
<style>body{margin:0;background:#f5f2e9;color:#17352d;font-family:Arial,sans-serif}.wrap{max-width:1000px;margin:auto;padding:30px 22px}h1{font:46px Georgia,serif;margin:0}.muted{color:#69766e;line-height:1.6}.card{background:#fffdf8;border:1px solid #dfe4d8;border-radius:18px;padding:25px;margin-top:22px}.card h2{font:28px Georgia,serif;margin:0 0 8px}input{width:100%;box-sizing:border-box;padding:12px;border:1px solid #dfe4d8;border-radius:9px;font-size:14px;margin:5px 0 10px}label{display:block;font-size:12px;font-weight:700;margin-top:10px}select{width:100%;box-sizing:border-box;padding:12px;border:1px solid #dfe4d8;border-radius:9px;font-size:14px;margin:5px 0 10px}textarea{width:100%;box-sizing:border-box;min-height:360px;padding:16px;border:1px solid #dfe4d8;border-radius:12px;font:15px/1.7 Arial,sans-serif;resize:vertical}button{padding:11px 18px;border:0;border-radius:999px;background:#27634e;color:white;font-weight:700;cursor:pointer}.danger{background:#9b3d3d}.media-item{display:flex;justify-content:space-between;gap:18px;align-items:flex-start;padding:16px 0;border-top:1px solid #e5e8df}.media-url{font-size:12px;word-break:break-all;margin:6px 0;color:#69766e}.tag{display:inline-block;margin-left:8px;padding:3px 8px;border-radius:999px;background:#e9efdf;font-size:11px;font-weight:700}.top{display:flex;justify-content:space-between;align-items:center;gap:15px}.notice{padding:12px 15px;border-radius:10px;background:#fff5d8;margin:15px 0}.overview{background:#17352d;color:#fff;border-radius:18px;padding:22px;margin-top:22px}.overview h2{font:28px Georgia,serif;margin:0 0 5px}.overview .muted{color:#c8d5ce}.overview-title{display:flex;justify-content:space-between;align-items:flex-start;gap:18px}.last-updated{font-size:12px;color:#c8d5ce;text-align:right}.stats{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-top:18px}.stat{background:#fff;color:#17352d;border-radius:14px;padding:16px}.stat strong{display:block;font:30px Georgia,serif;margin-bottom:4px}.stat span{font-size:12px;color:#69766e}@media(max-width:650px){h1{font-size:38px}.top{align-items:flex-start;flex-direction:column}.overview-title{flex-direction:column}.last-updated{text-align:left}.stats{grid-template-columns:repeat(2,1fr)}}</style></head><body><div class="wrap">
<div class="top"><div><div style="font-size:26px">🌱</div><h1>Admin Dashboard</h1><p class="muted">Private Peace &amp; Unity management area.</p></div><form method="post" action="/logout"><input type="hidden" name="_csrf" value="${req.session.csrfToken}"><button type="submit">Log out</button></form></div>
${storageReady ? (saved ? `<div class="notice" style="background:#e7f4e8">Saved successfully. Your ${esc(saved)} content has been updated.</div>` : "") : `<div class="notice">Content storage is not connected yet. The database must be linked to this Render service.</div>`}
<div class="overview"><div class="overview-title"><div><h2>Overview</h2><p class="muted">Quick view of your Peace &amp; Unity content.</p></div><div class="last-updated">${lastUpdated ? `Last content update: ${esc(new Date(lastUpdated).toLocaleString("en-GB", { timeZone: "Africa/Kampala" }))}` : "Last content update: —"}</div></div><div class="stats"><div class="stat"><strong>${story.trim() ? "1" : "0"}</strong><span>Story</span></div><div class="stat"><strong>${mediaItems.length}</strong><span>Media items</span></div><div class="stat"><strong>${donationMethods}</strong><span>Donation methods</span></div><div class="stat"><strong>${contact.trim() ? "✓" : "—"}</strong><span>Contact details</span></div><div class="stat"><strong>${enquiryItems.length}</strong><span>Enquiries</span></div><div class="stat"><strong>${acknowledgementItems.length}</strong><span>Acknowledgements</span></div></div></div>
<div class="card"><h2>Admin Backup</h2><p class="muted">Download a safe copy of your website content. Passwords and security secrets are never included.</p><a href="/admin/backup" style="display:inline-block;padding:11px 18px;border-radius:999px;background:#27634e;color:#fff;font-weight:700;text-decoration:none">Download Backup</a></div>
<div class="card"><h2>Change password</h2><p class="muted">Change the admin password without opening Render Environment settings. Use a strong password with at least 12 characters.</p><form method="post" action="/admin/change-password"><input type="hidden" name="_csrf" value="${req.session.csrfToken}"><label>Current password</label><input name="currentPassword" type="password" autocomplete="current-password" required><label>New password</label><input name="newPassword" type="password" autocomplete="new-password" minlength="12" required><label>Confirm new password</label><input name="confirmPassword" type="password" autocomplete="new-password" minlength="12" required><br><button type="submit">Change password</button></form></div>
<div class="card"><h2>Stories</h2><p class="muted">Edit the main story shown on the Peace &amp; Unity website.</p><form method="post" action="/admin/story"><input type="hidden" name="_csrf" value="${req.session.csrfToken}"><textarea name="story" required>${safeStory}</textarea><br><button type="submit">Save story</button></form></div>
<div class="card"><h2>Contact</h2><p class="muted">Update the public email address and WhatsApp number.</p><form method="post" action="/admin/contact"><input type="hidden" name="_csrf" value="${req.session.csrfToken}"><label>Email</label><input name="email" type="email" value="${JSON.parse(contact).email || ""}" required><label>WhatsApp</label><input name="whatsapp" value="${JSON.parse(contact).whatsapp || ""}" required><br><button type="submit">Save contact</button></form></div>
<div class="card"><h2>Donations</h2><p class="muted">Manage the public mobile money and bank donation details shown on the Peace &amp; Unity website.</p><div style="background:#f5f2e9;border-radius:14px;padding:16px;margin:15px 0"><strong>Current donation setup</strong><div class="muted" style="font-size:13px;margin-top:7px">Airtel Money: ${esc(donationData.airtelMoney || "Not set")} · MTN Mobile Money: ${esc(donationData.mtnMoney || "Not set")} · Bank: ${esc(donationData.bank || "Not set")} · Account: ${esc(donationData.accountNumber || "Not set")} · Currency: ${esc(donationData.currency || "Not set")}</div></div><form method="post" action="/admin/donations"><input type="hidden" name="_csrf" value="${req.session.csrfToken}"><label>Airtel Money</label><input name="airtelMoney" value="${esc(donationData.airtelMoney || "")}" required><label>MTN Mobile Money <span class="muted" style="font-weight:400">(optional)</span></label><input name="mtnMoney" value="${esc(donationData.mtnMoney || "")}" placeholder="+256 ..."><label>Account name</label><input name="accountName" value="${esc(donationData.accountName || "")}" required><label>Bank</label><input name="bank" value="${esc(donationData.bank || "")}" required><label>Account number</label><input name="accountNumber" value="${esc(donationData.accountNumber || "")}" required><label>Currency</label><input name="currency" value="${esc(donationData.currency || "")}" required><br><button type="submit">Save donation details</button></form></div><div class="card"><h2>Media Manager</h2><p class="muted">Add photos, videos, or stories using a public URL. These items will be stored safely in the content database.</p><form method="post" action="/admin/media/add"><input type="hidden" name="_csrf" value="${req.session.csrfToken}"><label>Type</label><select name="type" required><option value="image">Image</option><option value="video">Video</option><option value="story">Story</option><option value="project">Project</option><option value="news">News / Update</option></select><label>Title</label><input name="title" maxlength="120" required><label>Description</label><input name="description" maxlength="300"><label>Public URL</label><input name="url" type="url" placeholder="https://..."><p class="muted" style="font-size:12px">URL is optional for stories; images and videos need a public URL.</p><br><button type="submit">Add media</button></form><div style="margin-top:24px">${mediaRows}</div></div><div class="card"><h2>Terms &amp; Privacy Acknowledgements</h2><p class="muted">Anonymous records showing when visitors actively acknowledged the Terms and Privacy Policy. No name, email address, or IP address is stored.</p><div style="margin-top:18px">${acknowledgementRows}</div></div><div class="card"><h2>Enquiries</h2><p class="muted">Messages submitted through the public Peace &amp; Unity contact form appear here.</p><div style="margin-top:18px">${enquiryRows}</div></div>
</div></body></html>`);
});

app.post("/admin/story", requireAuth, requireCsrf, async (req, res) => {
  try { await saveContent("story", String(req.body.story || "").trim()); res.redirect("/dashboard?saved=story"); }
  catch (error) { res.status(503).send('Content storage is not connected yet. <a href="/dashboard">Back to dashboard</a>.'); }
});

app.post("/admin/contact", requireAuth, requireCsrf, async (req, res) => {
  try { await saveContent("contact", JSON.stringify({ email: String(req.body.email || "").trim(), whatsapp: String(req.body.whatsapp || "").trim() })); res.redirect("/dashboard?saved=contact"); }
  catch (error) { res.status(503).send('Content storage is not connected yet. <a href="/dashboard">Back to dashboard</a>.'); }
});

app.post("/admin/media/add", requireAuth, requireCsrf, async (req, res) => {
  try {
    const type = ["image","video","story","project","news"].includes(String(req.body.type || "")) ? String(req.body.type) : "";
    const title = String(req.body.title || "").trim();
    const description = String(req.body.description || "").trim();
    const url = String(req.body.url || "").trim();
    if (!type || !title) return res.status(400).send('Media type and title are required. <a href="/dashboard">Back to dashboard</a>.');
    if (["image","video"].includes(type) && !url) return res.status(400).send('A public URL is required for images and videos. <a href="/dashboard">Back to dashboard</a>.');
    if (url) { try { const parsedUrl = new URL(url); if (!["http:","https:"].includes(parsedUrl.protocol)) throw new Error(); } catch (_) { return res.status(400).send('Public URL must be a valid http(s) URL. <a href="/dashboard">Back to dashboard</a>.'); } }
    let items = [];
    try { items = JSON.parse(await getContent("media") || "[]"); } catch (_) {}
    items.push({ type, title, description, url, createdAt: new Date().toISOString() });
    await saveContent("media", JSON.stringify(items));
    res.redirect("/dashboard?saved=media");
  } catch (error) { res.status(503).send('Unable to save media. <a href="/dashboard">Back to dashboard</a>.'); }
});

app.post("/admin/media/delete", requireAuth, requireCsrf, async (req, res) => {
  try {
    const index = Number(req.body.index);
    let items = [];
    try { items = JSON.parse(await getContent("media") || "[]"); } catch (_) {}
    if (!Number.isInteger(index) || index < 0 || index >= items.length) return res.status(400).send('Invalid media item. <a href="/dashboard">Back to dashboard</a>.');
    items.splice(index, 1);
    await saveContent("media", JSON.stringify(items));
    res.redirect("/dashboard?saved=media");
  } catch (error) { res.status(503).send('Unable to delete media. <a href="/dashboard">Back to dashboard</a>.'); }
});

app.post("/admin/enquiries/delete", requireAuth, requireCsrf, async (req, res) => {
  try {
    const index = Number(req.body.index);
    let items = [];
    try { items = JSON.parse(await getContent("enquiries") || "[]"); } catch (_) {}
    if (!Number.isInteger(index) || index < 0 || index >= items.length) return res.status(400).send('Invalid enquiry. <a href="/dashboard">Back to dashboard</a>.');
    items.splice(index, 1);
    await saveContent("enquiries", JSON.stringify(items));
    res.redirect("/dashboard?saved=enquiry");
  } catch (error) { res.status(503).send('Unable to delete enquiry. <a href="/dashboard">Back to dashboard</a>.'); }
});

app.post("/admin/donations", requireAuth, requireCsrf, async (req, res) => {
  try {
    const airtelMoney = String(req.body.airtelMoney || "").trim();
    const mtnMoney = String(req.body.mtnMoney || "").trim();
    const accountName = String(req.body.accountName || "").trim();
    const bank = String(req.body.bank || "").trim();
    const accountNumber = String(req.body.accountNumber || "").trim();
    const currency = String(req.body.currency || "").trim();
    if (!airtelMoney || !accountName || !bank || !accountNumber || !currency) {
      return res.status(400).send('Airtel Money, account name, bank, account number and currency are required. <a href="/dashboard">Back to dashboard</a>.');
    }
    await saveContent("donations", JSON.stringify({ airtelMoney, mtnMoney, accountName, bank, accountNumber, currency }));
    res.redirect("/dashboard?saved=donations");
  } catch (error) {
    res.status(503).send('Content storage is not connected yet. <a href="/dashboard">Back to dashboard</a>.');
  }
});

initDatabase()
  .then(() => app.listen(PORT, "0.0.0.0", () => console.log(`Peace & Unity Admin listening on port ${PORT}`)))
  .catch(error => { console.error("Database initialization failed:", error.message); app.listen(PORT, "0.0.0.0", () => console.log(`Peace & Unity Admin listening on port ${PORT}`)); });

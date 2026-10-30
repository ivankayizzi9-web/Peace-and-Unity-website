const DEFAULTS = {
  story: {},
  contact: {},
  donations: {},
  media: [],
  enquiries: [],
  acknowledgements: []
};

const SCHEMA = `
CREATE TABLE IF NOT EXISTS content (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS admin_config (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);
`;

async function initialize(db) {
  await db.exec(SCHEMA);
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store"
    }
  });
}

function unauthorized() {
  return json({ error: "Please log in again." }, 401);
}

async function getValue(db, table, key) {
  const row = await db.prepare(
    `SELECT value FROM ${table} WHERE key = ?`
  ).bind(key).first();

  if (!row) return null;

  try {
    return JSON.parse(row.value);
  } catch {
    return row.value;
  }
}

async function saveValue(db, table, key, value) {
  await db.prepare(`
    INSERT INTO ${table} (key, value, updated_at)
    VALUES (?, ?, CURRENT_TIMESTAMP)
    ON CONFLICT(key) DO UPDATE SET
      value = excluded.value,
      updated_at = CURRENT_TIMESTAMP
  `).bind(key, JSON.stringify(value)).run();
}

function cookieValue(request, name) {
  const cookie = request.headers.get("Cookie") || "";
  const item = cookie.split(";").map(v => v.trim())
    .find(v => v.startsWith(name + "="));
  return item ? item.substring(name.length + 1) : null;
}

async function sha256(value) {
  const bytes = new TextEncoder().encode(value);
  const hash = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(hash))
    .map(b => b.toString(16).padStart(2, "0")).join("");
}

async function verifyPassword(password, stored) {
  if (!stored) return false;

  // Existing bcrypt hashes must be migrated securely before login is enabled.
  if (stored.startsWith("$2")) return false;

  return (await sha256(password)) === stored;
}

function secureCookie(value, maxAge = 86400) {
  return `bf_admin=${value}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${maxAge}`;
}

async function authenticated(request, env) {
  const token = cookieValue(request, "bf_admin");
  if (!token || !env.SESSION_SECRET) return false;

  const expected = await sha256(env.SESSION_SECRET + ":" + token);
  const stored = await env.DB.prepare(
    "SELECT value FROM admin_config WHERE key = 'active_session'"
  ).first();

  return !!stored && stored.value === expected;
}

async function handle(request, env) {
  await initialize(env.DB);

  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  if (path === "/health" && method === "GET") {
    return json({ service: "Brighter Future Admin", database: true });
  }

  if (path === "/login" && method === "POST") {
    const body = await request.json().catch(() => ({}));
    const password = String(body.password || "");

    const configured = await getValue(env.DB, "admin_config", "password_hash");
    const envHash = env.ADMIN_PASSWORD_HASH || "";

    const valid = await verifyPassword(password, configured || envHash);

    if (!valid) return json({ error: "Invalid login details." }, 401);

    const token = crypto.randomUUID();
    const sessionHash = await sha256(env.SESSION_SECRET + ":" + token);

    await saveValue(env.DB, "admin_config", "active_session", sessionHash);

    return new Response(JSON.stringify({ success: true }), {
      headers: {
        "Content-Type": "application/json",
        "Set-Cookie": secureCookie(token)
      }
    });
  }

  if (path === "/logout" && method === "POST") {
    await env.DB.prepare(
      "DELETE FROM admin_config WHERE key = 'active_session'"
    ).run();

    return new Response(JSON.stringify({ success: true }), {
      headers: {
        "Content-Type": "application/json",
        "Set-Cookie": secureCookie("", 0)
      }
    });
  }

  if (path.startsWith("/admin/") && !(await authenticated(request, env))) {
    return unauthorized();
  }

  if (path === "/api/content" && method === "GET") {
    const result = {};

    for (const key of Object.keys(DEFAULTS)) {
      result[key] = await getValue(env.DB, "content", key);
      if (result[key] === null) result[key] = DEFAULTS[key];
    }

    return json(result);
  }

  if (path === "/admin/backup" && method === "GET") {
    const backup = {};

    for (const key of Object.keys(DEFAULTS)) {
      backup[key] = await getValue(env.DB, "content", key) ?? DEFAULTS[key];
    }

    return json({
      exportedAt: new Date().toISOString(),
      content: backup
    });
  }

  if (path === "/admin/change-password" && method === "POST") {
    const body = await request.json().catch(() => ({}));
    const password = String(body.password || "");

    if (password.length < 12) {
      return json({ error: "Password must be at least 12 characters." }, 400);
    }

    await saveValue(env.DB, "admin_config", "password_hash", await sha256(password));
    return json({ success: true });
  }

  return json({ error: "Not found." }, 404);
}

export default {
  async fetch(request, env) {
    try {
      return await handle(request, env);
    } catch (error) {
      return json({ error: "The admin service encountered an error." }, 500);
    }
  }
};

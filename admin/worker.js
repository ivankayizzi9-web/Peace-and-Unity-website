const KEYS = ["homepage","story","contact","donations","media","enquiries","acknowledgements"];

const DEFAULTS = {
  homepage: {
    eyebrow: "Supporting Children. Empowering Families.",
    heading: "Building a Brighter Future for Every Child.",
    intro: "Brighter Future Foundation supports vulnerable children, promotes education access, and helps families experiencing poverty through compassion, practical assistance and community support.",
    missionLead: "To support vulnerable children, promote access to quality education, and help families experiencing poverty meet their basic needs with dignity and hope."
  },
  story: "",
  contact: { email: "brighterfuturefoundation85@gmail.com", whatsapp: "+256 742 119 378" },
  donations: { airtelMoney: "+256 742 119 378", mtnMoney: "", accountName: "Ivan Kayizzi", bank: "Equity Bank", accountNumber: "1003101355426", currency: "UGX" },
  media: [],
  enquiries: [],
  acknowledgements: []
};

const schema = `
CREATE TABLE IF NOT EXISTS content(key TEXT PRIMARY KEY,value TEXT NOT NULL,updated_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS admin_config(key TEXT PRIMARY KEY,value TEXT NOT NULL,updated_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY,csrf TEXT NOT NULL,expires_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS reset_tokens(token_hash TEXT PRIMARY KEY,expires_at INTEGER NOT NULL,used INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS rate_limits(bucket TEXT PRIMARY KEY,count INTEGER NOT NULL,reset_at INTEGER NOT NULL);
`;

const enc = new TextEncoder();
const htmlEscape = v => String(v ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const json = (data, status = 200, headers = {}) => new Response(JSON.stringify(data), {
  status, headers: {"Content-Type":"application/json; charset=utf-8","Cache-Control":"no-store",...headers}
});
async function digest(v) {
  const b = await crypto.subtle.digest("SHA-256", enc.encode(v));
  return [...new Uint8Array(b)].map(x => x.toString(16).padStart(2,"0")).join("");
}
async function passwordHash(p,salt) {
  const key = await crypto.subtle.importKey("raw",enc.encode(p),"PBKDF2",false,["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({name:"PBKDF2",salt:enc.encode(salt),iterations:210000,hash:"SHA-256"},key,256);
  return [...new Uint8Array(bits)].map(x => x.toString(16).padStart(2,"0")).join("");
}
async function checkPassword(p,stored) {
  if (!stored || !stored.startsWith("pbkdf2$")) return false;
  const [,salt,hash] = stored.split("$");
  return await passwordHash(p,salt) === hash;
}
async function makePassword(p) {
  const salt = crypto.randomUUID()+crypto.randomUUID();
  return "pbkdf2$"+salt+"$"+await passwordHash(p,salt);
}
async function init(db) {
  await db.exec(schema);
  for (const k of KEYS) {
    const v = await db.prepare("SELECT key FROM content WHERE key=?").bind(k).first();
    if (!v) await db.prepare("INSERT INTO content(key,value) VALUES(?,?)").bind(k,JSON.stringify(DEFAULTS[k])).run();
  }
}
async function get(db,k) {
  const r = await db.prepare("SELECT value FROM content WHERE key=?").bind(k).first();
  if (!r) return DEFAULTS[k];
  try { return JSON.parse(r.value); } catch { return r.value; }
}
async function put(db,k,v) {
  await db.prepare("INSERT INTO content(key,value,updated_at) VALUES(?,?,CURRENT_TIMESTAMP) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=CURRENT_TIMESTAMP").bind(k,JSON.stringify(v)).run();
}
function cookie(req,n) {
  const s = req.headers.get("Cookie") || "";
  const p = s.split(";").map(x=>x.trim()).find(x=>x.startsWith(n+"="));
  return p ? decodeURIComponent(p.slice(n.length+1)) : "";
}
function setCookie(v,age=28800) {
  return "bf_admin="+encodeURIComponent(v)+"; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age="+age;
}
function page(title,body) {
  return new Response(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${htmlEscape(title)} — Brighter Future Foundation</title><style>
  *{box-sizing:border-box}body{margin:0;background:#f5f2e9;color:#17352d;font:15px Arial,sans-serif}.wrap{max-width:1100px;margin:auto;padding:28px 18px}h1{font:40px Georgia,serif;margin:8px 0}h2{font:26px Georgia,serif;margin:0 0 8px}h3{margin:0 0 8px}.muted{color:#69766e;line-height:1.6}.card{background:#fffdf8;border:1px solid #dfe4d8;border-radius:16px;padding:22px;margin:18px 0}.login{max-width:440px;margin:8vh auto}.brand{font-size:28px}label{display:block;font-size:12px;font-weight:bold;margin:14px 0 6px}input,textarea,select{width:100%;padding:12px;border:1px solid #dfe4d8;border-radius:9px;font:14px Arial;margin:4px 0}textarea{min-height:130px;resize:vertical}button,.btn{display:inline-block;background:#27634e;color:white;border:0;border-radius:999px;padding:12px 18px;font-weight:bold;text-decoration:none;cursor:pointer;margin:5px 5px 0 0}.secondary{background:#69766e}.danger{background:#963e3e}.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:10px}.stat{background:#edf2e9;padding:16px;border-radius:12px;color:#17352d;text-decoration:none;display:block}.stat strong{display:block;font:28px Georgia}.row{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}.item{padding:14px 0;border-top:1px solid #e5e8df;overflow-wrap:anywhere}.notice{padding:12px;background:#e7f4e8;border-radius:9px;margin:12px 0}.warning{background:#fff0dd}.grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}.nav{display:flex;gap:8px;flex-wrap:wrap;margin:18px 0}.nav a{background:#e7ede3;padding:9px 13px;border-radius:999px;color:#17352d;text-decoration:none}.small{font-size:12px}.stat:hover,.nav a:hover{filter:brightness(.97)}@media(max-width:650px){.grid,.stats{grid-template-columns:1fr 1fr}h1{font-size:34px}.card{padding:17px}}
  </style></head><body>${body}</body></html>`,{headers:{"Content-Type":"text/html; charset=utf-8","Cache-Control":"no-store"}});
}
async function limit(db,key,max=8) {
  const now=Date.now(),r=await db.prepare("SELECT count,reset_at FROM rate_limits WHERE bucket=?").bind(key).first();
  if (r && r.reset_at>now && r.count>=max) return false;
  const count=r && r.reset_at>now ? r.count+1 : 1;
  await db.prepare("INSERT INTO rate_limits(bucket,count,reset_at) VALUES(?,?,?) ON CONFLICT(bucket) DO UPDATE SET count=excluded.count,reset_at=excluded.reset_at").bind(key,count,now+900000).run();
  return true;
}
async function session(req,env) {
  const token=cookie(req,"bf_admin");
  if (!token) return null;
  const hash=await digest(token),s=await env.DB.prepare("SELECT csrf,expires_at FROM sessions WHERE token_hash=?").bind(hash).first();
  if (!s || s.expires_at<Date.now()) {
    if (s) await env.DB.prepare("DELETE FROM sessions WHERE token_hash=?").bind(hash).run();
    return null;
  }
  return {tokenHash:hash,csrf:s.csrf};
}
function redirect(path) { return new Response(null,{status:303,headers:{Location:path}}); }
async function formData(req) { return req.formData(); }
function safeUrl(value) {
  try { const u=new URL(String(value)); return ["https:","http:"].includes(u.protocol) && !u.username && !u.password ? u.href : ""; }
  catch { return ""; }
}
function nav() {
  return `<nav class="nav"><a href="/dashboard">Dashboard</a><a href="/admin/story">Stories</a><a href="/admin/media">Media</a><a href="/admin/donations">Donations</a><a href="/admin/contact">Contact</a><a href="/admin/enquiries">Enquiries</a><a href="/admin/acknowledgements">Acknowledgements</a><a href="/admin/backup">Download Backup</a></nav>`;
}
function shell(title,content,s) {
  return page(title,`<main class="wrap"><div class="row"><div><div class="brand">🌱 Brighter Future Foundation</div><p class="muted">Administration dashboard</p></div><form method="post" action="/logout"><input type="hidden" name="csrf" value="${htmlEscape(s.csrf)}"><button class="secondary">Sign out</button></form></div>${nav()}${content}</main>`);
}
function field(label,name,value,type="text") {
  return `<label>${htmlEscape(label)}</label><input type="${type}" name="${htmlEscape(name)}" value="${htmlEscape(value)}">`;
}
function area(label,name,value) {
  return `<label>${htmlEscape(label)}</label><textarea name="${htmlEscape(name)}">${htmlEscape(value)}</textarea>`;
}
function editor(title,action,body,s) {
  return shell(title,`<section class="card"><h1>${htmlEscape(title)}</h1><form method="post" action="${action}"><input type="hidden" name="csrf" value="${htmlEscape(s.csrf)}">${body}<button type="submit">Save changes</button></form></section>`,s);
}
async function sendReset(env,email,token) {
  if (!env.RESEND_API_KEY) return false;
  const base=(env.ADMIN_URL||"").replace(/\/$/,"");
  if (!base) return false;
  const resp=await fetch("https://api.resend.com/emails",{method:"POST",headers:{Authorization:"Bearer "+env.RESEND_API_KEY,"Content-Type":"application/json"},body:JSON.stringify({from:env.EMAIL_FROM||"Brighter Future Foundation <onboarding@resend.dev>",to:[email],subject:"Reset your admin password",html:`<p>A password reset was requested for your Brighter Future Foundation admin account.</p><p><a href="${base}/reset-password?token=${encodeURIComponent(token)}">Reset password</a></p><p>This link expires in 30 minutes. If you did not request this, ignore this email.</p>`})});
  return resp.ok;
}
async function handle(req,env) {
  await init(env.DB);
  const u=new URL(req.url),p=u.pathname,m=req.method;
  if (p==="/health"&&m==="GET") return json({ok:true,service:"Brighter Future Admin",database:true});
  if (p==="/api/content"&&m==="GET") {
    const out={}; for (const k of ["homepage","story","contact","donations","media"]) out[k]=await get(env.DB,k);
    return json(out);
  }
  if (p==="/api/enquiries"&&m==="POST") {
    const ip=req.headers.get("CF-Connecting-IP")||"unknown";
    if (!await limit(env.DB,"enquiry:"+ip,5)) return json({error:"Too many messages. Please try again later."},429);
    const b=await req.json().catch(()=>({}));
    if (String(b.website||"").trim()) return json({error:"Unable to send message."},400);
    const name=String(b.name||"").trim().slice(0,100),email=String(b.email||"").trim().slice(0,160),message=String(b.message||"").trim().slice(0,2000);
    if (!name||!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||!message) return json({error:"Please provide a name, valid email and message."},400);
    const a=await get(env.DB,"enquiries"); a.unshift({id:crypto.randomUUID(),name,email,message,createdAt:new Date().toISOString(),status:"new"});
    await put(env.DB,"enquiries",a.slice(0,200)); return json({ok:true},201);
  }
  if (p==="/api/acknowledgements"&&m==="POST") {
    const ip=req.headers.get("CF-Connecting-IP")||"unknown";
    if (!await limit(env.DB,"ack:"+ip,10)) return json({error:"Too many requests. Please try again later."},429);
    const b=await req.json().catch(()=>({}));
    if (b.acknowledged!==true) return json({error:"Acknowledgement is required."},400);
    const a=await get(env.DB,"acknowledgements"); a.unshift({id:crypto.randomUUID(),acknowledgedAt:new Date().toISOString(),source:"website"});
    await put(env.DB,"acknowledgements",a.slice(0,500)); return json({ok:true},201);
  }

  if (p==="/login"&&m==="GET") {
    const s=await session(req,env); if (s) return redirect("/dashboard");
    return page("Admin Login",`<main class="wrap login"><section class="card"><div class="brand">🌱</div><h1>Admin login</h1><p class="muted">Private management area for Brighter Future Foundation.</p>${u.searchParams.has("error")?'<p class="notice warning">Login details could not be verified.</p>':""}${u.searchParams.has("changed")?'<p class="notice">Your password has been changed. Please sign in.</p>':""}<form method="post" action="/login"><label>Email</label><input name="email" type="email" autocomplete="username" required><label>Password</label><input name="password" type="password" autocomplete="current-password" required><button type="submit">Sign in</button></form><p><a href="/forgot-password">Forgot password?</a></p></section></main>`);
  }
  if (p==="/login"&&m==="POST") {
    const origin=req.headers.get("Origin");
    if (origin && new URL(origin).host!==u.host) return json({error:"Invalid request origin."},403);
    const ip=req.headers.get("CF-Connecting-IP")||"unknown";
    if (!await limit(env.DB,"login:"+ip,8)) return redirect("/login?error=1");
    const f=await formData(req),email=String(f.get("email")||"").trim().toLowerCase(),pw=String(f.get("password")||"");
    const admin=(env.ADMIN_EMAIL||"brighterfuturefoundation85@gmail.com").toLowerCase();
    let stored=(await env.DB.prepare("SELECT value FROM admin_config WHERE key='password_hash'").first())?.value||"";
    if (!stored && env.ADMIN_INITIAL_PASSWORD) {
      stored=await makePassword(env.ADMIN_INITIAL_PASSWORD);
      await env.DB.prepare("INSERT INTO admin_config(key,value) VALUES('password_hash',?)").bind(stored).run();
    }
    if (email!==admin || !(await checkPassword(pw,stored))) return redirect("/login?error=1");
    const token=crypto.randomUUID()+crypto.randomUUID(),csrf=crypto.randomUUID()+crypto.randomUUID();
    await env.DB.prepare("INSERT INTO sessions(token_hash,csrf,expires_at) VALUES(?,?,?)").bind(await digest(token),csrf,Date.now()+28800000).run();
    return new Response(null,{status:303,headers:{Location:"/dashboard","Set-Cookie":setCookie(token)}});
  }
  if (p==="/forgot-password"&&m==="GET") return page("Forgot Password",`<main class="wrap login"><section class="card"><h1>Forgot password?</h1><p class="muted">Enter the admin email address. If recovery is configured, a reset link will be sent.</p><form method="post"><label>Admin email</label><input type="email" name="email" required><button>Send reset link</button></form><p><a href="/login">Back to login</a></p></section></main>`);
  if (p==="/forgot-password"&&m==="POST") {
    const f=await formData(req),email=String(f.get("email")||"").trim().toLowerCase(),admin=(env.ADMIN_EMAIL||"brighterfuturefoundation85@gmail.com").toLowerCase(),ip=req.headers.get("CF-Connecting-IP")||"unknown";
    if (await limit(env.DB,"reset:"+ip,4) && email===admin && env.RESEND_API_KEY && env.ADMIN_URL) {
      const token=crypto.randomUUID()+crypto.randomUUID();
      await env.DB.prepare("INSERT INTO reset_tokens(token_hash,expires_at,used) VALUES(?,?,0)").bind(await digest(token),Date.now()+1800000).run();
      await sendReset(env,email,token);
    }
    return page("Password Recovery",'<main class="wrap login"><section class="card"><h1>Check your email</h1><p class="muted">If the address matches the admin account and email delivery is configured, a reset link will arrive shortly.</p><a class="btn" href="/login">Back to login</a></section></main>');
  }
  if (p==="/reset-password"&&m==="GET") {
    const token=u.searchParams.get("token")||"",r=await env.DB.prepare("SELECT expires_at,used FROM reset_tokens WHERE token_hash=?").bind(await digest(token)).first();
    if (!r||r.used||r.expires_at<Date.now()) return page("Reset Link Expired",'<main class="wrap login"><section class="card"><h1>Reset link unavailable</h1><p class="muted">This link is invalid or has expired. Request a new one.</p><a href="/forgot-password">Request another link</a></section></main>');
    return page("Choose New Password",`<main class="wrap login"><section class="card"><h1>Choose a new password</h1><form method="post"><input type="hidden" name="token" value="${htmlEscape(token)}"><label>New password (at least 12 characters)</label><input type="password" name="password" minlength="12" required><label>Confirm password</label><input type="password" name="confirm" minlength="12" required><button>Save new password</button></form></section></main>`);
  }
  if (p==="/reset-password"&&m==="POST") {
    const f=await formData(req),token=String(f.get("token")||""),pw=String(f.get("password")||""),confirm=String(f.get("confirm")||""),hash=await digest(token);
    if (!token||pw.length<12||pw!==confirm) return page("Unable to Reset",'<main class="wrap login"><section class="card"><p class="muted">The reset link or password details are invalid. Please try again.</p><a href="/forgot-password">Request a new link</a></section></main>');
    const claim=await env.DB.prepare("UPDATE reset_tokens SET used=1 WHERE token_hash=? AND used=0 AND expires_at>?").bind(hash,Date.now()).run();
    if (!claim.meta||claim.meta.changes!==1) return page("Unable to Reset",'<main class="wrap login"><section class="card"><p class="muted">This reset link is invalid, expired or already used. Please request a new one.</p><a href="/forgot-password">Request a new link</a></section></main>');
    const newHash=await makePassword(pw);
    await env.DB.prepare("INSERT INTO admin_config(key,value) VALUES('password_hash',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=CURRENT_TIMESTAMP").bind(newHash).run();
    await env.DB.prepare("DELETE FROM sessions").run();
    return redirect("/login?changed=1");
  }

  const s=await session(req,env);
  if (p==="/admin/backup"&&m==="GET") {
    if (!s) return redirect("/login");
    const content={};
    for (const k of KEYS) content[k]=await get(env.DB,k);
    const backup={exportedAt:new Date().toISOString(),service:"Brighter Future Admin",content};
    return new Response(JSON.stringify(backup,null,2),{headers:{
      "Content-Type":"application/json; charset=utf-8",
      "Content-Disposition":"attachment; filename=brighter-future-admin-backup.json",
      "Cache-Control":"no-store",
      "X-Content-Type-Options":"nosniff"
    }});
  }
  if (p==="/logout"&&m==="POST") {
    const f=await formData(req);
    if (!s||String(f.get("csrf")||"")!==s.csrf) return json({error:"Your session expired. Please sign in again."},403);
    await env.DB.prepare("DELETE FROM sessions WHERE token_hash=?").bind(s.tokenHash).run();
    return new Response(null,{status:303,headers:{Location:"/login","Set-Cookie":setCookie("",0)}});
  }
  if (p.startsWith("/admin")||p==="/dashboard") {
    if (!s) return redirect("/login");
    if (m==="POST") {
      const f=await formData(req);
      if (String(f.get("csrf")||"")!==s.csrf) return json({error:"Your session expired or the request could not be verified. Please sign in again."},403);
      if (p==="/admin/story") {
        await put(env.DB,"story",String(f.get("story")||"").slice(0,30000)); return redirect("/admin/story?saved=1");
      }
      if (p==="/admin/media") {
        const type=String(f.get("type")||"image"),title=String(f.get("title")||"").trim().slice(0,120),description=String(f.get("description")||"").trim().slice(0,500),url=safeUrl(f.get("url"));
        if (!["image","video","story","project","news"].includes(type)||!title||!url) return page("Media Manager",'<main class="wrap"><section class="card"><p class="notice warning">Please provide a title, a valid HTTP/HTTPS URL and a supported media type.</p><a href="/admin/media">Go back</a></section></main>');
        const items=await get(env.DB,"media"); items.unshift({id:crypto.randomUUID(),type,title,description,url,createdAt:new Date().toISOString()}); await put(env.DB,"media",items.slice(0,200)); return redirect("/admin/media?saved=1");
      }
      if (p==="/admin/media/delete") {
        const id=String(f.get("id")||""),items=await get(env.DB,"media"); await put(env.DB,"media",items.filter(x=>x.id!==id)); return redirect("/admin/media");
      }
      if (p==="/admin/donations") {
        await put(env.DB,"donations",{airtelMoney:String(f.get("airtelMoney")||"").trim().slice(0,80),mtnMoney:String(f.get("mtnMoney")||"").trim().slice(0,80),accountName:String(f.get("accountName")||"").trim().slice(0,120),bank:String(f.get("bank")||"").trim().slice(0,120),accountNumber:String(f.get("accountNumber")||"").trim().slice(0,120),currency:String(f.get("currency")||"UGX").slice(0,5)}); return redirect("/admin/donations?saved=1");
      }
      if (p==="/admin/contact") {
        const email=String(f.get("email")||"").trim().slice(0,160),whatsapp=String(f.get("whatsapp")||"").trim().slice(0,80);
        if (email&&!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return page("Contact Details",'<main class="wrap"><section class="card"><p class="notice warning">Please enter a valid email address.</p><a href="/admin/contact">Go back</a></section></main>');
        await put(env.DB,"contact",{email,whatsapp}); return redirect("/admin/contact?saved=1");
      }
      if (p==="/admin/enquiries/status") {
        const id=String(f.get("id")||""),status=String(f.get("status")||"new"),items=await get(env.DB,"enquiries");
        if (!["new","read","resolved"].includes(status)) return json({error:"Invalid status."},400);
        await put(env.DB,"enquiries",items.map(x=>x.id===id?{...x,status}:x)); return redirect("/admin/enquiries");
      }
      return json({error:"Unknown management action."},404);
    }
    const saved=u.searchParams.has("saved")?'<p class="notice">Changes saved successfully.</p>':"";
    if (p==="/dashboard"||p==="/admin"||p==="/admin/") {
      const [media,enquiries,acks]=await Promise.all([get(env.DB,"media"),get(env.DB,"enquiries"),get(env.DB,"acknowledgements")]);
      const cards=[
        ["/admin/story","Stories","Edit the foundation story and website story content", "Open Stories"],
        ["/admin/media","Media Manager","Add and manage images, videos, projects and news","Manage Media"],
        ["/admin/donations","Donations","Update mobile money and bank giving details","Manage Donations"],
        ["/admin/contact","Contact Details","Update the public email address and WhatsApp number","Edit Contact"],
        ["/admin/enquiries","Enquiries",`${enquiries.length} messages received`,"View Enquiries"],
        ["/admin/acknowledgements","Terms & Privacy Acknowledgements",`${acks.length} acknowledgements recorded`,"View Records"]
      ];
      return shell("Dashboard",`<section><h1>Welcome back</h1><p class="muted">Manage Brighter Future Foundation website content and visitor messages.</p>${saved}<div class="stats"><a class="stat" href="/admin/enquiries"><strong>${enquiries.length}</strong>Enquiries</a><a class="stat" href="/admin/media"><strong>${media.length}</strong>Media items</a><a class="stat" href="/admin/acknowledgements"><strong>${acks.length}</strong>Acknowledgements</a></div><div class="grid">${cards.map(c=>`<a class="card stat" href="${c[0]}"><h2>${htmlEscape(c[1])}</h2><p class="muted">${htmlEscape(c[2])}</p><strong style="font: bold 15px Arial">${htmlEscape(c[3])} →</strong></a>`).join("")}</div></section>`,s);
    }
    if (p==="/admin/story"&&m==="GET") {
      const story=await get(env.DB,"story");
      return editor("Stories","/admin/story",area("Story page content (plain text)","story",typeof story==="string"?story:JSON.stringify(story,null,2))+`<p class="muted small">This saves the story content stored for the public website.</p>`,s);
    }
    if (p==="/admin/media"&&m==="GET") {
      const items=await get(env.DB,"media");
      const list=items.length?items.map(x=>`<div class="item"><div class="row"><div><strong>${htmlEscape(x.title||"Untitled")}</strong><div class="muted small">${htmlEscape(x.type||"media")} · ${htmlEscape(x.description||"")}</div><a href="${htmlEscape(safeUrl(x.url)||"#")}" target="_blank" rel="noopener noreferrer">Open media</a></div><form method="post" action="/admin/media/delete"><input type="hidden" name="csrf" value="${htmlEscape(s.csrf)}"><input type="hidden" name="id" value="${htmlEscape(x.id)}"><button class="danger">Delete</button></form></div></div>`).join(""):'<p class="muted">No media items have been added yet.</p>';
      return shell("Media Manager",`<section class="card"><h1>Media Manager</h1><p class="muted">Add a public image, video, story, project or news link.</p>${saved}<form method="post" action="/admin/media"><input type="hidden" name="csrf" value="${htmlEscape(s.csrf)}"><label>Type</label><select name="type"><option>image</option><option>video</option><option>story</option><option>project</option><option>news</option></select>${field("Title","title","")}${field("Media URL (must begin with http:// or https://)","url","", "url")}${area("Description","description","")}<button>Add media item</button></form></section><section class="card"><h2>Current media items (${items.length})</h2>${list}</section>`,s);
    }
    if (p==="/admin/donations"&&m==="GET") {
      const d=await get(env.DB,"donations");
      return editor("Donations","/admin/donations",saved+field("Airtel Money number","airtelMoney",d.airtelMoney)+field("MTN Mobile Money number","mtnMoney",d.mtnMoney)+field("Account name","accountName",d.accountName)+field("Bank","bank",d.bank)+field("Account number","accountNumber",d.accountNumber)+`<label>Currency</label><select name="currency"><option value="UGX" ${d.currency==="UGX"?"selected":""}>UGX</option><option value="USD" ${d.currency==="USD"?"selected":""}>USD</option></select>`,s);
    }
    if (p==="/admin/contact"&&m==="GET") {
      const c=await get(env.DB,"contact");
      return editor("Contact Details","/admin/contact",saved+field("Public email address","email",c.email,"email")+field("WhatsApp number","whatsapp",c.whatsapp),s);
    }
    if (p==="/admin/enquiries"&&m==="GET") {
      const items=await get(env.DB,"enquiries");
      const list=items.length?items.map(x=>`<div class="item"><div class="row"><strong>${htmlEscape(x.name||"Visitor")} · ${htmlEscape(x.status||"new")}</strong><span class="muted small">${htmlEscape(x.createdAt||"")}</span></div><p><a href="mailto:${htmlEscape(x.email||"")}">${htmlEscape(x.email||"")}</a></p><p>${htmlEscape(x.message||"")}</p><form method="post" action="/admin/enquiries/status"><input type="hidden" name="csrf" value="${htmlEscape(s.csrf)}"><input type="hidden" name="id" value="${htmlEscape(x.id)}"><select name="status"><option value="new" ${x.status==="new"?"selected":""}>New</option><option value="read" ${x.status==="read"?"selected":""}>Read</option><option value="resolved" ${x.status==="resolved"?"selected":""}>Resolved</option></select><button>Update status</button></form></div>`).join(""):'<p class="muted">No enquiries received yet.</p>';
      return shell("Enquiries",`<section class="card"><h1>Visitor Enquiries (${items.length})</h1>${list}</section>`,s);
    }
    if (p==="/admin/acknowledgements"&&m==="GET") {
      const items=await get(env.DB,"acknowledgements");
      const list=items.length?items.map(x=>`<div class="item"><strong>${htmlEscape(x.source||"website")}</strong><p class="muted">${htmlEscape(x.acknowledgedAt||"")}</p></div>`).join(""):'<p class="muted">No acknowledgements recorded yet.</p>';
      return shell("Terms & Privacy Acknowledgements",`<section class="card"><h1>Terms & Privacy Acknowledgements</h1><p class="muted">Records submitted by visitors through the website.</p>${list}</section>`,s);
    }
    return shell("Not Found",'<section class="card"><h1>Page not found</h1><a href="/dashboard">Return to dashboard</a></section>',s);
  }
  return page("Not Found",'<main class="wrap"><h1>Page not found</h1><a href="/login">Admin login</a></main>');
}

export default {
  async fetch(request,env) {
    try {
      return await handle(request,env);
    } catch (e) {
      console.error("Admin Worker error:", e);
      return new Response("The admin service encountered an error.",{status:500});
    }
  }
};

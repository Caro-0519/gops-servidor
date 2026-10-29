"use strict";
/* GOPS · backend. Sin dependencias externas (solo módulos incluidos en Node 22).
   - Datos: SQLite en /data/gops.db (volumen de Docker).
   - Sesión: usuario único con contraseña cifrada (scrypt) y token firmado (HMAC-SHA256) de 12 h.
   - IA: adaptadores intercambiables (anthropic | openai | gemini) elegidos por variables de entorno.
   Las rutas llegan sin el prefijo /gops; se aceptan con o sin el prefijo /api. */
const http = require("http");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { DatabaseSync } = require("node:sqlite");

const PORT = Number(process.env.PORT || 3000);
const DB_PATH = process.env.DB_PATH || "/data/gops.db";
const TOKEN_HORAS = Number(process.env.TOKEN_HORAS || 12);
const MAX_BODY = 25 * 1024 * 1024;

fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
const db = new DatabaseSync(DB_PATH);
db.exec(`
  CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS respaldos (dia TEXT NOT NULL, key TEXT NOT NULL, value TEXT NOT NULL, PRIMARY KEY (dia, key));
  CREATE TABLE IF NOT EXISTS usuario (id INTEGER PRIMARY KEY CHECK (id = 1), nombre TEXT NOT NULL, hash TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
`);

/* ---------- secretos y contraseñas ---------- */
function meta(k) { const r = db.prepare("SELECT v FROM meta WHERE k = ?").get(k); return r ? r.v : null; }
function setMeta(k, v) { db.prepare("INSERT INTO meta (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v").run(k, v); }
let JWT_SECRET = process.env.JWT_SECRET || meta("jwt_secret");
if (!JWT_SECRET) { JWT_SECRET = crypto.randomBytes(32).toString("hex"); setMeta("jwt_secret", JWT_SECRET); }

function hashClave(clave) {
  const salt = crypto.randomBytes(16).toString("hex");
  const h = crypto.scryptSync(clave, salt, 64).toString("hex");
  return `scrypt$${salt}$${h}`;
}
function verificarClave(clave, guardado) {
  const [alg, salt, h] = String(guardado).split("$");
  if (alg !== "scrypt" || !salt || !h) return false;
  const calc = crypto.scryptSync(clave, salt, 64);
  const esperado = Buffer.from(h, "hex");
  return calc.length === esperado.length && crypto.timingSafeEqual(calc, esperado);
}
const b64 = (b) => Buffer.from(b).toString("base64url");
function firmar(payload) {
  const cuerpo = `${b64(JSON.stringify({ alg: "HS256", typ: "JWT" }))}.${b64(JSON.stringify(payload))}`;
  return `${cuerpo}.${crypto.createHmac("sha256", JWT_SECRET).update(cuerpo).digest("base64url")}`;
}
function validarToken(token) {
  const p = String(token || "").split(".");
  if (p.length !== 3) return null;
  const esperado = crypto.createHmac("sha256", JWT_SECRET).update(`${p[0]}.${p[1]}`).digest("base64url");
  const a = Buffer.from(p[2]), b = Buffer.from(esperado);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const payload = JSON.parse(Buffer.from(p[1], "base64url").toString("utf8"));
    return payload.exp * 1000 > Date.now() ? payload : null;
  } catch (e) { return null; }
}
const emitirToken = (nombre) => ({ token: firmar({ sub: nombre, exp: Math.floor(Date.now() / 1000) + TOKEN_HORAS * 3600 }), horas: TOKEN_HORAS });

/* ---------- límite de intentos de ingreso ---------- */
const intentos = new Map(); // ip -> { n, hasta }
function bloqueado(ip) { const r = intentos.get(ip); return r && r.hasta > Date.now(); }
function falla(ip) {
  const r = intentos.get(ip) || { n: 0, hasta: 0 };
  r.n += 1;
  if (r.n >= 5) { r.hasta = Date.now() + 5 * 60 * 1000; r.n = 0; }
  intentos.set(ip, r);
}

/* ---------- IA: adaptadores ---------- */
const IA = {
  proveedor: (process.env.IA_PROVIDER || "none").toLowerCase(),
  llave: process.env.IA_API_KEY || "",
  modelo: process.env.IA_MODEL || "",
  baseUrl: (process.env.IA_BASE_URL || "").replace(/\/$/, ""),
};
const MODELOS_POR_DEFECTO = { anthropic: "claude-sonnet-4-6", openai: "gpt-4o", gemini: "gemini-3.8-flash" };
const iaActiva = () => ["anthropic", "openai", "gemini"].includes(IA.proveedor) && (IA.llave || IA.baseUrl);
const modeloIA = () => IA.modelo || MODELOS_POR_DEFECTO[IA.proveedor];
const bloques = (m) => (typeof m.content === "string" ? [{ type: "text", text: m.content }] : m.content || []);

async function postJSON(url, headers, body) {
  const r = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json", ...headers }, body: JSON.stringify(body) });
  let json = null;
  try { json = await r.json(); } catch (e) { /* sin cuerpo JSON */ }
  return { status: r.status, ok: r.ok, json };
}
const errorAnthropic = (status, mensaje) => ({ status, json: { type: "error", error: { type: "api_error", message: mensaje } } });
const respuestaTexto = (texto) => ({ status: 200, json: { type: "message", role: "assistant", content: [{ type: "text", text: texto }] } });

const ADAPTADORES = {
  async anthropic(req) {
    const r = await postJSON(`${IA.baseUrl || "https://api.anthropic.com"}/v1/messages`, { "x-api-key": IA.llave, "anthropic-version": "2023-06-01" },
      { model: modeloIA(), max_tokens: req.max_tokens || 1000, messages: req.messages });
    return { status: r.status, json: r.json };
  },
  async openai(req) {
    const mensajes = req.messages.map((m) => ({
      role: m.role,
      content: bloques(m).map((b) => {
        if (b.type === "text") return { type: "text", text: b.text };
        if (b.type === "image") return { type: "image_url", image_url: { url: `data:${b.source.media_type};base64,${b.source.data}` } };
        if (b.type === "document") return { type: "file", file: { filename: "documento.pdf", file_data: `data:${b.source.media_type};base64,${b.source.data}` } };
        return { type: "text", text: "" };
      }),
    }));
    const r = await postJSON(`${IA.baseUrl || "https://api.openai.com"}/v1/chat/completions`, IA.llave ? { Authorization: `Bearer ${IA.llave}` } : {},
      { model: modeloIA(), max_completion_tokens: req.max_tokens || 1000, messages: mensajes });
    if (!r.ok) return errorAnthropic(r.status, (r.json && r.json.error && r.json.error.message) || `HTTP ${r.status}`);
    const texto = r.json && r.json.choices && r.json.choices[0] && r.json.choices[0].message ? r.json.choices[0].message.content : "";
    return respuestaTexto(texto || "");
  },
  async gemini(req) {
    const contenido = req.messages.map((m) => ({
      role: m.role === "assistant" ? "model" : "user",
      parts: bloques(m).map((b) => (b.type === "text" ? { text: b.text } : { inline_data: { mime_type: b.source.media_type, data: b.source.data } })),
    }));
    const r = await postJSON(`${IA.baseUrl || "https://generativelanguage.googleapis.com"}/v1beta/models/${modeloIA()}:generateContent`, { "x-goog-api-key": IA.llave },
      { contents: contenido, generationConfig: { maxOutputTokens: req.max_tokens || 1000 } });
    if (!r.ok) return errorAnthropic(r.status, (r.json && r.json.error && r.json.error.message) || `HTTP ${r.status}`);
    const partes = r.json && r.json.candidates && r.json.candidates[0] && r.json.candidates[0].content ? r.json.candidates[0].content.parts || [] : [];
    return respuestaTexto(partes.map((p) => p.text || "").join(""));
  },
};

/* ---------- utilidades HTTP ---------- */
function enviar(res, status, obj, extra = {}) {
  const cuerpo = typeof obj === "string" ? obj : JSON.stringify(obj);
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...extra });
  res.end(cuerpo);
}
function leerCuerpo(req) {
  return new Promise((resolve, reject) => {
    let total = 0; const trozos = [];
    req.on("data", (c) => { total += c.length; if (total > MAX_BODY) { reject(Object.assign(new Error("Cuerpo demasiado grande"), { status: 413 })); req.destroy(); } else trozos.push(c); });
    req.on("end", () => { try { resolve(trozos.length ? JSON.parse(Buffer.concat(trozos).toString("utf8")) : {}); } catch (e) { reject(Object.assign(new Error("JSON inválido"), { status: 400 })); } });
    req.on("error", reject);
  });
}
const ipDe = (req) => String(req.headers["x-forwarded-for"] || req.socket.remoteAddress || "").split(",")[0].trim();
const usuario = () => db.prepare("SELECT nombre, hash FROM usuario WHERE id = 1").get();

/* ---------- servidor ---------- */
const servidor = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, "http://localhost");
    let ruta = url.pathname.replace(/^\/gops(?=\/|$)/, "").replace(/^\/api(?=\/|$)/, "").replace(/\/+$/, "") || "/";
    const m = req.method;

    // públicas
    if (m === "GET" && (ruta === "/salud" || ruta === "/")) return enviar(res, 200, { ok: true });
    if (m === "GET" && ruta === "/estado") return enviar(res, 200, { hayUsuario: !!usuario() });
    if (m === "POST" && ruta === "/configurar") {
      if (usuario()) return enviar(res, 409, { error: "Ya hay una cuenta configurada." });
      const { usuario: nombre, clave } = await leerCuerpo(req);
      if (!nombre || String(nombre).trim().length < 3) return enviar(res, 400, { error: "El usuario debe tener al menos 3 caracteres." });
      if (!clave || String(clave).length < 8) return enviar(res, 400, { error: "La contraseña debe tener al menos 8 caracteres." });
      db.prepare("INSERT INTO usuario (id, nombre, hash) VALUES (1, ?, ?)").run(String(nombre).trim(), hashClave(String(clave)));
      return enviar(res, 200, emitirToken(String(nombre).trim()));
    }
    if (m === "POST" && ruta === "/login") {
      const ip = ipDe(req);
      if (bloqueado(ip)) return enviar(res, 429, { error: "Demasiados intentos. Espera 5 minutos." });
      const { usuario: nombre, clave } = await leerCuerpo(req);
      const u = usuario();
      if (!u || String(nombre || "").trim() !== u.nombre || !verificarClave(String(clave || ""), u.hash)) { falla(ip); return enviar(res, 401, { error: "Usuario o contraseña incorrectos." }); }
      intentos.delete(ip);
      return enviar(res, 200, emitirToken(u.nombre));
    }

    // protegidas
    const auth = String(req.headers.authorization || "");
    const sesion = auth.startsWith("Bearer ") ? validarToken(auth.slice(7)) : null;
    if (!sesion) return enviar(res, 401, { error: "Sesión no válida o vencida." });

    if (m === "POST" && ruta === "/cambiar-clave") {
      const { actual, nueva } = await leerCuerpo(req);
      const u = usuario();
      if (!verificarClave(String(actual || ""), u.hash)) return enviar(res, 400, { error: "La contraseña actual no es correcta." });
      if (!nueva || String(nueva).length < 8) return enviar(res, 400, { error: "La contraseña nueva debe tener al menos 8 caracteres." });
      db.prepare("UPDATE usuario SET hash = ? WHERE id = 1").run(hashClave(String(nueva)));
      return enviar(res, 200, { ok: true });
    }

    if (ruta === "/storage" && m === "GET") {
      const prefijo = url.searchParams.get("prefix") || "";
      const filas = db.prepare("SELECT key FROM kv WHERE key LIKE ? ESCAPE '\\' ORDER BY key").all(prefijo.replace(/[\\%_]/g, "\\$&") + "%");
      return enviar(res, 200, { keys: filas.map((f) => f.key), prefix: prefijo });
    }
    const mk = ruta.match(/^\/storage\/(.+)$/);
    if (mk) {
      const key = decodeURIComponent(mk[1]);
      if (key.length > 200) return enviar(res, 400, { error: "Clave demasiado larga." });
      if (m === "GET") {
        const f = db.prepare("SELECT value FROM kv WHERE key = ?").get(key);
        return f ? enviar(res, 200, { key, value: f.value }) : enviar(res, 404, { error: "No existe." });
      }
      if (m === "PUT") {
        const { value } = await leerCuerpo(req);
        if (typeof value !== "string") return enviar(res, 400, { error: "Falta el valor." });
        const dia = new Date().toISOString().slice(0, 10);
        db.exec("BEGIN");
        try {
          // copia diaria del estado anterior (la primera escritura del día guarda cómo estaba)
          db.prepare("INSERT OR IGNORE INTO respaldos (dia, key, value) SELECT ?, key, value FROM kv WHERE key = ?").run(dia, key);
          db.prepare("DELETE FROM respaldos WHERE dia < date('now', '-30 day')").run();
          db.prepare("INSERT INTO kv (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at").run(key, value, new Date().toISOString());
          db.exec("COMMIT");
        } catch (e) { db.exec("ROLLBACK"); throw e; }
        return enviar(res, 200, { key });
      }
      if (m === "DELETE") {
        const r = db.prepare("DELETE FROM kv WHERE key = ?").run(key);
        return enviar(res, 200, { key, deleted: r.changes > 0 });
      }
    }

    if (m === "GET" && ruta === "/respaldo") {
      const kv = {};
      for (const f of db.prepare("SELECT key, value FROM kv").all()) kv[f.key] = f.value;
      const nombre = `gops-respaldo-${new Date().toISOString().slice(0, 10)}.json`;
      return enviar(res, 200, { app: "GOPS", fecha: new Date().toISOString(), kv }, { "Content-Disposition": `attachment; filename="${nombre}"` });
    }

    if (m === "GET" && ruta === "/ia/estado") return enviar(res, 200, { activa: !!iaActiva(), proveedor: IA.proveedor, modelo: iaActiva() ? modeloIA() : null });
    if (m === "GET" && ruta === "/ia/probar") {
      if (!iaActiva()) return enviar(res, 200, { ok: false, mensaje: "La IA no está configurada en el servidor (falta IA_PROVIDER e IA_API_KEY en el archivo .env)." });
      let r;
      try { r = await ADAPTADORES[IA.proveedor]({ max_tokens: 40, messages: [{ role: "user", content: [{ type: "text", text: "Responde solo con la palabra OK." }] }] }); } catch (e) { r = errorAnthropic(502, "No se pudo conectar con el proveedor de IA."); }
      if (r.status === 200 && r.json && r.json.content) return enviar(res, 200, { ok: true, proveedor: IA.proveedor, modelo: modeloIA(), respuesta: (r.json.content[0] && r.json.content[0].text || "").slice(0, 80) });
      const detalle = (r.json && r.json.error && (r.json.error.message || r.json.error)) || `HTTP ${r.status}`;
      return enviar(res, 200, { ok: false, proveedor: IA.proveedor, modelo: modeloIA(), mensaje: String(detalle).slice(0, 300) });
    }
    if (m === "POST" && ruta === "/ia") {
      if (!iaActiva()) return enviar(res, 501, { type: "error", error: { type: "not_configured", message: "La IA no está configurada en el servidor. Los demás módulos funcionan normalmente." } });
      const cuerpo = await leerCuerpo(req);
      if (!Array.isArray(cuerpo.messages)) return enviar(res, 400, { error: { message: "Solicitud inválida." } });
      let r;
      try { r = await ADAPTADORES[IA.proveedor](cuerpo); } catch (e) { r = errorAnthropic(502, "No se pudo conectar con el proveedor de IA."); }
      return enviar(res, r.status, r.json || { error: { message: "Respuesta vacía del proveedor." } });
    }

    return enviar(res, 404, { error: "Ruta no encontrada." });
  } catch (e) {
    const status = e.status || 500;
    if (status === 500) console.error(e);
    enviar(res, status, { error: status === 500 ? "Error interno." : e.message });
  }
});
servidor.listen(PORT, "0.0.0.0", () => console.log(`GOPS backend en :${PORT} · IA: ${iaActiva() ? `${IA.proveedor} (${modeloIA()})` : "desactivada"}`));
module.exports = { servidor };

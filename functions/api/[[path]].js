/**
 * Cloudflare Pages Function — Catch-all API handler for /api/*
 *
 * Pure Web Standard APIs (Web Crypto, Fetch API) with zero runtime dependencies.
 * Storage: Cloudflare KV binding `AHOORA_KV`
 *
 * Optional Environment Variables (Cloudflare Pages Settings -> Environment variables):
 *   - INITIAL_PANEL_PASSWORD : Initial main panel password (default: "AT_SERVER")
 *   - INITIAL_ADMIN_PASSWORD : Initial admin panel password (default: "AT_ADMIN")
 *   - SESSION_SECRET         : Secret key for HMAC-SHA256 session signing (auto-generated in KV if omitted)
 */

const KV_KEYS = {
  PANEL: "auth:panel",
  ADMIN: "auth:admin",
  SECRET: "auth:secret"
};

const COOKIES = {
  PANEL: "ahoora_panel_token",
  ADMIN: "ahoora_admin_token"
};

const DEFAULTS = {
  PANEL_PASSWORD: "AT_SERVER",
  ADMIN_PASSWORD: "AT_ADMIN"
};

const PBKDF2_ITERATIONS = 15000;      // Safe within Cloudflare Workers Free plan 10ms CPU limit (even for 2 ops/req)
const MAX_PBKDF2_ITERATIONS = 100000; // Cloudflare Workers Web Crypto upper limit for verification
const PANEL_TOKEN_TTL_SEC = 60 * 60 * 24 * 7; // 7 days
const ADMIN_TOKEN_TTL_SEC = 60 * 60 * 12;     // 12 hours

const PANEL_MIN_LEN = 4;
const ADMIN_MIN_LEN = 6;
const MAX_PASS_LEN = 128;

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/* ---------- In-isolate cache for signing key (reduces KV reads on Free plan) ---------- */
let cachedSecretKv = null;
let cachedSecretSource = "";
let cachedHmacKey = null;

/* ---------- In-isolate login rate limiter (zero KV writes) ---------- */
const rateLimitStore = new Map();
const MAX_RATE_LIMIT_ENTRIES = 500;

function getClientIp(request) {
  const cfIp = request.headers.get("CF-Connecting-IP");
  if (cfIp) return cfIp.trim();
  const xff = request.headers.get("X-Forwarded-For");
  if (xff) return xff.split(",")[0].trim();
  return "local";
}

function pruneRateLimit(now) {
  if (rateLimitStore.size < MAX_RATE_LIMIT_ENTRIES) return;
  for (const [k, entry] of rateLimitStore.entries()) {
    if (entry.resetAt <= now) rateLimitStore.delete(k);
  }
  if (rateLimitStore.size >= MAX_RATE_LIMIT_ENTRIES) {
    const oldestKey = rateLimitStore.keys().next().value;
    if (oldestKey !== undefined) rateLimitStore.delete(oldestKey);
  }
}

function checkRateLimit(bucket, maxAttempts, windowMs) {
  const now = Date.now();
  const entry = rateLimitStore.get(bucket);
  if (!entry || entry.resetAt <= now) {
    return { blocked: false, retryAfterSec: 0 };
  }
  if (entry.count >= maxAttempts) {
    return {
      blocked: true,
      retryAfterSec: Math.max(1, Math.ceil((entry.resetAt - now) / 1000))
    };
  }
  return { blocked: false, retryAfterSec: 0 };
}

function recordFailedAttempt(bucket, windowMs) {
  const now = Date.now();
  pruneRateLimit(now);
  const entry = rateLimitStore.get(bucket);
  if (!entry || entry.resetAt <= now) {
    rateLimitStore.set(bucket, { count: 1, resetAt: now + windowMs });
  } else {
    entry.count += 1;
  }
}

function clearFailedAttempts(bucket) {
  rateLimitStore.delete(bucket);
}

/* ---------- Encoding & Crypto Helpers ---------- */
function bytesToBase64Url(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlToBytes(str) {
  if (typeof str !== "string" || !/^[A-Za-z0-9\-_]+$/.test(str)) {
    throw new Error("Invalid base64url");
  }
  let padded = str.replace(/-/g, "+").replace(/_/g, "/");
  while (padded.length % 4 !== 0) padded += "=";
  const binary = atob(padded);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}

function randomBytes(length) {
  const buf = new Uint8Array(length);
  crypto.getRandomValues(buf);
  return buf;
}

function randomHex(byteLength) {
  const buf = randomBytes(byteLength);
  let hex = "";
  for (let i = 0; i < buf.length; i++) {
    hex += buf[i].toString(16).padStart(2, "0");
  }
  return hex;
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

async function derivePbkdf2(password, saltBytes, iterations) {
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt: saltBytes,
      iterations
    },
    keyMaterial,
    256
  );
  return new Uint8Array(bits);
}

async function hashPassword(password) {
  const salt = randomBytes(16);
  const derived = await derivePbkdf2(password, salt, PBKDF2_ITERATIONS);
  return `pbkdf2$${PBKDF2_ITERATIONS}$${bytesToBase64Url(salt)}$${bytesToBase64Url(derived)}`;
}

async function verifyPassword(password, storedHash) {
  if (typeof password !== "string" || typeof storedHash !== "string") return false;
  const parts = storedHash.split("$");
  if (parts.length !== 4 || parts[0] !== "pbkdf2") return false;

  const iterations = Number(parts[1]);
  if (!Number.isInteger(iterations) || iterations < 10000 || iterations > MAX_PBKDF2_ITERATIONS) {
    return false;
  }

  let saltBytes;
  let expectedBytes;
  try {
    saltBytes = base64UrlToBytes(parts[2]);
    expectedBytes = base64UrlToBytes(parts[3]);
  } catch {
    return false;
  }

  const derived = await derivePbkdf2(password, saltBytes, iterations);
  return timingSafeEqual(derived, expectedBytes);
}

async function getSigningKey(env) {
  const envSecret = typeof env.SESSION_SECRET === "string" ? env.SESSION_SECRET.trim() : "";
  if (cachedHmacKey && cachedSecretKv === env.AHOORA_KV && cachedSecretSource === envSecret) {
    return cachedHmacKey;
  }

  let keyBytes;

  if (envSecret.length >= 16) {
    const digest = await crypto.subtle.digest("SHA-256", encoder.encode(envSecret));
    keyBytes = new Uint8Array(digest);
  } else {
    let stored = await env.AHOORA_KV.get(KV_KEYS.SECRET);
    if (!stored) {
      const fresh = randomBytes(32);
      stored = bytesToBase64Url(fresh);
      await env.AHOORA_KV.put(KV_KEYS.SECRET, stored);
      keyBytes = fresh;
    } else {
      try {
        keyBytes = base64UrlToBytes(stored);
      } catch {
        const fresh = randomBytes(32);
        stored = bytesToBase64Url(fresh);
        await env.AHOORA_KV.put(KV_KEYS.SECRET, stored);
        keyBytes = fresh;
      }
    }
  }

  const key = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );

  cachedSecretKv = env.AHOORA_KV;
  cachedSecretSource = envSecret;
  cachedHmacKey = key;
  return key;
}

async function signToken(env, payload) {
  const key = await getSigningKey(env);
  const payloadB64 = bytesToBase64Url(encoder.encode(JSON.stringify(payload)));
  const sigBuf = await crypto.subtle.sign("HMAC", key, encoder.encode(payloadB64));
  const sigB64 = bytesToBase64Url(new Uint8Array(sigBuf));
  return `${payloadB64}.${sigB64}`;
}

async function verifyToken(env, token, expectedRole, record) {
  if (!token || typeof token !== "string") {
    return { valid: false, reason: "unauthenticated" };
  }

  const parts = token.split(".");
  if (parts.length !== 2) {
    return { valid: false, reason: "unauthenticated" };
  }

  const [payloadB64, sigB64] = parts;
  let sigBytes;
  try {
    sigBytes = base64UrlToBytes(sigB64);
  } catch {
    return { valid: false, reason: "unauthenticated" };
  }

  const key = await getSigningKey(env);
  const expectedSigBuf = await crypto.subtle.sign("HMAC", key, encoder.encode(payloadB64));
  const expectedSigBytes = new Uint8Array(expectedSigBuf);
  if (!timingSafeEqual(sigBytes, expectedSigBytes)) {
    return { valid: false, reason: "unauthenticated" };
  }

  let payload;
  try {
    payload = JSON.parse(decoder.decode(base64UrlToBytes(payloadB64)));
  } catch {
    return { valid: false, reason: "unauthenticated" };
  }

  const nowSec = Math.floor(Date.now() / 1000);
  if (!payload || payload.role !== expectedRole) {
    return { valid: false, reason: "unauthenticated" };
  }
  if (typeof payload.exp !== "number" || payload.exp <= nowSec) {
    return { valid: false, reason: "expired" };
  }

  if (payload.v !== record.version || payload.e !== record.epoch) {
    return { valid: false, reason: "password_changed" };
  }

  return { valid: true, payload };
}

/* ---------- KV Auth Records ---------- */
async function ensureAuthRecord(env, role) {
  const kvKey = role === "admin" ? KV_KEYS.ADMIN : KV_KEYS.PANEL;
  const raw = await env.AHOORA_KV.get(kvKey);
  if (raw) {
    try {
      const parsed = JSON.parse(raw);
      if (parsed && typeof parsed.passwordHash === "string" && typeof parsed.version === "number" && typeof parsed.epoch === "string") {
        return parsed;
      }
    } catch {
      // Fall through to re-initialize malformed record
    }
  }

  const envVar = role === "admin" ? env.INITIAL_ADMIN_PASSWORD : env.INITIAL_PANEL_PASSWORD;
  const trimmedEnv = typeof envVar === "string" ? envVar.trim() : "";
  const initialPassword = trimmedEnv || (role === "admin" ? DEFAULTS.ADMIN_PASSWORD : DEFAULTS.PANEL_PASSWORD);
  const isDefault = !trimmedEnv;

  const record = {
    passwordHash: await hashPassword(initialPassword),
    version: 1,
    epoch: randomHex(8),
    updatedAt: new Date().toISOString(),
    isDefault
  };

  await env.AHOORA_KV.put(kvKey, JSON.stringify(record));
  return record;
}

function publicMeta(record) {
  return {
    version: record.version,
    updatedAt: record.updatedAt,
    isDefault: Boolean(record.isDefault)
  };
}

/* ---------- HTTP / Cookie Helpers ---------- */
function parseCookies(cookieHeader) {
  const map = Object.create(null);
  if (!cookieHeader) return map;
  const pairs = cookieHeader.split(";");
  for (let i = 0; i < pairs.length; i++) {
    const idx = pairs[i].indexOf("=");
    if (idx === -1) continue;
    const name = pairs[i].slice(0, idx).trim();
    const val = pairs[i].slice(idx + 1).trim();
    if (name) {
      try {
        map[name] = decodeURIComponent(val);
      } catch {
        map[name] = val;
      }
    }
  }
  return map;
}

function isHttpsRequest(request) {
  try {
    const url = new URL(request.url);
    if (url.protocol === "https:") return true;
  } catch {
    // ignore
  }
  const proto = request.headers.get("X-Forwarded-Proto");
  return proto === "https";
}

function buildCookie(name, value, maxAge, secure) {
  const parts = [
    `${name}=${encodeURIComponent(value)}`,
    "HttpOnly",
    "Path=/",
    "SameSite=Lax",
    `Max-Age=${maxAge}`
  ];
  if (secure) parts.push("Secure");
  return parts.join("; ");
}

function extractToken(request, cookieName) {
  const authHeader = request.headers.get("Authorization") || "";
  if (authHeader.startsWith("Bearer ")) {
    const bearer = authHeader.slice(7).trim();
    if (bearer) return { token: bearer, source: "bearer" };
  }
  const cookies = parseCookies(request.headers.get("Cookie"));
  if (cookies[cookieName]) {
    return { token: cookies[cookieName], source: "cookie" };
  }
  return { token: "", source: "none" };
}

function verifySameOrigin(request) {
  const origin = request.headers.get("Origin");
  if (!origin) return true;
  try {
    const originHost = new URL(origin).host.toLowerCase();
    const requestHost = new URL(request.url).host.toLowerCase();
    return originHost === requestHost;
  } catch {
    return false;
  }
}

function jsonResponse(body, status = 200, extraHeaders = {}) {
  const headers = new Headers({
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
    "Pragma": "no-cache",
    "X-Content-Type-Options": "nosniff"
  });
  for (const [k, v] of Object.entries(extraHeaders)) {
    if (v !== undefined && v !== null) headers.append(k, v);
  }
  return new Response(JSON.stringify(body), { status, headers });
}

async function readJsonBody(request) {
  try {
    const data = await request.json();
    if (!data || typeof data !== "object" || Array.isArray(data)) {
      return { ok: false };
    }
    return { ok: true, data };
  } catch {
    return { ok: false };
  }
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function normalizePasswordInput(val) {
  return typeof val === "string" ? val.trim() : "";
}

async function issueSessionToken(env, role, record, ttlSec) {
  const nowSec = Math.floor(Date.now() / 1000);
  return signToken(env, {
    role,
    v: record.version,
    e: record.epoch,
    iat: nowSec,
    exp: nowSec + ttlSec
  });
}

/* ---------- Route Handlers ---------- */
async function handlePanelSession(request, env) {
  const record = await ensureAuthRecord(env, "panel");
  const { token, source } = extractToken(request, COOKIES.PANEL);
  const result = await verifyToken(env, token, "panel", record);

  if (!result.valid) {
    const extra = {};
    if (source === "cookie") {
      extra["Set-Cookie"] = buildCookie(COOKIES.PANEL, "", 0, isHttpsRequest(request));
    }
    return jsonResponse(
      { ok: false, authenticated: false, reason: result.reason },
      401,
      extra
    );
  }

  return jsonResponse({
    ok: true,
    authenticated: true,
    ...publicMeta(record)
  });
}

async function handlePanelLogin(request, env) {
  const ip = getClientIp(request);
  const bucket = `panel:${ip}`;
  const limit = checkRateLimit(bucket, 10, 10 * 60 * 1000);
  if (limit.blocked) {
    return jsonResponse(
      {
        ok: false,
        error: "تعداد تلاش‌های ناموفق زیاد است. لطفاً چند دقیقه دیگر دوباره تلاش کنید.",
        retryAfterSec: limit.retryAfterSec
      },
      429,
      { "Retry-After": String(limit.retryAfterSec) }
    );
  }

  const parsed = await readJsonBody(request);
  if (!parsed.ok) {
    return jsonResponse({ ok: false, error: "فرمت درخواست نامعتبر است." }, 400);
  }

  const password = normalizePasswordInput(parsed.data.password);
  if (!password) {
    return jsonResponse({ ok: false, error: "لطفاً رمز عبور را وارد کنید." }, 400);
  }

  const record = await ensureAuthRecord(env, "panel");
  const valid = await verifyPassword(password, record.passwordHash);
  if (!valid) {
    recordFailedAttempt(bucket, 10 * 60 * 1000);
    await sleep(250);
    return jsonResponse({ ok: false, error: "رمز عبور اشتباه است" }, 401);
  }

  clearFailedAttempts(bucket);
  const token = await issueSessionToken(env, "panel", record, PANEL_TOKEN_TTL_SEC);
  const cookie = buildCookie(COOKIES.PANEL, token, PANEL_TOKEN_TTL_SEC, isHttpsRequest(request));

  return jsonResponse(
    {
      ok: true,
      token,
      ...publicMeta(record)
    },
    200,
    { "Set-Cookie": cookie }
  );
}

function handlePanelLogout(request) {
  return jsonResponse(
    { ok: true },
    200,
    { "Set-Cookie": buildCookie(COOKIES.PANEL, "", 0, isHttpsRequest(request)) }
  );
}

async function requireAdminSession(request, env) {
  const adminRecord = await ensureAuthRecord(env, "admin");
  const { token, source } = extractToken(request, COOKIES.ADMIN);
  const result = await verifyToken(env, token, "admin", adminRecord);

  if (!result.valid) {
    const extra = {};
    if (source === "cookie") {
      extra["Set-Cookie"] = buildCookie(COOKIES.ADMIN, "", 0, isHttpsRequest(request));
    }
    return {
      ok: false,
      response: jsonResponse(
        {
          ok: false,
          authenticated: false,
          reason: result.reason,
          error:
            result.reason === "password_changed"
              ? "رمز ادمین تغییر کرده است. لطفاً دوباره وارد شوید."
              : "نشست ادمین معتبر نیست. لطفاً وارد شوید."
        },
        401,
        extra
      )
    };
  }

  return { ok: true, adminRecord };
}

async function handleAdminSession(request, env) {
  const auth = await requireAdminSession(request, env);
  if (!auth.ok) return auth.response;

  const panelRecord = await ensureAuthRecord(env, "panel");
  return jsonResponse({
    ok: true,
    authenticated: true,
    panel: publicMeta(panelRecord),
    admin: publicMeta(auth.adminRecord)
  });
}

async function handleAdminLogin(request, env) {
  const ip = getClientIp(request);
  const bucket = `admin:${ip}`;
  const limit = checkRateLimit(bucket, 8, 15 * 60 * 1000);
  if (limit.blocked) {
    return jsonResponse(
      {
        ok: false,
        error: "تعداد تلاش‌های ناموفق ادمین زیاد است. لطفاً ۱۵ دقیقه دیگر تلاش کنید.",
        retryAfterSec: limit.retryAfterSec
      },
      429,
      { "Retry-After": String(limit.retryAfterSec) }
    );
  }

  const parsed = await readJsonBody(request);
  if (!parsed.ok) {
    return jsonResponse({ ok: false, error: "فرمت درخواست نامعتبر است." }, 400);
  }

  const password = normalizePasswordInput(parsed.data.password);
  if (!password) {
    return jsonResponse({ ok: false, error: "لطفاً رمز ادمین را وارد کنید." }, 400);
  }

  const adminRecord = await ensureAuthRecord(env, "admin");
  const valid = await verifyPassword(password, adminRecord.passwordHash);
  if (!valid) {
    recordFailedAttempt(bucket, 15 * 60 * 1000);
    await sleep(300);
    return jsonResponse({ ok: false, error: "رمز عبور ادمین اشتباه است" }, 401);
  }

  clearFailedAttempts(bucket);
  const panelRecord = await ensureAuthRecord(env, "panel");
  const token = await issueSessionToken(env, "admin", adminRecord, ADMIN_TOKEN_TTL_SEC);
  const cookie = buildCookie(COOKIES.ADMIN, token, ADMIN_TOKEN_TTL_SEC, isHttpsRequest(request));

  return jsonResponse(
    {
      ok: true,
      token,
      panel: publicMeta(panelRecord),
      admin: publicMeta(adminRecord)
    },
    200,
    { "Set-Cookie": cookie }
  );
}

function handleAdminLogout(request) {
  return jsonResponse(
    { ok: true },
    200,
    { "Set-Cookie": buildCookie(COOKIES.ADMIN, "", 0, isHttpsRequest(request)) }
  );
}

async function handleChangePanelPassword(request, env) {
  const auth = await requireAdminSession(request, env);
  if (!auth.ok) return auth.response;

  const parsed = await readJsonBody(request);
  if (!parsed.ok) {
    return jsonResponse({ ok: false, error: "فرمت درخواست نامعتبر است." }, 400);
  }

  const newPassword = normalizePasswordInput(parsed.data.newPassword);
  if (newPassword.length < PANEL_MIN_LEN) {
    return jsonResponse(
      { ok: false, error: `رمز جدید پنل اصلی باید حداقل ${PANEL_MIN_LEN} کاراکتر باشد.` },
      400
    );
  }
  if (newPassword.length > MAX_PASS_LEN) {
    return jsonResponse(
      { ok: false, error: `رمز عبور نمی‌تواند بیشتر از ${MAX_PASS_LEN} کاراکتر باشد.` },
      400
    );
  }

  const currentPanel = await ensureAuthRecord(env, "panel");
  const updatedPanel = {
    passwordHash: await hashPassword(newPassword),
    version: (currentPanel.version || 0) + 1,
    epoch: randomHex(8),
    updatedAt: new Date().toISOString(),
    isDefault: false
  };

  await env.AHOORA_KV.put(KV_KEYS.PANEL, JSON.stringify(updatedPanel));

  return jsonResponse({
    ok: true,
    message: "رمز ورود پنل اصلی با موفقیت تغییر کرد و برای همه کاربران اعمال شد.",
    panel: publicMeta(updatedPanel)
  });
}

async function handleChangeAdminPassword(request, env) {
  const auth = await requireAdminSession(request, env);
  if (!auth.ok) return auth.response;

  const parsed = await readJsonBody(request);
  if (!parsed.ok) {
    return jsonResponse({ ok: false, error: "فرمت درخواست نامعتبر است." }, 400);
  }

  const currentPassword = normalizePasswordInput(parsed.data.currentPassword);
  const newPassword = normalizePasswordInput(parsed.data.newPassword);

  if (!currentPassword) {
    return jsonResponse({ ok: false, error: "لطفاً رمز فعلی ادمین را وارد کنید." }, 400);
  }
  if (newPassword.length < ADMIN_MIN_LEN) {
    return jsonResponse(
      { ok: false, error: `رمز جدید ادمین باید حداقل ${ADMIN_MIN_LEN} کاراکتر باشد.` },
      400
    );
  }
  if (newPassword.length > MAX_PASS_LEN) {
    return jsonResponse(
      { ok: false, error: `رمز عبور نمی‌تواند بیشتر از ${MAX_PASS_LEN} کاراکتر باشد.` },
      400
    );
  }

  const currentValid = await verifyPassword(currentPassword, auth.adminRecord.passwordHash);
  if (!currentValid) {
    await sleep(250);
    return jsonResponse({ ok: false, error: "رمز فعلی ادمین اشتباه است." }, 400);
  }

  if (newPassword === currentPassword) {
    return jsonResponse({ ok: false, error: "رمز جدید ادمین باید با رمز فعلی متفاوت باشد." }, 400);
  }

  const updatedAdmin = {
    passwordHash: await hashPassword(newPassword),
    version: (auth.adminRecord.version || 0) + 1,
    epoch: randomHex(8),
    updatedAt: new Date().toISOString(),
    isDefault: false
  };

  await env.AHOORA_KV.put(KV_KEYS.ADMIN, JSON.stringify(updatedAdmin));

  // Refresh current admin's token while invalidating all other admin sessions
  const newToken = await issueSessionToken(env, "admin", updatedAdmin, ADMIN_TOKEN_TTL_SEC);
  const cookie = buildCookie(COOKIES.ADMIN, newToken, ADMIN_TOKEN_TTL_SEC, isHttpsRequest(request));

  return jsonResponse(
    {
      ok: true,
      message: "رمز ورود پنل ادمین با موفقیت تغییر کرد.",
      token: newToken,
      admin: publicMeta(updatedAdmin)
    },
    200,
    { "Set-Cookie": cookie }
  );
}

/* ---------- Main Entrypoint ---------- */
export async function onRequest(context) {
  const { request, env } = context;
  const method = request.method.toUpperCase();
  const pathname = new URL(request.url).pathname.replace(/\/+$/, "") || "/";

  if (pathname === "/api/health") {
    if (method !== "GET") {
      return jsonResponse({ ok: false, error: "متد درخواست مجاز نیست." }, 405);
    }
    return jsonResponse({
      ok: true,
      kvConfigured: Boolean(env && env.AHOORA_KV)
    });
  }

  if (!env || !env.AHOORA_KV) {
    return jsonResponse(
      {
        ok: false,
        error: "فضای ذخیره‌سازی KV با نام AHOORA_KV در تنظیمات Cloudflare Pages متصل نشده است."
      },
      503
    );
  }

  if (method === "POST" && !verifySameOrigin(request)) {
    return jsonResponse({ ok: false, error: "درخواست نامعتبر (Origin غیرمجاز)." }, 403);
  }

  try {
    switch (pathname) {
      case "/api/auth/session":
        if (method !== "GET") return jsonResponse({ ok: false, error: "متد درخواست مجاز نیست." }, 405);
        return await handlePanelSession(request, env);

      case "/api/auth/login":
        if (method !== "POST") return jsonResponse({ ok: false, error: "متد درخواست مجاز نیست." }, 405);
        return await handlePanelLogin(request, env);

      case "/api/auth/logout":
        if (method !== "POST") return jsonResponse({ ok: false, error: "متد درخواست مجاز نیست." }, 405);
        return handlePanelLogout(request);

      case "/api/admin/session":
        if (method !== "GET") return jsonResponse({ ok: false, error: "متد درخواست مجاز نیست." }, 405);
        return await handleAdminSession(request, env);

      case "/api/admin/login":
        if (method !== "POST") return jsonResponse({ ok: false, error: "متد درخواست مجاز نیست." }, 405);
        return await handleAdminLogin(request, env);

      case "/api/admin/logout":
        if (method !== "POST") return jsonResponse({ ok: false, error: "متد درخواست مجاز نیست." }, 405);
        return handleAdminLogout(request);

      case "/api/admin/panel-password":
        if (method !== "POST") return jsonResponse({ ok: false, error: "متد درخواست مجاز نیست." }, 405);
        return await handleChangePanelPassword(request, env);

      case "/api/admin/admin-password":
        if (method !== "POST") return jsonResponse({ ok: false, error: "متد درخواست مجاز نیست." }, 405);
        return await handleChangeAdminPassword(request, env);

      default:
        return jsonResponse({ ok: false, error: "مسیر API پیدا نشد." }, 404);
    }
  } catch (err) {
    console.error("[Ahoora API Error]", err);
    return jsonResponse({ ok: false, error: "خطای داخلی سرور رخ داد." }, 500);
  }
}

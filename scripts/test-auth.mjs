import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { onRequest } from "../functions/api/[[path]].js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..");

function createMemoryKv() {
  const map = new Map();
  return {
    async get(key, type = "text") {
      if (!map.has(key)) return null;
      const val = map.get(key);
      return type === "json" ? JSON.parse(val) : val;
    },
    async put(key, value) {
      map.set(key, typeof value === "string" ? value : String(value));
    },
    async delete(key) {
      map.delete(key);
    },
    _map: map
  };
}

async function callApi(env, method, route, { body, headers = {}, ip = "198.51.100.10" } = {}) {
  const reqHeaders = new Headers(headers);
  if (ip) reqHeaders.set("CF-Connecting-IP", ip);
  if (body !== undefined && !reqHeaders.has("Content-Type")) {
    reqHeaders.set("Content-Type", "application/json");
  }
  const req = new Request(`https://ahoora.example.com${route}`, {
    method,
    headers: reqHeaders,
    body: body !== undefined ? JSON.stringify(body) : undefined
  });
  const res = await onRequest({ request: req, env, params: {} });
  const data = await res.json();
  return { status: res.status, headers: res.headers, data };
}

function extractCookieValue(resHeaders, name) {
  const sc = resHeaders.get("Set-Cookie") || "";
  const match = sc.match(new RegExp(`${name}=([^;]+)`));
  return match ? decodeURIComponent(match[1]) : "";
}

async function runTests() {
  console.log("Running Ahoora Auth & Admin Panel tests...");

  // 1. Static source hygiene checks
  const indexHtml = fs.readFileSync(path.join(ROOT, "index.html"), "utf8");
  assert.ok(!indexHtml.includes("PANEL_PASS"), "index.html must not contain hardcoded PANEL_PASS");
  assert.ok(!indexHtml.includes("AT_SERVER"), "index.html must not contain hardcoded AT_SERVER password");
  assert.ok(!indexHtml.includes("__CF$cv$params"), "index.html must not contain stale CF challenge snippet");

  // 2. Missing KV binding returns clean 503
  {
    const health = await callApi({}, "GET", "/api/health");
    assert.equal(health.status, 200);
    assert.equal(health.data.kvConfigured, false);

    const noKv = await callApi({}, "GET", "/api/auth/session");
    assert.equal(noKv.status, 503);
    assert.equal(noKv.data.ok, false);
    assert.ok(noKv.data.error.includes("AHOORA_KV"));
  }

  // 3. Full auth & global password rotation flow
  const kv = createMemoryKv();
  const env = { AHOORA_KV: kv };

  const healthOk = await callApi(env, "GET", "/api/health");
  assert.equal(healthOk.status, 200);
  assert.equal(healthOk.data.kvConfigured, true);

  // Unauthenticated checks
  const unauthPanel = await callApi(env, "GET", "/api/auth/session");
  assert.equal(unauthPanel.status, 401);
  assert.equal(unauthPanel.data.authenticated, false);

  const unauthAdmin = await callApi(env, "GET", "/api/admin/session");
  assert.equal(unauthAdmin.status, 401);
  assert.equal(unauthAdmin.data.authenticated, false);

  const unauthChange = await callApi(env, "POST", "/api/admin/panel-password", {
    body: { newPassword: "hacked" }
  });
  assert.equal(unauthChange.status, 401);

  // Wrong main panel password fails
  const badPanelLogin = await callApi(env, "POST", "/api/auth/login", {
    body: { password: "WRONG" }
  });
  assert.equal(badPanelLogin.status, 401);

  // Default main panel password succeeds (User A + User B simulating two users)
  const userALogin = await callApi(env, "POST", "/api/auth/login", {
    body: { password: "AT_SERVER" },
    ip: "203.0.113.1"
  });
  assert.equal(userALogin.status, 200);
  assert.equal(userALogin.data.ok, true);
  assert.equal(userALogin.data.version, 1);
  const userAToken = userALogin.data.token;
  assert.ok(userAToken);

  const userBLogin = await callApi(env, "POST", "/api/auth/login", {
    body: { password: "AT_SERVER" },
    ip: "203.0.113.2"
  });
  assert.equal(userBLogin.status, 200);
  const userBCookie = extractCookieValue(userBLogin.headers, "ahoora_panel_token");
  assert.ok(userBCookie);

  // Verify stored password in KV is hashed (not plaintext!)
  const storedPanelRaw = await kv.get("auth:panel");
  assert.ok(!storedPanelRaw.includes("AT_SERVER"), "KV must never store plaintext password");
  assert.ok(storedPanelRaw.includes("pbkdf2$15000$"), "KV must store PBKDF2-SHA256 hash");

  // Both User A (Bearer) and User B (Cookie) have valid sessions
  const checkA1 = await callApi(env, "GET", "/api/auth/session", {
    headers: { Authorization: `Bearer ${userAToken}` }
  });
  assert.equal(checkA1.status, 200);
  assert.equal(checkA1.data.authenticated, true);

  const checkB1 = await callApi(env, "GET", "/api/auth/session", {
    headers: { Cookie: `ahoora_panel_token=${encodeURIComponent(userBCookie)}` }
  });
  assert.equal(checkB1.status, 200);
  assert.equal(checkB1.data.authenticated, true);

  // Admin login with wrong password fails
  const badAdminLogin = await callApi(env, "POST", "/api/admin/login", {
    body: { password: "wrong-admin" }
  });
  assert.equal(badAdminLogin.status, 401);

  // Admin login with default password succeeds
  const adminLogin = await callApi(env, "POST", "/api/admin/login", {
    body: { password: "AT_ADMIN" }
  });
  assert.equal(adminLogin.status, 200);
  assert.equal(adminLogin.data.ok, true);
  assert.equal(adminLogin.data.admin.isDefault, true);
  assert.equal(adminLogin.data.panel.isDefault, true);
  const adminToken1 = adminLogin.data.token;

  // Reject too-short panel password
  const shortPanelPass = await callApi(env, "POST", "/api/admin/panel-password", {
    headers: { Authorization: `Bearer ${adminToken1}` },
    body: { newPassword: "123" }
  });
  assert.equal(shortPanelPass.status, 400);

  // Admin changes main panel password globally!
  const changePanelPass = await callApi(env, "POST", "/api/admin/panel-password", {
    headers: { Authorization: `Bearer ${adminToken1}` },
    body: { newPassword: "NEW_GLOBAL_2026" }
  });
  assert.equal(changePanelPass.status, 200);
  assert.equal(changePanelPass.data.ok, true);
  assert.equal(changePanelPass.data.panel.version, 2);
  assert.equal(changePanelPass.data.panel.isDefault, false);

  // User A (Bearer) & User B (Cookie) are IMMEDIATELY kicked out with reason="password_changed"!
  const checkA2 = await callApi(env, "GET", "/api/auth/session", {
    headers: { Authorization: `Bearer ${userAToken}` }
  });
  assert.equal(checkA2.status, 401);
  assert.equal(checkA2.data.authenticated, false);
  assert.equal(checkA2.data.reason, "password_changed");

  const checkB2 = await callApi(env, "GET", "/api/auth/session", {
    headers: { Cookie: `ahoora_panel_token=${encodeURIComponent(userBCookie)}` }
  });
  assert.equal(checkB2.status, 401);
  assert.equal(checkB2.data.authenticated, false);
  assert.equal(checkB2.data.reason, "password_changed");
  assert.ok((checkB2.headers.get("Set-Cookie") || "").includes("Max-Age=0"));

  // Old main panel password no longer works
  const oldPassRetry = await callApi(env, "POST", "/api/auth/login", {
    body: { password: "AT_SERVER" },
    ip: "203.0.113.3"
  });
  assert.equal(oldPassRetry.status, 401);

  // New main panel password works for everyone!
  const newPassLogin = await callApi(env, "POST", "/api/auth/login", {
    body: { password: "NEW_GLOBAL_2026" },
    ip: "203.0.113.4"
  });
  assert.equal(newPassLogin.status, 200);
  assert.equal(newPassLogin.data.version, 2);

  const checkNewSession = await callApi(env, "GET", "/api/auth/session", {
    headers: { Authorization: `Bearer ${newPassLogin.data.token}` }
  });
  assert.equal(checkNewSession.status, 200);
  assert.equal(checkNewSession.data.authenticated, true);

  // 4. Admin password rotation
  const wrongCurrentAdmin = await callApi(env, "POST", "/api/admin/admin-password", {
    headers: { Authorization: `Bearer ${adminToken1}` },
    body: { currentPassword: "WRONG", newPassword: "SuperSecretAdmin99" }
  });
  assert.equal(wrongCurrentAdmin.status, 400);

  const sameAdminPass = await callApi(env, "POST", "/api/admin/admin-password", {
    headers: { Authorization: `Bearer ${adminToken1}` },
    body: { currentPassword: "AT_ADMIN", newPassword: "AT_ADMIN" }
  });
  assert.equal(sameAdminPass.status, 400);

  const changeAdminPass = await callApi(env, "POST", "/api/admin/admin-password", {
    headers: { Authorization: `Bearer ${adminToken1}` },
    body: { currentPassword: "AT_ADMIN", newPassword: "SuperSecretAdmin99" }
  });
  assert.equal(changeAdminPass.status, 200);
  assert.equal(changeAdminPass.data.ok, true);
  assert.equal(changeAdminPass.data.admin.version, 2);
  assert.equal(changeAdminPass.data.admin.isDefault, false);
  const adminToken2 = changeAdminPass.data.token;
  assert.ok(adminToken2 && adminToken2 !== adminToken1);

  // Old admin token is immediately invalidated!
  const oldAdminCheck = await callApi(env, "GET", "/api/admin/session", {
    headers: { Authorization: `Bearer ${adminToken1}` }
  });
  assert.equal(oldAdminCheck.status, 401);
  assert.equal(oldAdminCheck.data.reason, "password_changed");

  // New admin token stays valid!
  const newAdminCheck = await callApi(env, "GET", "/api/admin/session", {
    headers: { Authorization: `Bearer ${adminToken2}` }
  });
  assert.equal(newAdminCheck.status, 200);
  assert.equal(newAdminCheck.data.authenticated, true);
  assert.equal(newAdminCheck.data.admin.isDefault, false);

  // Old admin password fails, new admin password works
  const oldAdminPassLogin = await callApi(env, "POST", "/api/admin/login", {
    body: { password: "AT_ADMIN" },
    ip: "203.0.113.5"
  });
  assert.equal(oldAdminPassLogin.status, 401);

  const newAdminPassLogin = await callApi(env, "POST", "/api/admin/login", {
    body: { password: "SuperSecretAdmin99" },
    ip: "203.0.113.5"
  });
  assert.equal(newAdminPassLogin.status, 200);

  // 5. Same-origin CSRF check on POST
  const badOrigin = await callApi(env, "POST", "/api/auth/login", {
    headers: { Origin: "https://evil.example.net" },
    body: { password: "NEW_GLOBAL_2026" }
  });
  assert.equal(badOrigin.status, 403);

  // 6. Rate limiting triggers 429 after repeated failed attempts
  const attackerIp = "198.51.100.99";
  for (let i = 0; i < 8; i++) {
    const fail = await callApi(env, "POST", "/api/admin/login", {
      body: { password: "guess" },
      ip: attackerIp
    });
    assert.equal(fail.status, 401);
  }
  const blocked = await callApi(env, "POST", "/api/admin/login", {
    body: { password: "SuperSecretAdmin99" },
    ip: attackerIp
  });
  assert.equal(blocked.status, 429);

  // 7. Custom INITIAL_* environment variables & SESSION_SECRET
  const kv2 = createMemoryKv();
  const customEnv = {
    AHOORA_KV: kv2,
    INITIAL_PANEL_PASSWORD: "CustomPanelPass",
    INITIAL_ADMIN_PASSWORD: "CustomAdminPass",
    SESSION_SECRET: "a-very-long-secret-key-for-hmac-signing-12345"
  };
  const customPanel = await callApi(customEnv, "POST", "/api/auth/login", {
    body: { password: "CustomPanelPass" },
    ip: "203.0.113.50"
  });
  assert.equal(customPanel.status, 200);
  assert.equal(customPanel.data.isDefault, false);

  const customAdmin = await callApi(customEnv, "POST", "/api/admin/login", {
    body: { password: "CustomAdminPass" },
    ip: "203.0.113.50"
  });
  assert.equal(customAdmin.status, 200);
  assert.equal(customAdmin.data.admin.isDefault, false);

  // 8. Logout clears cookie
  const logoutRes = await callApi(env, "POST", "/api/auth/logout");
  assert.equal(logoutRes.status, 200);
  assert.ok((logoutRes.headers.get("Set-Cookie") || "").includes("Max-Age=0"));

  console.log("ALL TESTS PASSED!");
}

runTests().catch((err) => {
  console.error("TEST FAILED:", err);
  process.exit(1);
});

import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { onRequest } from "../functions/api/[[path]].js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT_DIR = path.resolve(__dirname, "..");
const KV_FILE = path.join(ROOT_DIR, ".local-kv.json");

const PORT = Number(process.env.PORT || 8788);
const HOST = process.env.HOST || "0.0.0.0";

function createLocalKv(filePath) {
  let store = Object.create(null);
  if (fs.existsSync(filePath)) {
    try {
      const raw = fs.readFileSync(filePath, "utf8");
      const parsed = JSON.parse(raw);
      if (parsed && typeof parsed === "object") {
        store = Object.assign(Object.create(null), parsed);
      }
    } catch {
      store = Object.create(null);
    }
  }

  function persist() {
    const tmp = `${filePath}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(store, null, 2), "utf8");
    fs.renameSync(tmp, filePath);
  }

  return {
    async get(key, type = "text") {
      if (!Object.prototype.hasOwnProperty.call(store, key)) return null;
      const val = store[key];
      if (type === "json") return JSON.parse(val);
      return val;
    },
    async put(key, value) {
      store[key] = typeof value === "string" ? value : String(value);
      persist();
    },
    async delete(key) {
      delete store[key];
      persist();
    }
  };
}

const kv = createLocalKv(KV_FILE);

const STATIC_ROUTES = new Map([
  ["/", path.join(ROOT_DIR, "index.html")],
  ["/index.html", path.join(ROOT_DIR, "index.html")],
  ["/admin", path.join(ROOT_DIR, "admin", "index.html")],
  ["/admin/", path.join(ROOT_DIR, "admin", "index.html")],
  ["/admin/index.html", path.join(ROOT_DIR, "admin", "index.html")]
]);

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    const MAX_BODY = 64 * 1024;
    req.on("data", (chunk) => {
      total += chunk.length;
      if (total > MAX_BODY) {
        reject(new Error("Payload too large"));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

const server = http.createServer(async (req, res) => {
  try {
    const proto = String(req.headers["x-forwarded-proto"] || "http").split(",")[0].trim();
    const host = req.headers.host || `127.0.0.1:${PORT}`;
    const fullUrl = new URL(req.url || "/", `${proto}://${host}`);
    const pathname = fullUrl.pathname;

    if (pathname === "/api" || pathname.startsWith("/api/")) {
      const headers = new Headers();
      for (const [k, v] of Object.entries(req.headers)) {
        if (v === undefined) continue;
        if (Array.isArray(v)) {
          for (const item of v) headers.append(k, item);
        } else {
          headers.set(k, v);
        }
      }

      const method = (req.method || "GET").toUpperCase();
      let body;
      if (method !== "GET" && method !== "HEAD") {
        const buf = await readBody(req);
        if (buf.length > 0) body = buf;
      }

      const webReq = new Request(fullUrl.toString(), {
        method,
        headers,
        body
      });

      const env = {
        AHOORA_KV: kv,
        INITIAL_PANEL_PASSWORD: process.env.INITIAL_PANEL_PASSWORD || "",
        INITIAL_ADMIN_PASSWORD: process.env.INITIAL_ADMIN_PASSWORD || "",
        SESSION_SECRET: process.env.SESSION_SECRET || ""
      };

      const segments = pathname.replace(/^\/api\/?/, "").split("/").filter(Boolean);
      const webRes = await onRequest({
        request: webReq,
        env,
        params: { path: segments }
      });

      const outHeaders = {};
      for (const [k, v] of webRes.headers.entries()) {
        if (k.toLowerCase() === "set-cookie") continue;
        outHeaders[k] = v;
      }
      if (typeof webRes.headers.getSetCookie === "function") {
        const setCookies = webRes.headers.getSetCookie();
        if (setCookies.length > 0) outHeaders["Set-Cookie"] = setCookies;
      } else {
        const sc = webRes.headers.get("set-cookie");
        if (sc) outHeaders["Set-Cookie"] = sc;
      }

      res.writeHead(webRes.status, outHeaders);
      const resBuf = Buffer.from(await webRes.arrayBuffer());
      res.end(resBuf);
      return;
    }

    const staticFile = STATIC_ROUTES.get(pathname);
    if (staticFile && fs.existsSync(staticFile)) {
      const content = fs.readFileSync(staticFile);
      const headers = {
        "Content-Type": "text/html; charset=utf-8",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "same-origin"
      };
      if (pathname.startsWith("/admin")) {
        headers["Cache-Control"] = "no-store";
        headers["X-Robots-Tag"] = "noindex, nofollow";
      } else {
        headers["Cache-Control"] = "no-cache";
      }
      res.writeHead(200, headers);
      if ((req.method || "GET").toUpperCase() === "HEAD") {
        res.end();
      } else {
        res.end(content);
      }
      return;
    }

    res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
    res.end("Not Found");
  } catch (err) {
    console.error("[dev-server]", err);
    if (!res.headersSent) {
      res.writeHead(500, { "Content-Type": "application/json; charset=utf-8" });
      res.end(JSON.stringify({ ok: false, error: "خطای داخلی سرور" }));
    }
  }
});

server.listen(PORT, HOST, () => {
  console.log(`Ahoora dev server listening on http://${HOST}:${PORT}`);
  console.log(`  Main panel : http://127.0.0.1:${PORT}/`);
  console.log(`  Admin panel: http://127.0.0.1:${PORT}/admin`);
  console.log(`  Local KV   : ${KV_FILE}`);
});

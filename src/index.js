import { createPrivateKey, createPublicKey, sign, verify } from "crypto";

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type"
};

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: CORS });
    }

    // Serve landing page at root
    if (path === "/" || path === "/index.html") {
      return env.ASSETS.fetch(new Request(new URL("/index.html", request.url), request));
    }

    // Serve app at /app
    if (path === "/app" || path === "/app.html") {
      return env.ASSETS.fetch(new Request(new URL("/app.html", request.url), request));
    }

    // POST /sign
    if (path === "/sign" && request.method === "POST") {
      const body = await request.text();
      if (!body) return new Response("No content provided", { status: 400 });

      const contentHash = await hashContent(body);
      const privateKey = createPrivateKey(env.PRIVATE_KEY.replace(/\\n/g, "\n"));
      const signatureHex = sign(null, Buffer.from(contentHash), privateKey).toString("hex");
      const signingKeyId = await getKeyId(env.PUBLIC_KEY);
      const timestamp = new Date().toISOString();
      const version = "UTVN-0.2";
      const recordId = await hashContent(signatureHex + timestamp);

      await env.utvn_ledger.prepare(
        `INSERT INTO provenance_records
         (id, content_hash, signature, signing_key_id, timestamp, version, content)
         VALUES (?, ?, ?, ?, ?, ?, ?)`
      ).bind(recordId, contentHash, signatureHex, signingKeyId, timestamp, version, body).run();

      return new Response(JSON.stringify({
        id: recordId,
        content: body,
        contentHash,
        signature: signatureHex,
        publicKey: env.PUBLIC_KEY,
        signingKeyId,
        timestamp,
        version
      }, null, 2), {
        headers: { ...CORS, "Content-Type": "application/json" }
      });
    }

    // GET /verify/:id
    if (path.startsWith("/verify/") && request.method === "GET") {
      const id = path.split("/verify/")[1];
      const record = await env.utvn_ledger.prepare(
        `SELECT * FROM provenance_records WHERE id = ?`
      ).bind(id).first();

      if (!record) {
        return new Response(JSON.stringify({ verified: false, reason: "Record not found" }, null, 2), {
          status: 404,
          headers: { ...CORS, "Content-Type": "application/json" }
        });
      }

      const publicKey = createPublicKey(env.PUBLIC_KEY.replace(/\\n/g, "\n"));
      const isValid = verify(
        null,
        Buffer.from(record.content_hash),
        publicKey,
        Buffer.from(record.signature, "hex")
      );

      return new Response(JSON.stringify({
        verified: isValid,
        message: isValid
          ? "✓ Provenance verified — content is authentic and unaltered"
          : "✗ Verification failed — content may have been tampered with",
        record: {
          id: record.id,
          contentHash: record.content_hash,
          signature: record.signature,
          signingKeyId: record.signing_key_id,
          timestamp: record.timestamp,
          version: record.version,
          content: record.content
        }
      }, null, 2), {
        headers: { ...CORS, "Content-Type": "application/json" }
      });
    }

    // GET /ledger
    if (path === "/ledger" && request.method === "GET") {
      const records = await env.utvn_ledger.prepare(
        `SELECT id, content_hash, signing_key_id, timestamp, version, content
         FROM provenance_records
         ORDER BY timestamp DESC
         LIMIT 50`
      ).all();

      return new Response(JSON.stringify(records.results, null, 2), {
        headers: { ...CORS, "Content-Type": "application/json" }
      });
    }

    // Fall back to static assets
    return env.ASSETS.fetch(request);
  }
};

async function hashContent(content) {
  const data = new TextEncoder().encode(content);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  return bytesToHex(new Uint8Array(hashBuffer));
}

async function getKeyId(publicKey) {
  const data = new TextEncoder().encode(publicKey);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  return bytesToHex(new Uint8Array(hashBuffer)).slice(0, 16);
}

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}

import { createPrivateKey, createPublicKey, sign, verify } from "crypto";

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Access-Control-Max-Age": "86400"
};

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: CORS_HEADERS
      });
    }

    if (request.method === "POST" && url.pathname === "/sign") {
      return handleSign(request, env);
    }

    if (request.method === "GET" && url.pathname.startsWith("/verify/")) {
      const id = url.pathname.split("/verify/")[1];
      return handleVerify(id, env);
    }

    if (request.method === "GET" && url.pathname === "/ledger") {
      return handleLedger(env);
    }

    if (request.method === "GET" && url.pathname === "/") {
      return new Response(getHTMLPage(), {
        headers: { "Content-Type": "text/html; charset=utf-8" }
      });
    }

    return new Response("Not found", { status: 404 });
  }
};

async function handleSign(request, env) {
  const body = await request.text();
  if (!body) {
    return new Response("No content provided", { status: 400 });
  }

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
    headers: { ...CORS_HEADERS, "Content-Type": "application/json" }
  });
}

async function handleVerify(id, env) {
  const record = await env.utvn_ledger.prepare(
    `SELECT * FROM provenance_records WHERE id = ?`
  ).bind(id).first();

  if (!record) {
    return new Response(JSON.stringify({
      verified: false,
      reason: "Record not found"
    }, null, 2), {
      status: 404,
      headers: { ...CORS_HEADERS, "Content-Type": "application/json" }
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
    headers: { ...CORS_HEADERS, "Content-Type": "application/json" }
  });
}

async function handleLedger(env) {
  const records = await env.utvn_ledger.prepare(
    `SELECT id, content_hash, signing_key_id, timestamp, version, content
     FROM provenance_records
     ORDER BY timestamp DESC
     LIMIT 50`
  ).all();

  return new Response(JSON.stringify(records.results, null, 2), {
    headers: { ...CORS_HEADERS, "Content-Type": "application/json" }
  });
}

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

function getHTMLPage() {
  return `<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>UTVN Provenance Engine</title>
    <style>
      :root {
        --bg: #0b0f19;
        --panel: #151c2c;
        --accent: #3b82f6;
        --accent-hover: #2563eb;
        --text: #f3f4f6;
        --text-muted: #9ca3af;
        --success: #10b981;
        --error: #ef4444;
        --border: #1e293b;
      }
      body {
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        background: var(--bg);
        color: var(--text);
        margin: 0;
        padding: 20px;
        display: flex;
        justify-content: center;
      }
      .container {
        width: 100%;
        max-width: 800px;
      }
      header {
        text-align: center;
        margin-bottom: 2rem;
        border-bottom: 1px solid var(--border);
        padding-bottom: 1.5rem;
      }
      h1 {
        margin: 0 0 0.5rem 0;
        font-size: 1.8rem;
        letter-spacing: -0.025em;
      }
      .subtitle {
        color: var(--text-muted);
        margin: 0 0 1rem 0;
        font-size: 0.95rem;
      }
      .badge {
        display: inline-block;
        background: rgba(16, 185, 129, 0.1);
        color: var(--success);
        padding: 4px 12px;
        border-radius: 9999px;
        font-size: 0.75rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        border: 1px solid rgba(16, 185, 129, 0.2);
      }
      .panel {
        background: var(--panel);
        border: 1px solid var(--border);
        border-radius: 12px;
        padding: 1.5rem;
        margin-bottom: 1.5rem;
      }
      h2 {
        font-size: 1.2rem;
        margin-top: 0;
        margin-bottom: 0.5rem;
        display: flex;
        align-items: center;
        gap: 8px;
      }
      .step-num {
        background: var(--accent);
        color: white;
        width: 20px;
        height: 20px;
        border-radius: 50%;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        font-size: 0.75rem;
        font-weight: bold;
      }
      p.desc {
        color: var(--text-muted);
        font-size: 0.9rem;
        margin: 0 0 1rem 0;
      }
      textarea, input {
        width: 100%;
        box-sizing: border-box;
        background: #0d131f;
        border: 1px solid var(--border);
        border-radius: 6px;
        color: var(--text);
        padding: 10px 12px;
        font-family: inherit;
        font-size: 0.95rem;
        margin-bottom: 1rem;
      }
      textarea {
        resize: vertical;
        min-height: 80px;
      }
      button {
        background: var(--accent);
        color: white;
        border: none;
        padding: 10px 20px;
        border-radius: 6px;
        font-weight: 600;
        cursor: pointer;
        width: 100%;
        transition: background 0.15s;
      }
      button:hover {
        background: var(--accent-hover);
      }
      pre {
        background: #0d131f;
        border: 1px solid var(--border);
        padding: 1rem;
        border-radius: 6px;
        overflow-x: auto;
        font-family: monospace;
        font-size: 0.85rem;
        display: none;
        margin-top: 1rem;
      }
      .success-msg { color: var(--success); }
      .error-msg { color: var(--error); }
    </style>
  </head>
  <body>
    <div class="container">
      <header>
        <h1>UTVN Provenance Engine</h1>
        <p class="subtitle">Layer 1 Cryptographic Signer &amp; Layer 2 Auditing Ledger</p>
        <span class="badge">Ed25519 Active</span>
      </header>

      <section class="panel">
        <h2><span class="step-num">1</span> Issue Content Provenance</h2>
        <p class="desc">Input official statements, media logs, or disclosures to generate an immutable origin stamp.</p>
        <textarea id="signInput" placeholder="Paste official text or asset metadata here..."></textarea>
        <button onclick="signContent()">Cryptographically Sign Asset</button>
        <pre id="signResult"></pre>
      </section>

      <section class="panel">
        <h2><span class="step-num">2</span> Independent Verification Audit</h2>
        <p class="desc">Query the ledger directly using a unique tracking ID to confirm ownership and track file integrity.</p>
        <input id="verifyInput" placeholder="Enter Provenance Transaction ID..." />
        <button onclick="verifyContent()">Run Cryptographic Audit</button>
        <pre id="verifyResult"></pre>
      </section>
    </div>

    <script>
      async function signContent() {
        const content = document.getElementById('signInput').value;
        const resultBox = document.getElementById('signResult');
        if (!content.trim()) return alert('Please enter some content to sign.');

        resultBox.style.display = 'block';
        resultBox.textContent = 'Signing...';

        try {
          const res = await fetch('http://127.0.0.1:8787/sign', {
            method: 'POST',
            headers: { 'Content-Type': 'text/plain' },
            body: content
          });
          const data = await res.json();
          resultBox.innerHTML = '✓ Record successfully signed and committed!\n\n' + JSON.stringify(data, null, 2);
        } catch (err) {
          resultBox.innerHTML = '✗ Signing failed\n' + err.message;
        }
      }

      async function verifyContent() {
        const id = document.getElementById('verifyInput').value.trim();
        const resultBox = document.getElementById('verifyResult');
        if (!id) return alert('Please enter a ledger ID to verify.');

        resultBox.style.display = 'block';
        resultBox.textContent = 'Querying ledger and verifying cryptographic signatures...';

        try {
          const res = await fetch('http://127.0.0.1:8787/verify/' + id);
          const data = await res.json();
          if (data.verified) {
            resultBox.innerHTML = '✓ ' + data.message + '\n\n' + JSON.stringify(data.record, null, 2);
          } else {
            resultBox.innerHTML = '✗ Verification failed: ' + (data.reason || 'Hash mismatch');
          }
        } catch (err) {
          resultBox.innerHTML = '✗ Verification failed\n' + err.message;
        }
      }
    </script>
  </body>
</html>`;
}

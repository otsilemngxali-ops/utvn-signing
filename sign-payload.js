// sign-payload.js
const crypto = require('crypto');

// 1. Paste your raw private key hex string here locally
const PRIVATE_KEY_HEX = "d624550d033d4904e7b98f1ad6ed83ceaea57f92ca61a8cbd78940ff42d89e408"; 

// 2. Define the structured payload object matching your data schema
const payloadObject = {
  vector_id: "VEC-2026-004",
  asset_class: "Sovereign Infrastructure",
  allocation_units: 1500000.00,
  currency: "USD",
  recipient_identifier: "UTVN-TREASURY-01",
  purpose_manifesto: "Fourth Sovereign Wealth Inflow Distribution Allocation Vector"
};

async function generateSignedPayload() {
  const timestamp = new Date().toISOString();
  
  // Fetch the current tip of the chain from your live verify route to link them
  const response = await fetch("https://utvn-signing.utvn-signing.workers.dev/ledger/verify");
  const status = await response.json();
  const previousHash = status.last_confirmed_state || "00000000000000000000000000000000";

  // Enforce strict local validation before signing
  const requiredKeys = ['vector_id', 'asset_class', 'allocation_units', 'currency', 'recipient_identifier'];
  for (const key of requiredKeys) {
    if (payloadObject[key] === undefined) {
      throw new Error(`Local Schema Validation Error: Missing required key "${key}"`);
    }
  }

  // Convert object to a single, deterministic string for the signature message
  const payloadStr = JSON.stringify(payloadObject);

  // Reconstruct structural message layout string
  const messageStr = `${timestamp}|${payloadStr}|${previousHash}`;
  const messageBytes = Buffer.from(messageStr);

  // 1. Convert your 32-byte raw hex private key to a Buffer
  const rawPrivateBytes = Buffer.from(PRIVATE_KEY_HEX, 'hex');

  // 2. Prepend the standard 16-byte PKCS#8 ASN.1 header for Ed25519 private keys
  const pkcs8Header = Buffer.from([
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
    0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20
  ]);

  // Combine them to form a valid PKCS#8 DER object
  const fullPkcs8Buffer = Buffer.concat([pkcs8Header, rawPrivateBytes]);

  // 3. Import it seamlessly into Node
  const signingKey = crypto.createPrivateKey({
    key: fullPkcs8Buffer,
    format: 'der',
    type: 'pkcs8'
  });

  // 4. Sign the message bytes
  const signatureBuffer = crypto.sign(null, messageBytes, signingKey);
  const signatureHex = signatureBuffer.toString('hex');

  // Print out the exact JSON object needed by the updated server
  console.log("\n🚀 COPY THIS JSON ENTRY FOR YOUR CURL REQUEST:\n");
  console.log(JSON.stringify({
    timestamp,
    payload: payloadStr, // Pass the stringified JSON object as the payload string
    previous_hash: previousHash,
    signature: signatureHex
  }, null, 2));
}

generateSignedPayload().catch(console.error);

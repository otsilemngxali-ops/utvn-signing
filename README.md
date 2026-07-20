# UTVN — Universal Truth Verification Network

Cryptographic content provenance infrastructure for the AI era.

## What It Does

UTVN shifts the question from "is this true?" to "where did this originate and has it been altered?"

Any piece of content — a news article, an official statement, a court document — can be signed cryptographically at the point of creation. The signature travels with the content permanently. Anyone can verify it later.

## Live Demo

🔗 https://utvn-signing.utvn-signing.workers.dev

## How It Works

- **POST /sign** — Submit any content and receive a cryptographic provenance record
- **GET /verify/:id** — Verify any record by ID, confirming authenticity and integrity
- **GET /ledger** — View all signed records publicly

## Tech Stack

- Ed25519 asymmetric cryptography
- SHA-256 content hashing
- Cloudflare Workers (edge runtime)
- Cloudflare D1 (immutable distributed ledger)

## Architecture

UTVN is designed as four-layer infrastructure:

1. **Layer 1 — Open Protocol** — cryptographic signing standard, open and auditable
2. **Layer 2 — Independent Foundation** — governance and credibility scoring
3. **Layer 3 — Market Ecosystem** — tools and products built on the protocol
4. **Layer 4 — Government Integration** — institutional adoption without control

## Background

Built by Otsile Mngxali, independent researcher based in South Africa.

Contact: otsilemngxali@gmail.com

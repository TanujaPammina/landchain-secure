# LandChain Secure

**Blockchain-Based Land Registry System with Cryptographic Security**

> PKI digital identity · AES-256-GCM encryption · Multi-signature transfers · SHA-256 blockchain · TOTP MFA

---

## Live Demo

**https://landchain-secure.onrender.com**

---

## Quick Start (Run Locally)

```bash
# No npm install needed — zero external dependencies
node server.js
```

Open **http://localhost:3000**

The registrar setup code prints in the terminal on first run.

> Requires Node.js 18+

---

## How to Use

| Step | Who | What |
|------|-----|------|
| 1 | Land Inspector | Register with setup code from server log |
| 2 | Seller | Register → Inspector approves KYC |
| 3 | Buyer | Register → Inspector approves KYC |
| 4 | Seller | List land with encrypted documents |
| 5 | Land Inspector | Verify the listed land |
| 6 | Buyer | Request to buy from marketplace |
| 7 | Seller | Approve request + share document key |
| 8 | Buyer | Decrypt documents → Pay (simulated) |
| 9 | All 3 | Sign transfer (multi-signature) |
| 10 | Land Inspector | Commit transfer to blockchain |
| 11 | Anyone | Audit blockchain — all blocks verified |

---

## Roles

| Role | Permissions |
|------|-------------|
| **Land Inspector** | Approve/reject users, verify lands, sign transfers, commit to blockchain |
| **Seller** | List lands, approve buyer requests, sign ownership transfers |
| **Buyer** | Browse marketplace, request purchase, decrypt documents, pay, sign transfer |

---

## Security Features

| Feature | Implementation |
|---------|---------------|
| AES-256-GCM | KYC and documents encrypted in browser — server never sees plaintext |
| PKI Certificates | ECDSA P-256 — Government CA issues certificates to all verified users |
| Multi-Signature | 3-of-3 approval required — Buyer + Seller + Inspector must all sign |
| TOTP MFA | 6-digit code from Google/Microsoft Authenticator required at every login |
| SHA-256 Blockchain | Tamper-evident hash chain with Merkle roots and BFT 3-of-4 consensus |
| scrypt Hashing | Password hashed with N=16384 — brute-force resistant |
| RBAC | Role-based access control enforced on every API call |
| Rate Limiting | Account locks after 5 failed login attempts |

---

## Project Structure

```
landchain-app/
├── server.js          # Main server — API, blockchain, PKI CA
├── lib/
│   ├── auth.js        # scrypt password hashing + TOTP
│   └── chain.js       # SHA-256 blockchain, BFT consensus, Merkle tree, audit
├── public/
│   ├── index.html     # Single page app entry point
│   ├── css/style.css  # Styles
│   └── js/
│       ├── crypto.js  # Browser crypto — AES-256-GCM, ECDSA, RSA-OAEP, TOTP
│       ├── client.js  # API client, wallet management, transaction signing
│       └── app.js     # UI — role-based dashboards, blockchain explorer
├── package.json       # Node config — start: node server.js
└── render.yaml        # Render.com deployment config
```

---

## Deploy on Render (Free)

### 1. Push to GitHub
```bash
git init
git add .
git commit -m "initial commit"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/landchain-secure.git
git push -u origin main
```

### 2. Create Web Service on Render
- Go to [render.com](https://render.com) → New → Web Service
- Connect your GitHub repo
- `render.yaml` is auto-detected — no manual config needed

### 3. Add Persistent Disk
- Render Service → Disks → Add Disk
- Name: `landchain-data`, Mount path: `/var/data`, Size: `1 GB`

### 4. Environment Variables (optional)
| Key | Value |
|-----|-------|
| `NODE_ENV` | `production` |
| `DATA_DIR` | `/var/data` |
| `INSPECTOR_CODE` | `your-chosen-setup-code` |

### 5. Get Setup Code
After deploy → **Logs** tab → look for:
```
Registrar setup code: xxxxxxxxxxxxxxxx
```
Use this code when registering as Land Inspector.

---

## Tech Stack

- **Backend** — Node.js (zero npm dependencies, built-in modules only)
- **Frontend** — Vanilla JS + React-style rendering (no build step)
- **Crypto** — Browser WebCrypto API + Node.js `crypto` module
- **Blockchain** — Custom SHA-256 hash chain with BFT 3-of-4 consensus
- **Storage** — JSON file on persistent disk (swap to PostgreSQL for production)
- **Hosting** — Render.com free tier

---

## GitHub

[github.com/TanujaPammina/landchain-secure](https://github.com/TanujaPammina/landchain-secure)

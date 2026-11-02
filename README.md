# LandChain Secure

Blockchain-based land registry system with cryptographic security.
PKI digital identity, AES-256-GCM encryption, multi-signature transfers, SHA-256 blockchain.

---

## Run Locally

1. Install Node.js 18+ from https://nodejs.org
2. Open terminal in this folder
3. Run: `node server.js`
4. Open: http://localhost:3000

The registrar setup code is printed in the terminal on first run.

---

## Deploy to Render (Free)

### Step 1 — Push to GitHub
1. Create a new repo on https://github.com (make it public or private)
2. Open terminal in the `landchain-app` folder and run:

```
git init
git add .
git commit -m "first commit"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPO.git
git push -u origin main
```

### Step 2 — Create a Render account
- Go to https://render.com and sign up (free)
- Connect your GitHub account

### Step 3 — Create a new Web Service
- Click **New** → **Web Service**
- Select your GitHub repo
- Render will auto-detect `render.yaml`

If it does not auto-detect, set manually:
- **Build Command:** `echo done`
- **Start Command:** `node server.js`
- **Environment:** Node

### Step 4 — Add a Disk (important — keeps data between restarts)
- In your Render service → **Disks** tab
- Add disk:
  - Name: `landchain-data`
  - Mount path: `/var/data`
  - Size: 1 GB (free tier)

### Step 5 — Set Environment Variables
In Render service → **Environment** tab, add:

| Key | Value |
|-----|-------|
| `NODE_ENV` | `production` |
| `DATA_DIR` | `/var/data` |
| `INSPECTOR_CODE` | (any secret code you choose, e.g. `myinspector123`) |

### Step 6 — Deploy
- Click **Deploy**
- Wait ~2 minutes
- Your app will be live at: `https://landchain-secure.onrender.com` (or similar)

### Step 7 — Get the registrar setup code
- In Render → **Logs** tab
- Look for: `Registrar setup code: xxxxxxxx`
- OR use the `INSPECTOR_CODE` env variable you set — that becomes the code

---

## How It Works

| Role | What they do |
|------|-------------|
| Land Inspector | Government registrar — approves users, verifies lands, commits transfers |
| Seller | Registers land, approves buyer requests, signs transfers |
| Buyer | Browses marketplace, requests to buy, pays, signs transfers |

### Full flow
1. Inspector registers first (needs setup code from server log)
2. Seller registers → Inspector approves KYC
3. Buyer registers → Inspector approves KYC
4. Seller lists land with documents (encrypted in browser)
5. Inspector verifies the land
6. Buyer requests to buy
7. Seller approves and shares document key with buyer
8. Buyer reviews documents and pays
9. All 3 sign the transfer (multi-signature)
10. Inspector commits transfer to blockchain
11. Ownership permanently recorded — auditable by anyone

---

## Security Features

- AES-256-GCM: KYC and documents encrypted in browser before upload
- PKI: ECDSA P-256 digital identity, CA-issued certificates
- Multi-signature: 3-of-3 approval for every ownership transfer
- TOTP MFA: 6-digit authenticator code required at every login
- SHA-256 blockchain: tamper-evident hash chain with Merkle roots
- RBAC: role-based access control enforced on every API call
- scrypt password hashing + account lockout after 5 failed attempts

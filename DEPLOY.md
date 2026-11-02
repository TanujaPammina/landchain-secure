# Deployment

The app is one Node.js process with a data folder (`DATA_DIR`: blockchain, encrypted files, CA key). HTTPS is **required**
(browsers only allow encryption APIs on HTTPS or localhost) – all hosts below provide it automatically.

## Option 1 – Render (easiest)
1. Push this folder to a GitHub repo.  2. Render → New → Blueprint → select the repo (`render.yaml` is included).
3. After deploy, open the service logs (or the INSPECTOR_CODE env var) to get the registrar setup code.
Note: the persistent disk (so data survives restarts) needs a paid instance.

## Option 2 – Docker (any VPS / cloud)
```
docker build -t landchain .
docker run -d -p 3000:3000 -v landchain-data:/data -e INSPECTOR_CODE=your-long-secret --name landchain landchain
```
Put it behind HTTPS (Caddy / Nginx / a cloud load balancer). Behind a proxy it reads `X-Forwarded-For`.

## Option 3 – Plain Node
`NODE_ENV=production DATA_DIR=/var/lib/landchain INSPECTOR_CODE=... node server.js`

## Before real-world use (honest limits of this project version)
- The 4 validators run in one process; real deployment would run them on separate machines.
- The CA private key is a file in DATA_DIR (use an HSM/KMS); back up DATA_DIR (it holds the chain).
- JSON-file storage: fine for a project/demo; use PostgreSQL for scale.
- Payment is simulated. Lost key backups cannot be recovered (by design: the server never has private keys).

# LandChain Secure – Feature list (and the security measure at every step)

Based on the base project (vrii14/Land-Registration-with-Blockchain: Seller / Buyer / Land Inspector,
add land, request, approve, pay, transfer) + the proposed cryptographic layer from the review deck
(PKI digital identity, AES-256 encryption, multi-signature approval, RBAC, MFA, on-chain hash + off-chain data).

Simplification vs the GitHub project: no Ethereum, Ganache, Truffle, MetaMask or IPFS. The blockchain is built
into the server (SHA-256 hash chain + Merkle roots + PoS proposer + BFT 3-of-4 voting by 4 validator nodes),
and documents are stored off-chain as ciphertext in the server's data folder.

| # | Feature | Who | Security applied at this step |
|---|---------|-----|-------------------------------|
| 1 | Registration (name, role, KYC: Aadhaar/PAN/phone/address) | Seller, Buyer | Password hashed with scrypt; KYC encrypted in the browser with AES-256-GCM and the key wrapped (RSA-OAEP) only for the user + registrar; browser generates the user's key pairs (ECDSA + RSA); private keys never leave the browser; registration is a signed blockchain transaction |
| 2 | MFA enrolment | All | TOTP secret (RFC 6238) shown once; works with Google/Microsoft Authenticator |
| 3 | Login | All | Password + TOTP code; rate limiting + temporary lockout; HttpOnly SameSite cookie |
| 4 | Registrar (Land Inspector) setup | Inspector | Registrar account needs a secret setup code (env var); only one registrar |
| 5 | Verify users (KYC review) | Inspector | Registrar decrypts KYC (only he holds a key), signs approval; Government CA issues an X.509-style certificate (PKI digital identity) |
| 6 | Add land + upload documents | Seller | Files encrypted in the browser (AES-256-GCM) BEFORE upload; server stores ciphertext only; on-chain: hash (CID) + wrapped keys; only metadata is public |
| 7 | Verify land | Inspector | Decrypts documents (MFA session), signs verification |
| 8 | Marketplace | Everyone | Public: area, place, price, status. Documents/KYC unreadable without a wrapped key |
| 9 | Request to buy | Buyer | Signed transaction (non-repudiation); RBAC |
| 10 | Approve request + share documents | Seller | Seller's browser re-wraps the AES key for that buyer; access exists only after owner consent; signed |
| 11 | Decrypt & view documents | Buyer | Decryption happens locally with the buyer's private key |
| 12 | Payment (simulated) | Buyer | Signed transaction; amount must equal price |
| 13 | Ownership transfer | Seller+Buyer+Inspector | 3-of-3 multi-signature; validators check all signatures, so no single official can move a title |
| 14 | My lands / history of a land | Owners | Provenance read from the chain |
| 15 | Blockchain explorer + audit | Everyone | Recomputes hashes, Merkle roots, links and every signature |
| 16 | Platform hardening | – | RBAC enforced on server, signature on every action, replay protection (nonce + time window), CSP & security headers, input validation, size limits |
| 17 | Deployment | – | Dockerfile, render.yaml, env-based secrets, persistent data folder |

Status: features 1–17 are implemented and covered by `npm test` (39 checks) plus a browser run through the full flow.

Not included (out of scope for the project, listed in the slides as future work): mortgage, tax, inheritance contracts;
real payment gateway; real distributed validator nodes (4 nodes run inside the one server process);
profile editing.

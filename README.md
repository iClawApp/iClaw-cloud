# iClaw cloud

Companion **cloud share** server for [iClaw](https://github.com/tmlxrd/iClaw). Lets you publish a chat as an end-to-end encrypted link with a TTL: receivers open the URL in any browser and the chat decrypts client-side.

The server stores **ciphertext only**. Keys live in the URL fragment (`#k=…`) and never reach the server. Optional password protection wraps the key with a PBKDF2-derived key so even the URL alone isn't enough.

## How it works

```
iClaw (your browser)                 iClaw-cloud (this server)              Recipient (any browser)
────────────────────                 ─────────────────────────              ──────────────────────────
Chat → gzip → AES-256-GCM  ──upload──▶  store ciphertext + TTL
                                                                     ◀──── GET /s/<id> + frag key #k=…
                                       fetch /api/shares/<id>  ────▶
                                                                          decrypt + render in browser
```

Key generation, encryption, and decryption all happen in the browser via the WebCrypto API. The server is a thin Express + Mongoose app that:

- accepts POSTed ciphertext blobs with metadata (TTL, optional `wrappedKey` + `salt` if password-protected, optional `maxViews` for burn-after-read);
- returns a short share id and public URL;
- serves the **viewer page** at `/s/<id>` (static HTML + JS that does the decryption);
- auto-deletes expired shares via MongoDB's TTL index.

## Run it

Requirements: Node.js 20+, MongoDB (or `docker compose up -d`).

```bash
git clone https://github.com/tmlxrd/iClaw-cloud.git
cd iClaw-cloud
cp .env.example .env       # tweak BASE_URL + MONGO_URL if needed
npm install
docker compose up -d       # local Mongo on :27017
npm run dev                # http://localhost:4000
```

For production: set `NODE_ENV=production`, point `MONGO_URL` at a managed cluster (Atlas free tier is enough), set `BASE_URL=https://app.iclaw.digital`, allow `https://iclaw.digital,https://www.iclaw.digital,https://app.iclaw.digital` in `ALLOWED_ORIGINS`, and enable `TRUST_PROXY=true` behind a reverse proxy. Optional `ICLAW_APP_URL` overrides the **Built by iClaw** link target in the share viewer (defaults to `https://app.iclaw.digital`).

## Endpoints

| Method | Path | What |
|---|---|---|
| `POST` | `/api/shares` | Upload encrypted blob → `{id, url, expiresAt}` |
| `GET`  | `/api/shares/:id` | Fetch ciphertext + metadata. Increments view counter; deletes the doc if `maxViews` reached |
| `GET`  | `/s/:id` | Static viewer page — decrypts in browser |
| `GET`  | `/healthz` | Liveness probe |

### POST body shape

```jsonc
{
  "ciphertext": "<base64>",
  "nonce":      "<base64>",       // 12 bytes
  "salt":       "<base64> | null",   // only when hasPassword
  "wrappedKey": "<base64> | null",   // only when hasPassword
  "hasPassword": false,
  "ttlDays":    7,                // bounded by TTL_MIN_DAYS / TTL_MAX_DAYS
  "maxViews":   null              // null = unlimited, 1 = burn-after-read
}
```

### GET response shape

Same fields back, plus `viewCount` and `expiresAt`.

## Crypto contract (what iClaw must do)

For a share **without password**:

```js
const key = crypto.getRandomValues(new Uint8Array(32));   // 256 bits
const nonce = crypto.getRandomValues(new Uint8Array(12)); // 96 bits
const ciphertext = await crypto.subtle.encrypt(
  { name: 'AES-GCM', iv: nonce },
  await crypto.subtle.importKey('raw', key, 'AES-GCM', false, ['encrypt']),
  gzipped_payload_bytes,
);
// POST { ciphertext, nonce, hasPassword: false, ttlDays, … }
// URL: https://app.iclaw.digital/s/<id>#k=<base64url(key)>
```

For a share **with password**:

```js
const realKey = crypto.getRandomValues(new Uint8Array(32));
const nonce   = crypto.getRandomValues(new Uint8Array(12));
const ciphertext = encryptWith(realKey, nonce, payload);

// Wrap the real key with a PBKDF2-derived key.
const salt = crypto.getRandomValues(new Uint8Array(16));
const wrapKey = await deriveAesKeyFromPassword(password, salt, 200_000);
const wrapNonce = crypto.getRandomValues(new Uint8Array(12));
const wrappedCt = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: wrapNonce }, wrapKey, realKey);
const wrappedKey = concat(wrapNonce, new Uint8Array(wrappedCt));   // 12B nonce || 32B ciphertext + 16B tag

// POST { ciphertext, nonce, salt, wrappedKey, hasPassword: true, ttlDays, … }
// URL: https://app.iclaw.digital/s/<id>   (no fragment — the recipient enters the password)
```

The viewer page (`public/viewer.js`) implements the matching decrypt path.

## Configuration

All knobs live in `src/config.ts` and are validated via Zod at boot. Read `.env.example` for the full list. The two values you'll always set:

- `MONGO_URL`
- `BASE_URL` — the public origin of this server, used to build returned share URLs.

## Operational notes

- **Storage costs** are bounded by `MAX_PAYLOAD_BYTES × max active shares`. With defaults (5 MiB × ~thousands of shares), an Atlas free-tier cluster fits comfortably.
- **Abuse**: the server never sees plaintext, but it hosts the encrypted bytes. We log `id`, `creatorIpHash`, `size`, and timestamps for DMCA / abuse responses; no IPs in plaintext, no message bodies, ever.
- **Rate limits** are per-IP for both create and read. Tune `RATE_LIMIT_PER_IP_HOUR` + `READ_RATE_LIMIT_PER_IP_MINUTE` to match your traffic.
- **TTL bounds**: `TTL_MIN_DAYS=1` prevents accidental "permanent" 0-day shares; `TTL_MAX_DAYS=30` caps storage cost. Mongo's TTL index deletes the doc within ~60 seconds of `expiresAt`.

## License

MIT — see `LICENSE`. Same license as iClaw and OpenClaw.

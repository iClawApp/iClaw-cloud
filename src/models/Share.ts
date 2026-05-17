/**
 * One encrypted share.
 *
 * The server stores ciphertext + the metadata needed to decrypt — but NEVER
 * the symmetric key itself. The key lives in the URL fragment (`#k=...`) and,
 * optionally, behind a password (a `wrappedKey` + `salt` is stored so the
 * client can derive the unwrap-key from the password and unlock the real key).
 *
 * Auto-expiry is handled by a MongoDB TTL index on `expiresAt` — Mongo runs a
 * background sweeper every 60s and deletes documents whose `expiresAt` is
 * older than `now`. View-based expiry (`maxViews`) is handled inline in the
 * read handler.
 */

import { Schema, model, type InferSchemaType, type Model } from 'mongoose';
import { randomBytes } from 'node:crypto';

/* ---------------------------------------------------------------- shape -- */

const ShareSchema = new Schema(
  {
    /**
     * Short URL-safe id (12 base64url chars ≈ 72 bits of entropy). Enough to
     * make guessing infeasible even at high write rates. Generated server-side.
     */
    _id: {
      type: String,
      required: true,
      default: () => generateShareId(),
    },

    /** Encrypted chat payload (AES-256-GCM ciphertext + auth tag, gzipped first). */
    ciphertext: { type: Buffer, required: true },

    /** AES-GCM nonce (96 bits). Random per share. */
    nonce: { type: Buffer, required: true },

    /** Random salt (16 bytes) for password key derivation. Null if no password. */
    salt: { type: Buffer, default: null },

    /**
     * If the share is password-protected, the real symmetric key is wrapped
     * (encrypted) with a key derived from the password via PBKDF2/Argon2id,
     * and stored here. The fragment key in the URL is NOT used in that case.
     */
    wrappedKey: { type: Buffer, default: null },

    /** Cached for client UI; redundant with (salt && wrappedKey) being set. */
    hasPassword: { type: Boolean, required: true, default: false },

    /**
     * Hash of the random `deleteToken` we hand back to the creator. We never
     * store the token itself, only its sha256 — matching against incoming
     * DELETE auth headers.
     */
    deleteTokenHash: { type: String, required: true },

    /** How many times the blob has been fetched via GET. */
    viewCount: { type: Number, required: true, default: 0 },

    /**
     * If set, the share auto-deletes after this many views (typical: 1 for
     * burn-after-read). Null = unlimited until TTL.
     */
    maxViews: { type: Number, default: null },

    /** Mongo TTL index on this field — defined via schema.index() below
        (not inline) so we don't end up with a duplicate index. */
    expiresAt: { type: Date, required: true },

    /** Size of the encrypted payload in bytes. Cheap to compute, useful for stats/abuse. */
    size: { type: Number, required: true },

    /** SHA-256 of the creator IP — kept ONLY for abuse responses, not user-visible. */
    creatorIpHash: { type: String, default: null },
  },
  {
    // We assign _id manually, so disable Mongo's default ObjectId.
    _id: false,
    timestamps: { createdAt: true, updatedAt: false },
    versionKey: false,
    minimize: false,
  },
);

// MongoDB native TTL — checked once a minute by the background reaper.
// `expireAfterSeconds: 0` means "delete when `expiresAt` is in the past".
ShareSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

export type ShareDoc = InferSchemaType<typeof ShareSchema> & { _id: string };
export const Share: Model<ShareDoc> = model<ShareDoc>('Share', ShareSchema);

/* ----------------------------------------------------- id generator ------ */

const ID_LEN_BYTES = 9; // 9 bytes → 12 base64url chars; ~72 bits of entropy

/** Base64-URL alphabet (RFC 4648 §5) without padding. */
function generateShareId(): string {
  return randomBytes(ID_LEN_BYTES)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

export const _testing = { generateShareId };

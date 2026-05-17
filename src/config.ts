/**
 * Centralised, validated configuration.
 *
 * `config.ts` is the ONLY place that reads `process.env`. Every other module
 * imports values from `config`, so we get:
 *   - a single point of validation (fail-fast on missing/invalid env at boot)
 *   - strict typing (no `string | undefined` leaking through the codebase)
 *   - one obvious place to document each knob
 *
 * `dotenv` is loaded here too, so importing this module anywhere automatically
 * sets up the environment.
 */

import 'dotenv/config';
import { z } from 'zod';

/* ---------------------------------------------------------------- schema -- */

const RawConfigSchema = z.object({
  /** Node lifecycle mode. Production tightens CORS + disables verbose errors. */
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),

  /** HTTP port. */
  PORT: z.coerce.number().int().positive().default(4000),

  /** Mongo connection string. Required — server can't run without storage. */
  MONGO_URL: z.string().min(1, 'MONGO_URL is required'),

  /** Mongo database name (e.g. "iclaw_cloud"). */
  MONGO_DB_NAME: z.string().min(1).default('iclaw_cloud'),

  /**
   * Public origin of THIS server (e.g. https://app.iclaw.digital). Used to
   * build the share URL we return to clients.
   */
  BASE_URL: z.string().url().default('http://localhost:4000'),

  /**
   * Main iClaw web app URL for the "Built by iClaw" link in the share viewer.
   * Defaults to https://app.iclaw.digital when unset or empty.
   */
  ICLAW_APP_URL: z.string().optional(),

  /**
   * Comma-separated list of origins allowed to POST encrypted blobs to
   * /api/shares. The viewer page (served by us) and the iClaw web app
   * itself are the typical entries.
   *
   * Special value "*" allows any origin — convenient for dev, never use in
   * production.
   */
  ALLOWED_ORIGINS: z
    .string()
    .default('http://localhost:3000,http://localhost:4000'),

  /**
   * Max ciphertext payload size in BYTES. Ciphertext includes the encrypted
   * chat plus the AES-GCM auth tag; 5 MiB is generous for typical chats.
   * Don't raise this without a rate-limit + storage-cost review.
   */
  MAX_PAYLOAD_BYTES: z.coerce.number().int().positive().default(5 * 1024 * 1024),

  /** Per-IP create-share rate limit (requests per hour). */
  RATE_LIMIT_PER_IP_HOUR: z.coerce.number().int().positive().default(20),

  /** Per-IP read-share rate limit (requests per minute). */
  READ_RATE_LIMIT_PER_IP_MINUTE: z.coerce.number().int().positive().default(60),

  /**
   * Allowed TTL bounds (in days). The client picks within these.
   * Lower bound: prevents instant-burn shares from being "permanent" by
   * accident. Upper bound: caps storage cost.
   */
  TTL_MIN_DAYS: z.coerce.number().int().positive().default(1),
  TTL_MAX_DAYS: z.coerce.number().int().positive().default(30),

  /**
   * If true, log create/read events (id, size, ttl, view counts) — useful for
   * abuse responses. Off by default to keep local logs readable; enable in
   * production when you need an audit trail. We NEVER log ciphertext.
   */
  LOG_ACCESS: z
    .string()
    .transform((v) => v === 'true' || v === '1')
    .default('false'),

  /**
   * Trust upstream proxy headers (X-Forwarded-For). Set to "1" when behind
   * Cloudflare / nginx so rate-limiting keys off the real client IP, not the
   * proxy.
   */
  TRUST_PROXY: z
    .string()
    .transform((v) => v === 'true' || v === '1')
    .default('false'),
}).superRefine((data, ctx) => {
  const t = (data.ICLAW_APP_URL ?? '').trim();
  if (!t) return;
  try {
    new URL(t);
  } catch {
    ctx.addIssue({
      code: 'custom',
      path: ['ICLAW_APP_URL'],
      message: 'must be a valid absolute URL',
    });
  }
});

/* ---------------------------------------------------------------- parse -- */

const parsed = RawConfigSchema.safeParse(process.env);

if (!parsed.success) {
  // Print every failed field on its own line so the operator sees what to fix.
  console.error('[config] Invalid environment configuration:');
  for (const issue of parsed.error.issues) {
    const path = issue.path.join('.') || '(root)';
    console.error(`  - ${path}: ${issue.message}`);
  }
  process.exit(1);
}

const raw = parsed.data;

/** Derived: split ALLOWED_ORIGINS into a clean array. */
function parseAllowedOrigins(input: string): readonly string[] | '*' {
  const trimmed = input.trim();
  if (trimmed === '*') return '*';
  return Object.freeze(
    trimmed
      .split(',')
      .map((s) => s.trim())
      .filter((s) => s.length > 0),
  );
}

/** Strongly-typed config object exported to the rest of the app. */
export const config = Object.freeze({
  env: raw.NODE_ENV,
  isProduction: raw.NODE_ENV === 'production',
  isTest: raw.NODE_ENV === 'test',
  port: raw.PORT,
  baseUrl: raw.BASE_URL.replace(/\/+$/, ''),

  /** Main iClaw app (viewer "Built by iClaw" link). */
  iclawAppUrl: (() => {
    const t = (raw.ICLAW_APP_URL ?? '').trim();
    return (t || 'https://app.iclaw.digital').replace(/\/+$/, '');
  })(),

  mongo: Object.freeze({
    url: raw.MONGO_URL,
    dbName: raw.MONGO_DB_NAME,
  }),

  cors: Object.freeze({
    allowedOrigins: parseAllowedOrigins(raw.ALLOWED_ORIGINS),
  }),

  limits: Object.freeze({
    maxPayloadBytes: raw.MAX_PAYLOAD_BYTES,
    createPerIpPerHour: raw.RATE_LIMIT_PER_IP_HOUR,
    readPerIpPerMinute: raw.READ_RATE_LIMIT_PER_IP_MINUTE,
  }),

  ttl: Object.freeze({
    minDays: raw.TTL_MIN_DAYS,
    maxDays: raw.TTL_MAX_DAYS,
  }),

  logAccess: raw.LOG_ACCESS,
  trustProxy: raw.TRUST_PROXY,
});

/** Public type so callers can declare config-shaped params. */
export type AppConfig = typeof config;

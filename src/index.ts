/**
 * iClaw-cloud entry point.
 *
 *   /                  → landing page (static)
 *   /s/:id             → viewer page (static; JS decrypts client-side)
 *   /api/shares/*      → ciphertext storage API
 *   /healthz           → liveness probe
 *
 * Order matters: rate limiters and CORS need to run before the routers, and
 * the error handler needs to be last.
 */

import path from 'node:path';
import fs from 'node:fs';
import express from 'express';
import helmet from 'helmet';
import compression from 'compression';
import cors from 'cors';

import { config } from './config';
import { connectToDb, disconnectFromDb } from './db';
import { sharesRouter } from './routes/shares';
import { errorHandler } from './middleware/errorHandler';

const PUBLIC_DIR = path.resolve(__dirname, '../public');

const shareViewerHtml = fs
  .readFileSync(path.join(PUBLIC_DIR, 'viewer.html'), 'utf8')
  .replace(/\{\{ICLAW_APP_URL\}\}/g, config.iclawAppUrl);

function sendShareViewer(res: express.Response) {
  res.type('html');
  res.send(shareViewerHtml);
}

function buildApp(): express.Express {
  const app = express();

  if (config.trustProxy) {
    // Behind Cloudflare / nginx: trust the first proxy hop so req.ip becomes
    // the real client IP for rate limiting.
    app.set('trust proxy', 1);
  }

  app.use(
    helmet({
      // Allow inline crypto code on the viewer page; we'd lock this down
      // further with a hash-based CSP in production.
      contentSecurityPolicy: false,
    }),
  );
  app.use(compression());

  // Only POST /api/shares needs CORS — the viewer page is served from this
  // same origin so it doesn't need it. But it's cheaper to enable the
  // middleware globally with a strict allow-list than to gate per-route.
  app.use(
    cors({
      origin: (origin, cb) => {
        const allow = config.cors.allowedOrigins;
        if (allow === '*') return cb(null, true);
        // Same-origin / non-browser requests have no Origin header.
        if (!origin) return cb(null, true);
        if (allow.includes(origin)) return cb(null, true);
        cb(new Error(`Origin ${origin} is not allowed by CORS`));
      },
      methods: ['GET', 'POST', 'OPTIONS'],
      allowedHeaders: ['Content-Type'],
      maxAge: 600,
    }),
  );

  // JSON body limit slightly above the largest possible base64-encoded
  // ciphertext (base64 inflates by ~4/3). Express defaults to 100kb which is
  // way too small for chat-sized payloads.
  app.use(
    express.json({
      limit: Math.ceil((config.limits.maxPayloadBytes * 4) / 3) + 4 * 1024,
    }),
  );

  app.get('/healthz', (_req, res) => {
    res.json({ ok: true, ts: Date.now() });
  });

  app.use('/api/shares', sharesRouter);

  // Static viewer: any path that looks like /s/<id> serves the same SPA.
  app.get(/^\/s\/[A-Za-z0-9_-]{6,32}\/?$/, (_req, res) => {
    sendShareViewer(res);
  });

  app.get('/viewer.html', (_req, res) => {
    sendShareViewer(res);
  });

  // Landing + any other static asset (CSS/JS/icons).
  //
  // HTML + viewer.js use `no-cache` so a fresh deploy is visible without a
  // hard reload; browsers still revalidate via ETag so unchanged bytes are
  // a single 304. Vendored libs and icons keep the 1-hour cache.
  app.use(
    express.static(PUBLIC_DIR, {
      index: 'index.html',
      etag: true,
      maxAge: '1h',
      setHeaders(res, filePath) {
        if (/\.(html|js|css)$/.test(filePath) && !filePath.includes(`${PUBLIC_DIR}/js/vendor/`) && !filePath.includes(`${PUBLIC_DIR}/css/vendor/`)) {
          res.setHeader('Cache-Control', 'no-cache, must-revalidate');
        }
      },
    }),
  );

  app.use(errorHandler);
  return app;
}

async function main(): Promise<void> {
  await connectToDb();
  const app = buildApp();
  const server = app.listen(config.port, config.host, () => {
    console.log(
      `[iclaw-cloud] listening on ${config.baseUrl} (${config.host}:${config.port}, ${config.env})`,
    );
  });

  // Graceful shutdown.
  const shutdown = async (signal: string) => {
    console.log(`[iclaw-cloud] ${signal} — shutting down`);
    server.close(() => {
      void disconnectFromDb().finally(() => process.exit(0));
    });
    // If we hang, force exit after 10s.
    setTimeout(() => process.exit(1), 10_000).unref();
  };
  process.on('SIGINT', () => void shutdown('SIGINT'));
  process.on('SIGTERM', () => void shutdown('SIGTERM'));
}

void main().catch((err) => {
  console.error('[iclaw-cloud] failed to start', err);
  process.exit(1);
});

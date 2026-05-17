/**
 * Last-resort Express error handler.
 *
 * Returns a sanitised JSON body. Logging is tiered: 404/expected client
 * outcomes stay quiet; 4xx other than 404 as a single warn line; 5xx as
 * error + stack in development. 4-arg signature is what Express uses to
 * detect "error middleware" — don't remove `_next` even unused.
 */

import type { ErrorRequestHandler } from 'express';
import { config } from '../config';

export const errorHandler: ErrorRequestHandler = (err, req, res, _next) => {
  const status =
    typeof (err as { status?: unknown }).status === 'number'
      ? (err as { status: number }).status
      : 500;
  const message =
    err instanceof Error ? err.message : 'internal error';

  const line = `${req.method} ${req.originalUrl} → ${status} :: ${message}`;

  if (status >= 500) {
    console.error(`[error] ${line}`);
    if (!config.isProduction && err instanceof Error && err.stack) {
      console.error(err.stack);
    }
  } else if (status === 404) {
    // Burned share, TTL expiry, bad id — normal for the viewer; not an ops incident.
  } else if (status >= 400) {
    console.warn(`[http] ${line}`);
  }

  if (res.headersSent) return;
  res.status(status).json({
    error: config.isProduction && status >= 500 ? 'internal error' : message,
  });
};

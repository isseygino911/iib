import rateLimit from 'express-rate-limit';
import { verifyAccessToken } from '../utils/auth.js';

// ── Auth middleware ──────────────────────────────────────────

export function authMiddleware(req, res, next) {
  const token = req.cookies?.accessToken;
  if (!token)
    return res.status(401).json({ message: 'No access token provided' });

  try {
    req.user = verifyAccessToken(token);
    next();
  } catch (err) {
    const msg = err.name === 'TokenExpiredError' ? 'Access token expired' : 'Invalid access token';
    return res.status(401).json({ message: msg });
  }
}

// ── Rate limiters ────────────────────────────────────────────

export const authLimiter = rateLimit({
  windowMs:        15 * 60 * 1000,
  max:             10,
  standardHeaders: true,
  legacyHeaders:   false,
  message: { message: 'Too many requests from this IP, please try again after 15 minutes.' },
});

export const apiLimiter = rateLimit({
  windowMs:        60 * 1000,
  max:             100,
  standardHeaders: true,
  legacyHeaders:   false,
  message: { message: 'Too many requests, please slow down.' },
});

// ── Error handlers ───────────────────────────────────────────

export function errorHandler(err, req, res, next) {
  const status  = err.status || err.statusCode || 500;
  const message = err.message || 'Internal Server Error';

  if (process.env.NODE_ENV !== 'production') console.error('[error]', err);

  res.status(status).json({
    message,
    ...(process.env.NODE_ENV !== 'production' && { stack: err.stack }),
  });
}

export function notFoundHandler(req, res) {
  res.status(404).json({ message: `Route ${req.method} ${req.path} not found` });
}

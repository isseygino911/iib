import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

// ── Password ─────────────────────────────────────────────────

export const hashPassword    = (password) => bcrypt.hash(password, 12);
export const comparePassword = (password, hash) => bcrypt.compare(password, hash);

// ── JWT ──────────────────────────────────────────────────────

export const signAccessToken  = (payload) =>
  jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN || '15m' });

export const signRefreshToken = (payload) =>
  jwt.sign(payload, process.env.JWT_REFRESH_SECRET, { expiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d' });

export const verifyAccessToken  = (token) => jwt.verify(token, process.env.JWT_SECRET);
export const verifyRefreshToken = (token) => jwt.verify(token, process.env.JWT_REFRESH_SECRET);

// ── Cookie options ───────────────────────────────────────────

export const ACCESS_COOKIE_OPTS = {
  httpOnly: true,
  secure:   process.env.NODE_ENV === 'production',
  sameSite: 'strict',
  maxAge:   15 * 60 * 1000,
};

export const REFRESH_COOKIE_OPTS = {
  httpOnly: true,
  secure:   process.env.NODE_ENV === 'production',
  sameSite: 'strict',
  maxAge:   7 * 24 * 60 * 60 * 1000,
};

// ── Token helpers ────────────────────────────────────────────

export function generateTokenPair(id, email, role = 'user') {
  const payload = { id, email, role };
  return {
    accessToken:  signAccessToken(payload),
    refreshToken: signRefreshToken(payload),
  };
}

export function setCookieTokens(res, accessToken, refreshToken) {
  res.cookie('accessToken',  accessToken,  ACCESS_COOKIE_OPTS);
  res.cookie('refreshToken', refreshToken, REFRESH_COOKIE_OPTS);
}

// ── Async handler ────────────────────────────────────────────

export const asyncHandler = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);

// ── Validators ───────────────────────────────────────────────

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
export const isValidEmail = (email) => EMAIL_RE.test(email);

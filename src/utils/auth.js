import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

// ── Password ─────────────────────────────────────────────────

// bcrypt throws on a non-string argument, so the type is checked before the
// length gate rather than letting it surface as a 500.
export const isValidPassword = (password) =>
  typeof password === 'string' && password.length >= 8;

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

// A browser only deletes a cookie when httpOnly/secure/sameSite/path match the
// ones it was set with. maxAge must be dropped, though — clearCookie derives
// Expires from it, which would push the expiry into the future instead of the past.
const clearOpts = ({ maxAge, ...rest }) => rest;

export function clearCookieTokens(res) {
  res.clearCookie('accessToken',  clearOpts(ACCESS_COOKIE_OPTS));
  res.clearCookie('refreshToken', clearOpts(REFRESH_COOKIE_OPTS));
}

// ── Async handler ────────────────────────────────────────────

export const asyncHandler = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);

// ── Validators ───────────────────────────────────────────────

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// 254 is the RFC 5321 maximum and fits the VARCHAR(255) email column, so an
// over-long address is rejected here instead of failing as a MySQL 500.
export const isValidEmail = (email) =>
  typeof email === 'string' && email.length <= 254 && EMAIL_RE.test(email);

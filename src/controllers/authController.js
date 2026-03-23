import pool from '../config/db.js';
import {
  hashPassword, comparePassword,
  verifyRefreshToken,
  generateTokenPair, setCookieTokens,
  asyncHandler, isValidEmail,
} from '../utils/auth.js';

// ── Controllers ──────────────────────────────────────────────

export const register = asyncHandler(async (req, res) => {
  const { name, email, password } = req.body;

  if (!email || !password)
    return res.status(400).json({ message: 'Email and password are required' });
  if (password.length < 8)
    return res.status(400).json({ message: 'Password must be at least 8 characters' });
  if (!isValidEmail(email))
    return res.status(400).json({ message: 'Invalid email address' });
  if (name !== undefined && (typeof name !== 'string' || name.trim().length === 0 || name.trim().length > 100))
    return res.status(400).json({ message: 'Name must be between 1 and 100 characters' });

  const [existing] = await pool.query('SELECT id FROM users WHERE email = ?', [email]);
  if (existing.length > 0)
    return res.status(409).json({ message: 'Email already registered' });

  const passwordHash = await hashPassword(password);
  const cleanName    = name ? name.trim() : null;
  const [result] = await pool.query(
    'INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)',
    [cleanName, email, passwordHash]
  );

  const userId = result.insertId;
  const { accessToken, refreshToken } = generateTokenPair(userId, email, 'user');

  await pool.query('UPDATE users SET refresh_token = ? WHERE id = ?', [refreshToken, userId]);
  setCookieTokens(res, accessToken, refreshToken);

  return res.status(201).json({ message: 'Account created successfully', user: { id: userId, email, role: 'user' } });
});

export const login = asyncHandler(async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password)
    return res.status(400).json({ message: 'Email and password are required' });

  const [rows] = await pool.query(
    'SELECT id, email, password_hash, role FROM users WHERE email = ?',
    [email]
  );

  if (rows.length === 0 || !(await comparePassword(password, rows[0].password_hash)))
    return res.status(401).json({ message: 'Invalid credentials' });

  const user = rows[0];
  const { accessToken, refreshToken } = generateTokenPair(user.id, user.email, user.role);

  await pool.query('UPDATE users SET refresh_token = ? WHERE id = ?', [refreshToken, user.id]);
  setCookieTokens(res, accessToken, refreshToken);

  return res.status(200).json({ message: 'Login successful', user: { id: user.id, email: user.email, role: user.role } });
});

export const logout = asyncHandler(async (req, res) => {
  const token = req.cookies?.refreshToken;

  if (token) {
    await pool.query('UPDATE users SET refresh_token = NULL WHERE refresh_token = ?', [token]);
  }

  res.clearCookie('accessToken',  { httpOnly: true, sameSite: 'strict' });
  res.clearCookie('refreshToken', { httpOnly: true, sameSite: 'strict' });
  return res.status(200).json({ message: 'Logged out successfully' });
});

export const getMe = asyncHandler(async (req, res) => {
  const [rows] = await pool.query(
    'SELECT id, name, email, role, created_at FROM users WHERE id = ?',
    [req.user.id]
  );

  if (rows.length === 0)
    return res.status(404).json({ message: 'User not found' });

  return res.status(200).json({ user: rows[0] });
});

export const refresh = asyncHandler(async (req, res) => {
  const token = req.cookies?.refreshToken;
  if (!token)
    return res.status(401).json({ message: 'No refresh token' });

  let decoded;
  try {
    decoded = verifyRefreshToken(token);
  } catch {
    return res.status(401).json({ message: 'Invalid or expired refresh token' });
  }

  const [rows] = await pool.query(
    'SELECT id, email, role FROM users WHERE id = ? AND refresh_token = ?',
    [decoded.id, token]
  );

  if (rows.length === 0)
    return res.status(401).json({ message: 'Refresh token revoked' });

  const user = rows[0];
  const { accessToken, refreshToken: newRefreshToken } = generateTokenPair(user.id, user.email, user.role);

  await pool.query('UPDATE users SET refresh_token = ? WHERE id = ?', [newRefreshToken, user.id]);
  setCookieTokens(res, accessToken, newRefreshToken);

  return res.status(200).json({ ok: true });
});


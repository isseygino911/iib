import pool from '../config/db.js';
import { hashPassword, asyncHandler, isValidEmail } from '../utils/auth.js';

// ── Helpers ───────────────────────────────────────────────────

const SAFE_COLUMNS = 'id, name, email, role, created_at, updated_at';

function isValidRole(role) {
  return role === 'user' || role === 'admin';
}

function isValidName(name) {
  return typeof name === 'string' && name.trim().length > 0 && name.trim().length <= 100;
}

// ── Controllers ───────────────────────────────────────────────

/**
 * GET /api/users
 * List all users (admin only).
 * Query params: ?page=1&limit=20&role=user&search=email_fragment
 */
export const listUsers = asyncHandler(async (req, res) => {
  const page   = Math.max(1, parseInt(req.query.page,  10) || 1);
  const limit  = Math.min(100, Math.max(1, parseInt(req.query.limit, 10) || 20));
  const offset = (page - 1) * limit;

  const conditions = [];
  const params     = [];

  if (req.query.role) {
    if (!isValidRole(req.query.role))
      return res.status(400).json({ message: 'Invalid role filter. Must be "user" or "admin".' });
    conditions.push('role = ?');
    params.push(req.query.role);
  }

  if (req.query.search) {
    conditions.push('email LIKE ?');
    params.push(`%${req.query.search}%`);
  }

  const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';

  const [[{ total }]] = await pool.query(
    `SELECT COUNT(*) AS total FROM users ${where}`,
    params
  );

  const [rows] = await pool.query(
    `SELECT ${SAFE_COLUMNS} FROM users ${where} ORDER BY created_at DESC LIMIT ? OFFSET ?`,
    [...params, limit, offset]
  );

  return res.status(200).json({
    message: 'Users retrieved successfully',
    data: {
      users: rows,
      pagination: {
        total,
        page,
        limit,
        totalPages: Math.ceil(total / limit),
      },
    },
  });
});

/**
 * GET /api/users/:id
 * Get a single user by ID (admin only).
 */
export const getUser = asyncHandler(async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!id || id < 1)
    return res.status(400).json({ message: 'Invalid user ID' });

  const [rows] = await pool.query(
    `SELECT ${SAFE_COLUMNS} FROM users WHERE id = ?`,
    [id]
  );

  if (rows.length === 0)
    return res.status(404).json({ message: 'User not found' });

  return res.status(200).json({ message: 'User retrieved successfully', data: { user: rows[0] } });
});

/**
 * POST /api/users
 * Create a new user (admin only).
 * Body: { name?, email, password, role? }
 */
export const createUser = asyncHandler(async (req, res) => {
  const { name, email, password, role = 'user' } = req.body;

  if (!email || !password)
    return res.status(400).json({ message: 'Email and password are required' });
  if (!isValidEmail(email))
    return res.status(400).json({ message: 'Invalid email address' });
  if (password.length < 8)
    return res.status(400).json({ message: 'Password must be at least 8 characters' });
  if (!isValidRole(role))
    return res.status(400).json({ message: 'Role must be "user" or "admin"' });
  if (name !== undefined && !isValidName(name))
    return res.status(400).json({ message: 'Name must be between 1 and 100 characters' });

  const [existing] = await pool.query('SELECT id FROM users WHERE email = ?', [email]);
  if (existing.length > 0)
    return res.status(409).json({ message: 'Email already registered' });

  const passwordHash = await hashPassword(password);
  const cleanName    = name ? name.trim() : null;

  const [result] = await pool.query(
    'INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, ?)',
    [cleanName, email, passwordHash, role]
  );

  const userId = result.insertId;
  const [rows] = await pool.query(
    `SELECT ${SAFE_COLUMNS} FROM users WHERE id = ?`,
    [userId]
  );

  return res.status(201).json({ message: 'User created successfully', data: { user: rows[0] } });
});

/**
 * PATCH /api/users/:id
 * Update a user's name, email, role, or password (admin only).
 * Body: { name?, email?, password?, role? }
 */
export const updateUser = asyncHandler(async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!id || id < 1)
    return res.status(400).json({ message: 'Invalid user ID' });

  const { name, email, password, role } = req.body;

  if (!name && !email && !password && !role)
    return res.status(400).json({ message: 'At least one field (name, email, password, role) must be provided' });

  const setClauses = [];
  const params     = [];

  if (name !== undefined) {
    if (!isValidName(name))
      return res.status(400).json({ message: 'Name must be between 1 and 100 characters' });
    setClauses.push('name = ?');
    params.push(name.trim());
  }

  if (email !== undefined) {
    if (!isValidEmail(email))
      return res.status(400).json({ message: 'Invalid email address' });

    const [dup] = await pool.query('SELECT id FROM users WHERE email = ? AND id != ?', [email, id]);
    if (dup.length > 0)
      return res.status(409).json({ message: 'Email already in use by another account' });

    setClauses.push('email = ?');
    params.push(email);
  }

  if (password !== undefined) {
    if (password.length < 8)
      return res.status(400).json({ message: 'Password must be at least 8 characters' });
    const passwordHash = await hashPassword(password);
    setClauses.push('password_hash = ?');
    params.push(passwordHash);
  }

  if (role !== undefined) {
    if (!isValidRole(role))
      return res.status(400).json({ message: 'Role must be "user" or "admin"' });
    setClauses.push('role = ?');
    params.push(role);
  }

  params.push(id);

  const [result] = await pool.query(
    `UPDATE users SET ${setClauses.join(', ')} WHERE id = ?`,
    params
  );

  if (result.affectedRows === 0)
    return res.status(404).json({ message: 'User not found' });

  const [rows] = await pool.query(
    `SELECT ${SAFE_COLUMNS} FROM users WHERE id = ?`,
    [id]
  );

  return res.status(200).json({ message: 'User updated successfully', data: { user: rows[0] } });
});

/**
 * DELETE /api/users/:id
 * Delete a user by ID (admin only). An admin cannot delete themselves.
 */
export const deleteUser = asyncHandler(async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!id || id < 1)
    return res.status(400).json({ message: 'Invalid user ID' });

  if (req.user.id === id)
    return res.status(400).json({ message: 'You cannot delete your own account' });

  const [result] = await pool.query('DELETE FROM users WHERE id = ?', [id]);

  if (result.affectedRows === 0)
    return res.status(404).json({ message: 'User not found' });

  return res.status(200).json({ message: 'User deleted successfully' });
});

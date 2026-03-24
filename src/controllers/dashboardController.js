import pool from '../config/db.js';
import { hashPassword, comparePassword, asyncHandler, isValidEmail, ACCESS_COOKIE_OPTS, REFRESH_COOKIE_OPTS } from '../utils/auth.js';
import { PROJECTS } from '../data/projects.js';

// ── Helpers ───────────────────────────────────────────────────

const SAFE_COLUMNS = 'id, name, email, role, created_at, updated_at';

function isValidName(name) {
  return typeof name === 'string' && name.trim().length > 0 && name.trim().length <= 100;
}

/**
 * Derive a human-readable account age string from a created_at timestamp.
 * e.g. "2 years, 3 months" or "5 days"
 */
function accountAge(createdAt) {
  const now      = new Date();
  const created  = new Date(createdAt);
  let   years    = now.getFullYear() - created.getFullYear();
  let   months   = now.getMonth()    - created.getMonth();
  let   days     = now.getDate()     - created.getDate();

  if (days < 0) {
    months -= 1;
    days   += new Date(now.getFullYear(), now.getMonth(), 0).getDate();
  }
  if (months < 0) {
    years  -= 1;
    months += 12;
  }

  if (years > 0 && months > 0) return `${years} year${years !== 1 ? 's' : ''}, ${months} month${months !== 1 ? 's' : ''}`;
  if (years > 0)                return `${years} year${years !== 1 ? 's' : ''}`;
  if (months > 0)               return `${months} month${months !== 1 ? 's' : ''}`;
  return `${days} day${days !== 1 ? 's' : ''}`;
}

// ── Controllers ───────────────────────────────────────────────

/**
 * GET /api/dashboard
 * Returns a summary object for the authenticated user's dashboard.
 * Includes: profile, account stats, and global portfolio stats.
 */
export const getDashboard = asyncHandler(async (req, res) => {
  const userId = req.user.id;

  // Fetch the full user record
  const [rows] = await pool.query(
    `SELECT ${SAFE_COLUMNS} FROM users WHERE id = ?`,
    [userId]
  );

  if (rows.length === 0)
    return res.status(404).json({ message: 'User not found' });

  const user = rows[0];

  // ── Account stats ────────────────────────────────────────────
  const memberSince     = new Date(user.created_at).toISOString().split('T')[0];
  const lastUpdated     = new Date(user.updated_at).toISOString().split('T')[0];
  const accountAgeLabel = accountAge(user.created_at);

  // ── Admin-only: total user count ─────────────────────────────
  let totalUsers = null;
  if (user.role === 'admin') {
    const [[{ count }]] = await pool.query('SELECT COUNT(*) AS count FROM users');
    totalUsers = count;
  }

  // ── Portfolio stats (derived from static project data) ───────
  const projectTypes = PROJECTS.reduce((acc, p) => {
    acc[p.type] = (acc[p.type] || 0) + 1;
    return acc;
  }, {});

  const projectYears = [...new Set(PROJECTS.map(p => p.year))].sort((a, b) => b - a);

  const portfolioStats = {
    totalProjects:  PROJECTS.length,
    projectsByType: projectTypes,
    yearsActive:    projectYears,
    latestProject:  PROJECTS
      .slice()
      .sort((a, b) => b.year - a.year)[0]?.title ?? null,
  };

  // ── Response ─────────────────────────────────────────────────
  return res.status(200).json({
    message: 'Dashboard data retrieved successfully',
    data: {
      profile: {
        id:    user.id,
        name:  user.name,
        email: user.email,
        role:  user.role,
      },
      accountStats: {
        memberSince,
        lastUpdated,
        accountAge: accountAgeLabel,
        ...(totalUsers !== null && { totalUsers }),
      },
      portfolioStats,
    },
  });
});

/**
 * PATCH /api/dashboard/profile
 * Allows the authenticated user to update their own name or email.
 * Body: { name?, email? }
 */
export const updateProfile = asyncHandler(async (req, res) => {
  const userId = req.user.id;
  const { name, email } = req.body;

  if (name === undefined && email === undefined)
    return res.status(400).json({ message: 'At least one field (name, email) must be provided' });

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

    const [dup] = await pool.query(
      'SELECT id FROM users WHERE email = ? AND id != ?',
      [email, userId]
    );
    if (dup.length > 0)
      return res.status(409).json({ message: 'Email already in use by another account' });

    setClauses.push('email = ?');
    params.push(email);
  }

  params.push(userId);

  const [result] = await pool.query(
    `UPDATE users SET ${setClauses.join(', ')} WHERE id = ?`,
    params
  );

  if (result.affectedRows === 0)
    return res.status(404).json({ message: 'User not found' });

  const [rows] = await pool.query(
    `SELECT ${SAFE_COLUMNS} FROM users WHERE id = ?`,
    [userId]
  );

  return res.status(200).json({
    message: 'Profile updated successfully',
    data: {
      profile: {
        id:    rows[0].id,
        name:  rows[0].name,
        email: rows[0].email,
        role:  rows[0].role,
      },
    },
  });
});

/**
 * PATCH /api/dashboard/password
 * Allows the authenticated user to change their own password.
 * Body: { currentPassword, newPassword }
 */
export const changePassword = asyncHandler(async (req, res) => {
  const userId = req.user.id;
  const { currentPassword, newPassword } = req.body;

  if (!currentPassword || !newPassword)
    return res.status(400).json({ message: 'currentPassword and newPassword are required' });

  const trimmedNew = typeof newPassword === 'string' ? newPassword.trim() : '';
  if (trimmedNew.length < 8)
    return res.status(400).json({ message: 'New password must be at least 8 characters' });

  if (currentPassword === trimmedNew)
    return res.status(400).json({ message: 'New password must differ from the current password' });

  // Fetch current hash
  const [rows] = await pool.query(
    'SELECT id, password_hash FROM users WHERE id = ?',
    [userId]
  );

  if (rows.length === 0)
    return res.status(404).json({ message: 'User not found' });

  const isMatch = await comparePassword(currentPassword, rows[0].password_hash);
  if (!isMatch)
    return res.status(401).json({ message: 'Current password is incorrect' });

  const newHash = await hashPassword(trimmedNew);

  await pool.query(
    'UPDATE users SET password_hash = ?, refresh_token = NULL WHERE id = ?',
    [newHash, userId]
  );

  // Clear tokens from cookies so the client must log in again with the new password
  res.clearCookie('accessToken',  ACCESS_COOKIE_OPTS);
  res.clearCookie('refreshToken', REFRESH_COOKIE_OPTS);

  return res.status(200).json({ message: 'Password changed successfully. Please log in again.' });
});

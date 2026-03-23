import { Router } from 'express';
import { getDashboard, updateProfile, changePassword } from '../controllers/dashboardController.js';
import { authMiddleware, apiLimiter } from '../middleware/index.js';

const router = Router();

// All dashboard routes require a valid access token
router.use(authMiddleware);

/**
 * GET /api/dashboard
 * Returns the full dashboard summary for the authenticated user.
 */
router.get('/', apiLimiter, getDashboard);

/**
 * PATCH /api/dashboard/profile
 * Update the authenticated user's name or email.
 */
router.patch('/profile', apiLimiter, updateProfile);

/**
 * PATCH /api/dashboard/password
 * Change the authenticated user's password.
 */
router.patch('/password', apiLimiter, changePassword);

export default router;

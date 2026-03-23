import { Router } from 'express';
import { register, login, logout, getMe, refresh } from '../controllers/authController.js';
import { authMiddleware, authLimiter } from '../middleware/index.js';

const router = Router();

router.post('/register', authLimiter, register);
router.post('/login',    authLimiter, login);
router.post('/logout',   authLimiter, logout);
router.post('/refresh',  refresh);
router.get('/me',        authMiddleware, getMe);

export default router;

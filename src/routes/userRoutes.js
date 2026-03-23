import { Router } from 'express';
import {
  listUsers,
  getUser,
  createUser,
  updateUser,
  deleteUser,
} from '../controllers/userController.js';
import { authMiddleware, adminMiddleware } from '../middleware/index.js';

const router = Router();

// All user management routes require authentication + admin role
router.use(authMiddleware, adminMiddleware);

router.get('/',    listUsers);
router.get('/:id', getUser);
router.post('/',   createUser);
router.patch('/:id', updateUser);
router.delete('/:id', deleteUser);

export default router;

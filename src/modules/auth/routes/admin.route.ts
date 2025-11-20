// routes/admin.route.ts
import { Router } from 'express';
import { authenticate } from '../../../middleware/auth.middleware';
import { requireAdminRole } from '../../../middleware/admin.middleware';

const router = Router();

router.get(
  '/protected',
  authenticate,      // cek JWT
  requireAdminRole,  // cek role admin
  (_req, res) => {
    res.json({ message: 'Access granted to admin protected route' });
  }
);

export default router;

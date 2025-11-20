import { Router, Request, Response } from 'express';
import { authenticate } from '../../../middleware/auth.middleware';

const router = Router();

// Protected test route
router.get('/', authenticate, (req: Request, res: Response) => {
  res.json({
    message: 'Access granted to protected route',
    user: req.user,
  });
});

export default router;

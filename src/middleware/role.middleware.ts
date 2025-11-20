import { Request, Response, NextFunction } from 'express';
import { Role } from '../core/auth/roles';
import { authenticate } from './auth.middleware';

type Policy = (req: Request) => boolean;

/**
 * requireRole
 * @param allowedRoles array of allowed roles
 * @param policy optional function untuk cek resource ownership / policy
 */
export const requireRole = (allowedRoles: Role[], policy?: Policy) => {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      // Pastikan user sudah authenticated
      await authenticate(req, res, async () => {
        const user = req.user;
        if (!user) return res.status(401).json({ error: 'Unauthorized: User not authenticated' });

        // Cek role
        if (!allowedRoles.includes(user.role)) {
          return res.status(403).json({ error: 'Forbidden: Insufficient role' });
        }

        // Cek policy (misal resource ownership)
        if (policy && !policy(req)) {
          return res.status(403).json({ error: 'Forbidden: Policy validation failed' });
        }

        next();
      });
    } catch (err) {
      console.error('requireRole error:', err);
      return res.status(500).json({ error: 'Internal server error' });
    }
  };
};

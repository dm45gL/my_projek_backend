// import { Request, Response, NextFunction } from 'express';
// import { verifyJwt } from '../core/auth/jwt';
// import { prisma } from '../core/db/client';

// export const authenticate = async (req: Request, res: Response, next: NextFunction) => {
//   const accessToken = req.cookies.accessToken;
//   if (!accessToken) {
//     return res.status(401).json({ error: 'Unauthorized: No access token provided' });
//   }

//   const payload = verifyJwt(accessToken);
//   if (!payload) {
//     return res.status(401).json({ error: 'Unauthorized: Invalid or expired token' });
//   }

//   if (
//     typeof payload.sub !== 'string' ||
//     (payload.type !== 'ADMIN' && payload.type !== 'CLIENT')
//   ) {
//     return res.status(401).json({ error: 'Unauthorized: Invalid token structure' });
//   }

//   // ✅ Pisahkan logika berdasarkan tipe user
//   if (payload.type === 'ADMIN') {
//     const user = await prisma.admin.findUnique({
//       where: { id: payload.sub },
//       select: { id: true, email: true, role: true },
//     });

//     if (!user) {
//       return res.status(401).json({ error: 'Unauthorized: Admin not found' });
//     }

//     (req as any).user = {
//       id: user.id,
//       email: user.email,
//       role: user.role,
//       type: 'ADMIN',
//     };

//   } else if (payload.type === 'CLIENT') {
//     const user = await prisma.client.findUnique({
//       where: { id: payload.sub },
//       select: { id: true, email: true },
//     });

//     if (!user) {
//       return res.status(401).json({ error: 'Unauthorized: Client not found' });
//     }

//     (req as any).user = {
//       id: user.id,
//       email: user.email,
//       role: 'CLIENT', // ✅ Hardcode karena Client tidak punya role
//       type: 'CLIENT',
//     };
//   }

//   next();
// };


import { Request, Response, NextFunction } from 'express';
import { prisma } from '../core/db/client';
import { Role } from '../core/auth/roles';
import { verifyJwt } from '../core/auth/jwt';

declare module 'express' {
  interface Request {
    user?: {
      id: string;
      email: string;
      role: Role;
      type: 'ADMIN' | 'CLIENT';
    };
  }
}

export const authenticate = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const accessToken = req.cookies.accessToken;
    if (!accessToken) return res.status(401).json({ error: 'Unauthorized: No access token provided' });

    const payload = verifyJwt(accessToken);
    if (!payload) return res.status(401).json({ error: 'Unauthorized: Invalid or expired token' });

    if (typeof payload.sub !== 'string' || (payload.type !== 'ADMIN' && payload.type !== 'CLIENT')) {
      return res.status(401).json({ error: 'Unauthorized: Invalid token structure' });
    }

    if (payload.type === 'ADMIN') {
      const user = await prisma.admin.findUnique({
        where: { id: payload.sub },
        select: { id: true, email: true, role: true },
      });
      if (!user) return res.status(401).json({ error: 'Unauthorized: Admin not found' });

      req.user = { id: user.id, email: user.email, role: user.role as Role, type: 'ADMIN' };
    } else if (payload.type === 'CLIENT') {
      const user = await prisma.client.findUnique({
        where: { id: payload.sub },
        select: { id: true, email: true },
      });
      if (!user) return res.status(401).json({ error: 'Unauthorized: Client not found' });

      req.user = { id: user.id, email: user.email, role: Role.CLIENT, type: 'CLIENT' };
    }

    next();
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Internal server error' });
  }
};

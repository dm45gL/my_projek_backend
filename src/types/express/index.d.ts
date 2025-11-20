import { Role } from '../../types/role';

declare global {
  namespace Express {
    interface Request {
      user?: {
        id: string;
        email: string;
        role: Role;
        type: 'ADMIN' | 'CLIENT';
      };
    }
  }
}

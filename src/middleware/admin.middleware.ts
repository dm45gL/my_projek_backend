// middleware/admin.middleware.ts
import { requireRole } from './role.middleware';
import { Role } from '../core/auth/roles';

export const requireAdminRole = requireRole([Role.SYSADMIN, Role.FINANCE, Role.BUSINESS]);

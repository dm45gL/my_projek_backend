import { Router } from "express";
import { authenticate } from "../../../middleware/auth.middleware";
import { requireRole } from "../../../middleware/role.middleware";
import { Role } from "../../../core/auth/roles";
import {
  createUserBySysadmin,
  listUsers,
  getUserById,
  updateUserBySysadmin,
  deleteUserBySysadmin
} from "./../controllers/admin.controller";
const router = Router();

router.post("/create-user", authenticate, requireRole([Role.SYSADMIN]), createUserBySysadmin);
router.get("/users", authenticate, requireRole([Role.SYSADMIN]), listUsers);
router.get("/users/:id", authenticate, requireRole([Role.SYSADMIN]), getUserById);
router.put("/users/:id", authenticate, requireRole([Role.SYSADMIN]), updateUserBySysadmin);
router.delete("/users/:id", authenticate, requireRole([Role.SYSADMIN]), deleteUserBySysadmin);

export default router;

import { Router } from 'express';
import * as authCtrl from '../controllers/auth.controller';
import { getAdminMe } from '../controllers/auth.controller';
import { authenticate } from '../../../middleware/auth.middleware';
import { requireAdminRole } from '../../../middleware/admin.middleware';
const router = Router();

// Admin login
router.post('/login', authCtrl.adminLogin);         
router.post('/login/verify', authCtrl.adminLoginVerify); 

// Admin forgot password
router.post('/forgot-password/request', authCtrl.adminForgotPasswordRequest);
router.post('/forgot-password/verify', authCtrl.adminForgotPasswordVerify);

// Refresh access token
router.post('/refresh', authCtrl.RefreshAccessToken);

router.get('/me', authenticate, requireAdminRole, getAdminMe);
// Logout
router.post('/logout', authCtrl.Logout);

export default router;

// \modules\client\routes\auth.routes.ts

import { Router } from 'express';
import * as authCtrl from '../controllers/auth.controller';
import { getClientMe } from '../controllers/auth.controller';
import { authenticate } from '../../../middleware/auth.middleware';



const router = Router();

// ── REGISTER CLIENT ───────────────────────────────
router.post('/register/request-otp', authCtrl.requestRegisterOtp);
router.post('/register/complete', authCtrl.completeRegister);

// Login client dengan OTP
router.post('/login', authCtrl.loginClient);          
router.post('/login/verify', authCtrl.loginVerify);  

// Forgot password
router.post('/forgot-password/request', authCtrl.forgotPasswordRequest);
router.post('/forgot-password/verify', authCtrl.forgotPasswordVerify);

// Refresh access token
router.post('/refresh', authCtrl.refreshAccessToken);
router.get('/me', authenticate, getClientMe);
// Logout
router.post('/logout', authCtrl.logout);

export default router;

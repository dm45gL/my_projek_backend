import express from 'express';
import cookieParser from 'cookie-parser';
import helmet from 'helmet';
import cors from 'cors';

// Routes
import adminAuthRoutes from './modules/auth/routes/auth.routes';
import clientAuthRoutes from './modules/client/routes/auth.routes';
import sysadminRoutes from './modules/sysadmin/routes/admin.routes';
import protectedRoute from './modules/auth/routes/protected.route';

// Utils
import { errorHandler } from './core/utils/error-handler';

const app = express();

// ── Middleware Global ─────────────
app.use(helmet());
app.use(express.json({ limit: '10mb' }));
app.use(cookieParser());

// CORS setup (whitelist frontend URL)
app.use(
  cors({
    origin: [
      process.env.FRONTEND_URL || 'http://localhost:5173',
      'http://localhost:5000',
    ],
    credentials: true,
  })
);

// ── Routes ─────────────────────────

// Client routes (self-service, register/login OTP)
app.use('/client', clientAuthRoutes);

// Admin auth routes (login, verify OTP, forgot password, refresh, logout)
app.use('/admin', adminAuthRoutes);

// Sysadmin management routes (requires authentication + SYSADMIN role)
app.use('/sysadmin', sysadminRoutes);

// Protected example route
app.use('/protected-route', protectedRoute);


// ── Global Error Handler ───────────
app.use(errorHandler);

export default app;

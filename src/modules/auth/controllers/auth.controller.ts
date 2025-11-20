import { Request, Response } from 'express';
import redis from '../../../core/db/redis';
import { prisma } from '../../../core/db/client';
import { hashPassword, comparePassword } from '../../../core/utils/bcrypt';
import { signJwt } from '../../../core/auth/jwt';
import { requestOtp, verifyOtp } from '../../../core/security/otp.service';
import {
  adminLoginRequestSchema,
  adminLoginVerifySchema,
  adminForgotPasswordRequestSchema,
  adminForgotPasswordVerifySchema,
} from '../dto/auth.dto';
import crypto from 'crypto';

// ── GENERATE REFRESH TOKEN ─────────────
export const generateRefreshToken = (): string => {
  return crypto.randomBytes(64).toString('hex'); // token 128 karakter
};

// ── ADMIN LOGIN STEP 1: PASSWORD → OTP ─────────────
export const adminLogin = async (req: Request, res: Response) => {
  try {
    const result = adminLoginRequestSchema.safeParse(req.body);
    if (!result.success) return res.status(400).json({ error: 'Validation failed', details: result.error.format() });

    const { email, password } = result.data;

    const admin = await prisma.admin.findUnique({ where: { email } });
    if (!admin) return res.status(400).json({ error: 'Email or password incorrect' });

    const valid = await comparePassword(password, admin.password);
    if (!valid) return res.status(400).json({ error: 'Email or password incorrect' });

    // Kirim OTP ke email
    const otpResult = await requestOtp(email);
    if (!otpResult.success) return res.status(429).json({ error: otpResult.message });

    // Simpan sementara di Redis untuk verifikasi OTP (5 menit)
    await redis.set(`admin:login:${email}`, 'pending', { EX: 300 });

    return res.json({ message: 'OTP sent to your email' });
  } catch (err) {
    console.error('adminLogin error:', err);
    return res.status(500).json({ error: 'Admin login failed' });
  }
};

// ── ADMIN LOGIN STEP 2: VERIFY OTP → JWT + REFRESH TOKEN ───────────
export const adminLoginVerify = async (req: Request, res: Response) => {
  try {
    const result = adminLoginVerifySchema.safeParse(req.body);
    if (!result.success)
      return res.status(400).json({ error: 'Validation failed', details: result.error.format() });

    const { email, otp } = result.data;

    const temp = await redis.get(`admin:login:${email}`);
    if (!temp) return res.status(400).json({ error: 'OTP session expired or invalid' });

    const otpResult = await verifyOtp(email, otp);
    if (!otpResult.success) return res.status(400).json({ error: otpResult.message });

    const admin = await prisma.admin.findUnique({ where: { email } });
    if (!admin) return res.status(404).json({ error: 'Admin not found' });

    // Generate access token (1 jam)
    const accessToken = signJwt(admin.id, 'ADMIN');

    // Generate refresh token (12 jam)
    const refreshToken = generateRefreshToken();
    await redis.set(`admin:refresh:${admin.id}`, refreshToken, { EX: 12 * 60 * 60 }); // 12 jam

    // Set cookies
    res.cookie('accessToken', accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 1000 * 60 * 60, // 1 jam
    });
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 12 * 60 * 60 * 1000, // 12 jam
    });

    // Hapus temporary OTP session
    await redis.del(`admin:login:${email}`);

    return res.json({ message: 'Login successful', adminId: admin.id, role: admin.role });
  } catch (err) {
    console.error('adminLoginVerify error:', err);
    return res.status(500).json({ error: 'Admin login verification failed' });
  }
};

// ── REFRESH ACCESS TOKEN ADMIN (PERBARUI SETIAP 30 MENIT) ─────────
export const adminRefreshAccessToken = async (req: Request, res: Response) => {
  try {
    const { refreshToken } = req.cookies;
    if (!refreshToken) return res.status(401).json({ error: 'No refresh token provided' });

    // Cari adminId di Redis
    const keys = await redis.keys('admin:refresh:*');
    let adminId: string | null = null;
    for (const key of keys) {
      const token = await redis.get(key);
      if (token === refreshToken) {
        adminId = key.split(':')[2]; // format key: admin:refresh:<adminId>
        break;
      }
    }
    if (!adminId) return res.status(401).json({ error: 'Invalid or expired refresh token' });

    // Generate access token baru
    const newAccessToken = signJwt(adminId, 'ADMIN');

    // Refresh token diperbarui setiap 30 menit
    const newRefreshToken = generateRefreshToken();
    await redis.set(`admin:refresh:${adminId}`, newRefreshToken, { EX: 12 * 60 * 60 }); // 12 jam

    // Set cookies baru
    res.cookie('accessToken', newAccessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 1000 * 60 * 60,
    });
    res.cookie('refreshToken', newRefreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 12 * 60 * 60 * 1000,
    });

    return res.json({ message: 'Access token refreshed' });
  } catch (err) {
    console.error('adminRefreshAccessToken error:', err);
    return res.status(500).json({ error: 'Failed to refresh access token' });
  }
};

// ── LOGOUT ADMIN ─────────────
export const adminLogout = async (req: Request, res: Response) => {
  try {
    const { refreshToken } = req.cookies;
    if (refreshToken) {
      const keys = await redis.keys('admin:refresh:*');
      for (const key of keys) {
        const token = await redis.get(key);
        if (token === refreshToken) {
          await redis.del(key);
          break;
        }
      }
    }

    // Hapus cookies
    res.cookie('accessToken', '', { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'strict', expires: new Date(0) });
    res.cookie('refreshToken', '', { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'strict', expires: new Date(0) });

    return res.json({ message: 'Logout successful' });
  } catch (err) {
    console.error('adminLogout error:', err);
    return res.status(500).json({ error: 'Logout failed' });
  }
};



// // ── ADMIN FORGOT PASSWORD: Request OTP ─────────────
// ── ADMIN FORGOT PASSWORD: Request OTP ─────────────
export const adminForgotPasswordRequest = async (req: Request, res: Response) => {
  try {
    const parse = adminForgotPasswordRequestSchema.safeParse(req.body);
    if (!parse.success) {
      return res.status(400).json({ error: "Validation failed", details: parse.error.format() });
    }

    const { email } = parse.data;

    const admin = await prisma.admin.findUnique({ where: { email } });
    if (!admin) {
      return res.status(404).json({ error: "Admin not found" });
    }

    // Send OTP
    const otp = await requestOtp(email);
    if (!otp.success) {
      return res.status(429).json({ error: otp.message });
    }

    return res.json({ message: "OTP sent to your email" });
  } catch (err) {
    console.error("adminForgotPasswordRequest error:", err);
    return res.status(500).json({ error: "Failed to request password reset" });
  }
};

// // ── ADMIN FORGOT PASSWORD: Verify OTP & Set New Password ─────────────
export const adminForgotPasswordVerify = async (req: Request, res: Response) => {
  try {
    const parse = adminForgotPasswordVerifySchema.safeParse(req.body);
    if (!parse.success) {
      return res.status(400).json({ error: "Validation failed", details: parse.error.format() });
    }

    const { email, otp, newPassword } = parse.data;

    // Verify OTP
    const otpCheck = await verifyOtp(email, otp);
    if (!otpCheck.success) {
      return res.status(400).json({ error: otpCheck.message });
    }

    const hashed = await hashPassword(newPassword);

    await prisma.admin.update({
      where: { email },
      data: { password: hashed },
    });

    return res.json({ message: "Password updated successfully" });
  } catch (err) {
    console.error("adminForgotPasswordVerify error:", err);
    return res.status(500).json({ error: "Failed to reset password" });
  }
};


const hashToken = (token: string) => crypto.createHash('sha256').update(token).digest('hex');
 

// ── REFRESH ACCESS TOKEN ADMIN ─────────────
export const RefreshAccessToken = async (req: Request, res: Response) => {
  try {
    const { refreshToken } = req.cookies;
    if (!refreshToken) return res.status(401).json({ error: 'No refresh token provided' });

    const hashedToken = hashToken(refreshToken);

    // Lookup token di Redis
    const adminId = await redis.get(`admin:refresh:${hashedToken}`);
    if (!adminId) return res.status(401).json({ error: 'Invalid or expired refresh token' });

    // Generate access token baru
    const newAccessToken = signJwt(adminId, 'ADMIN');

    // Optionally: rotate refresh token (untuk keamanan)
    const newRefreshToken = generateRefreshToken();
    const newHashedToken = hashToken(newRefreshToken);

    // Simpan token baru di Redis, hapus token lama
    await redis.set(`admin:refresh:${newHashedToken}`, adminId, { EX: 12 * 60 * 60 }); // 12 jam
    await redis.del(`admin:refresh:${hashedToken}`);

    // Set cookies baru
    res.cookie('accessToken', newAccessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 1000 * 60 * 60, // 1 jam
    });
    res.cookie('refreshToken', newRefreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 12 * 60 * 60 * 1000, // 12 jam
    });

    return res.json({ message: 'Access token refreshed' });
  } catch (err) {
    console.error('adminRefreshAccessToken error:', err);
    return res.status(500).json({ error: 'Failed to refresh access token' });
  }
};

// ── LOGOUT ADMIN ─────────────
export const Logout = async (req: Request, res: Response) => {
  try {
    const { refreshToken } = req.cookies;
    if (refreshToken) {
      const hashedToken = hashToken(refreshToken);
      await redis.del(`admin:refresh:${hashedToken}`);
    }

    // Hapus cookies
    res.cookie('accessToken', '', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      expires: new Date(0),
    });
    res.cookie('refreshToken', '', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      expires: new Date(0),
    });

    return res.json({ message: 'Logout successful' });
  } catch (err) {
    console.error('adminLogout error:', err);
    return res.status(500).json({ error: 'Logout failed' });
  }
};

// ── SAVE REFRESH TOKEN SAAT LOGIN ─────────────
export const saveRefreshToken = async (adminId: string, refreshToken: string) => {
  const hashedToken = hashToken(refreshToken);
  await redis.set(`admin:refresh:${hashedToken}`, adminId, { EX: 12 * 60 * 60 }); // 12 jam
};




// ── GET CURRENT ADMIN PROFILE ─────────────
export const getAdminMe = async (req: Request, res: Response) => {
  try {
    if (!req.user || req.user.type !== 'ADMIN') {
      return res.status(401).json({ error: 'Unauthorized: Admin not authenticated' });
    }

    const admin = await prisma.admin.findUnique({
      where: { id: req.user.id },
      select: { id: true, email: true, role: true, createdAt: true, updatedAt: true },
    });

    if (!admin) return res.status(404).json({ error: 'Admin not found' });

    return res.json({ admin });
  } catch (err) {
    console.error('getAdminMe error:', err);
    return res.status(500).json({ error: 'Failed to fetch admin profile' });
  }
};
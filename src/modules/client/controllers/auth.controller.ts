import { Request, Response } from 'express';
import redis from '../../../core/db/redis';
import { prisma } from '../../../core/db/client';
import { hashPassword, comparePassword } from '../../../core/utils/bcrypt';
import { signJwt } from '../../../core/auth/jwt';
import { requestOtp, verifyOtp } from '../../../core/security/otp.service';
import {
  registerRequestSchema,
  registerCompleteSchema,
  loginRequestSchema,
  loginVerifySchema,
  forgotPasswordRequestSchema,
  forgotPasswordVerifySchema,
} from '../dto/auth.dto';
import crypto from 'crypto';


// ── REGISTER: Tahap 1 — Request OTP ───────────────────────
export const requestRegisterOtp = async (req: Request, res: Response) => {
  try {
    const result = registerRequestSchema.safeParse(req.body);
    if (!result.success) {
      return res.status(400).json({
        error: 'Validation failed',
        details: result.error.format(),
      });
    }

    const { email, password } = result.data;

    // Cek email sudah ada
    const existing = await prisma.client.findUnique({ where: { email } });
    if (existing) return res.status(400).json({ error: 'Email already registered' });

    const hashedPassword = await hashPassword(password);

    // Simpan sementara di Redis dengan key berdasarkan email
    await redis.set(
      `register:${email}`,
      JSON.stringify({ hashedPassword }),
      { EX: 300 } // 5 menit
    );

    // Kirim OTP
    const otpResult = await requestOtp(email);
    if (!otpResult.success) {
      await redis.del(`register:${email}`);
      return res.status(429).json({ error: otpResult.message });
    }

    return res.json({ message: 'OTP sent to your email' });
  } catch (error: any) {
    console.error('requestRegisterOtp error:', error);
    return res.status(500).json({ error: 'Failed to process registration' });
  }
};

// ── REGISTER: Tahap 2 — Verifikasi OTP & Buat Akun ────────
export const completeRegister = async (req: Request, res: Response) => {
  try {
    const result = registerCompleteSchema.safeParse(req.body);
    if (!result.success) {
      return res.status(400).json({
        error: 'Validation failed',
        details: result.error.format(),
      });
    }

    const { email, otp } = result.data;

    // Ambil data sementara dari Redis
    const tempDataStr = await redis.get(`register:${email}`);
    if (!tempDataStr) return res.status(400).json({ error: 'Registration session expired' });

    const { hashedPassword } = JSON.parse(tempDataStr);

    // Verifikasi OTP
    const otpResult = await verifyOtp(email, otp);
    if (!otpResult.success) return res.status(400).json({ error: otpResult.message });

    // Race condition check
    const existing = await prisma.client.findUnique({ where: { email } });
    if (existing) {
      await redis.del(`register:${email}`);
      return res.status(400).json({ error: 'Email already registered' });
    }

    // Buat user baru
    const client = await prisma.client.create({
      data: { email, password: hashedPassword },
    });

    // Hapus data sementara dari Redis
    await redis.del(`register:${email}`);

    // Generate JWT HttpOnly cookie (opsional login otomatis)
    const token = signJwt(client.id, 'CLIENT');
    res.cookie('accessToken', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 1000 * 60 * 60, // 1 jam
    });

    return res.status(201).json({
      message: 'Registration successful',
      clientId: client.id,
    });
  } catch (error: any) {
    console.error('completeRegister error:', error);
    if (error.code === 'P2002') return res.status(400).json({ error: 'Email already exists' });
    return res.status(500).json({ error: 'Registration failed' });
  }
};

// ── LOGIN: Step 1 - Request OTP ───────────────────────

export const loginClient = async (req: Request, res: Response) => {
  try {
    const result = loginRequestSchema.safeParse(req.body);
    if (!result.success) {
      return res.status(400).json({ error: 'Validation failed', details: result.error.format() });
    }

    const { email, password } = result.data;

    // Cari user
    const client = await prisma.client.findUnique({ where: { email } });
    if (!client) return res.status(400).json({ error: 'Email or password incorrect' });

    // Cek password
    const valid = await comparePassword(password, client.password);
    if (!valid) return res.status(400).json({ error: 'Email or password incorrect' });

    // Kirim OTP
    const otpResult = await requestOtp(email);
    if (!otpResult.success) return res.status(429).json({ error: otpResult.message });

    return res.json({ message: 'OTP sent to your email' });
  } catch (err: any) {
    console.error('loginClient error:', err);
    return res.status(500).json({ error: 'Login failed' });
  }
};


// ── GENERATE REFRESH TOKEN ─────────────
export const generateRefreshToken = (): string => {
  return crypto.randomBytes(64).toString('hex'); // token 128 karakter
};

// ── LOGIN VERIFY (update) ──────────────
export const loginVerify = async (req: Request, res: Response) => {
  try {
    const result = loginVerifySchema.safeParse(req.body);
    if (!result.success) return res.status(400).json({ error: 'Validation failed', details: result.error.format() });

    const { email, otp } = result.data;
    const otpResult = await verifyOtp(email, otp);
    if (!otpResult.success) return res.status(400).json({ error: otpResult.message });

    const client = await prisma.client.findUnique({ where: { email } });
    if (!client) return res.status(404).json({ error: 'User not found' });

    // Access token (1h)
    const accessToken = signJwt(client.id, 'CLIENT');

    // Refresh token (7 days)
    const refreshToken = generateRefreshToken();
    await redis.set(`refresh:${client.id}`, refreshToken, { EX: 7 * 24 * 60 * 60 });

    // Set cookies
    res.cookie('accessToken', accessToken, { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'strict', maxAge: 1000 * 60 * 60 });
    res.cookie('refreshToken', refreshToken, { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'strict', maxAge: 7 * 24 * 60 * 60 * 1000 });

    return res.json({ message: 'Login successful', clientId: client.id });
  } catch (err) {
    console.error('loginVerify error:', err);
    return res.status(500).json({ error: 'Login verification failed' });
  }
};


// ── FORGOT PASSWORD: Request OTP ─────────────
export const forgotPasswordRequest = async (req: Request, res: Response) => {
  try {
    const result = forgotPasswordRequestSchema.safeParse(req.body);
    if (!result.success) return res.status(400).json({ error: 'Validation failed', details: result.error.format() });

    const { email } = result.data;

    const client = await prisma.client.findUnique({ where: { email } });
    if (!client) return res.status(404).json({ error: 'Client not found' });

    // Kirim OTP ke email
    const otpResult = await requestOtp(email);
    if (!otpResult.success) return res.status(429).json({ error: otpResult.message });

    // Simpan session OTP sementara di Redis
    await redis.set(`forgot:${email}`, 'pending', { EX: 300 }); // 5 menit

    return res.json({ message: 'OTP sent to your email' });
  } catch (err) {
    console.error('forgotPasswordRequest error:', err);
    return res.status(500).json({ error: 'Failed to send OTP' });
  }
};

// ── FORGOT PASSWORD: Verify OTP & Set New Password ─────────────
export const forgotPasswordVerify = async (req: Request, res: Response) => {
  try {
    const result = forgotPasswordVerifySchema.safeParse(req.body);
    if (!result.success) return res.status(400).json({ error: 'Validation failed', details: result.error.format() });

    const { email, otp, newPassword } = result.data;

    const temp = await redis.get(`forgot:${email}`);
    if (!temp) return res.status(400).json({ error: 'OTP session expired or invalid' });

    const otpResult = await verifyOtp(email, otp);
    if (!otpResult.success) return res.status(400).json({ error: otpResult.message });

    const hashed = await hashPassword(newPassword);

    // Update password client
    await prisma.client.update({
      where: { email },
      data: { password: hashed },
    });

    // Hapus session OTP
    await redis.del(`forgot:${email}`);

    return res.json({ message: 'Password updated successfully' });
  } catch (err) {
    console.error('forgotPasswordVerify error:', err);
    return res.status(500).json({ error: 'Failed to reset password' });
  }
};


const hashToken = (token: string) => crypto.createHash('sha256').update(token).digest('hex');


// ── REFRESH ACCESS TOKEN ─────────────
export const refreshAccessToken = async (req: Request, res: Response) => {
  try {
    const { refreshToken } = req.cookies;
    if (!refreshToken) return res.status(401).json({ error: 'No refresh token provided' });

    const hashedToken = hashToken(refreshToken);

    // Lookup token di Redis
    const clientId = await redis.get(`refresh:${hashedToken}`);
    if (!clientId) return res.status(401).json({ error: 'Invalid or expired refresh token' });

    // Generate access token baru
    const newAccessToken = signJwt(clientId, 'CLIENT');

    // Rotate refresh token (opsional tapi lebih aman)
    const newRefreshToken = generateRefreshToken();
    const newHashedToken = hashToken(newRefreshToken);

    // Simpan token baru, hapus token lama
    await redis.set(`refresh:${newHashedToken}`, clientId, { EX: 12 * 60 * 60 }); // 12 jam
    await redis.del(`refresh:${hashedToken}`);

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
    console.error('refreshAccessToken error:', err);
    return res.status(500).json({ error: 'Failed to refresh access token' });
  }
};

// ── LOGOUT ─────────────
export const logout = async (req: Request, res: Response) => {
  try {
    const { refreshToken } = req.cookies;
    if (refreshToken) {
      const hashedToken = hashToken(refreshToken);
      await redis.del(`refresh:${hashedToken}`);
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
    console.error('logout error:', err);
    return res.status(500).json({ error: 'Logout failed' });
  }
};

// ── SAVE REFRESH TOKEN SAAT LOGIN ─────────────
export const saveRefreshToken = async (clientId: string, refreshToken: string) => {
  const hashedToken = hashToken(refreshToken);
  await redis.set(`refresh:${hashedToken}`, clientId, { EX: 12 * 60 * 60 }); // 12 jam
};



// ── GET CURRENT CLIENT PROFILE ─────────────
export const getClientMe = async (req: Request, res: Response) => {
  try {
    if (!req.user || req.user.type !== 'CLIENT') {
      return res.status(401).json({ error: 'Unauthorized: Client not authenticated' });
    }

    const client = await prisma.client.findUnique({
      where: { id: req.user.id },
      select: { id: true, email: true, createdAt: true, updatedAt: true },
    });

    if (!client) return res.status(404).json({ error: 'Client not found' });

    return res.json({ client });
  } catch (err) {
    console.error('getClientMe error:', err);
    return res.status(500).json({ error: 'Failed to fetch client profile' });
  }
};
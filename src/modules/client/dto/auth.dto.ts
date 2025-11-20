import { z } from 'zod';

const emailTransform = (val: string) => val.trim().toLowerCase();
const stringTrim = (val: string) => val.trim();


// Register: Tahap 1 - Request OTP
export const registerRequestSchema = z.object({
  email: z.string().email({ message: 'Invalid email format' }).transform(emailTransform),
  password: z
    .string()
    .min(8, { message: 'Password must be at least 8 characters' })
    .regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/, {
      message: 'Password must contain uppercase, lowercase, and number',
    })
    .transform(stringTrim),
});

// Register: Tahap 2 - Complete registration (email + OTP)
export const registerCompleteSchema = z.object({
  email: z.string().email({ message: 'Invalid email format' }).transform(emailTransform),
  otp: z
    .string()
    .length(6, { message: 'OTP must be 6 digits' })
    .regex(/^\d+$/, { message: 'OTP must be numeric' })
    .transform(stringTrim),
});

// login: Tahap 1 - Request login
export const loginRequestSchema = z.object({
  email: z.string().email({ message: 'Invalid email format' }).transform(emailTransform),
  password: z.string().min(8, { message: 'Password must be at least 8 characters' }).transform(stringTrim),
});

// Login verification (OTP)
export const loginVerifySchema = z.object({
  email: z.string().email({ message: 'Invalid email format' }).transform(emailTransform),
  otp: z
    .string()
    .length(6, { message: 'OTP must be 6 digits' })
    .regex(/^\d+$/, { message: 'OTP must be numeric' })
    .transform(stringTrim),
});



// ── CLIENT FORGOT PASSWORD ───────────────
export const forgotPasswordRequestSchema = z.object({
  email: z.string().email({ message: 'Email tidak valid' }).transform(emailTransform),
});

// ── CLIENT FORGOT PASSWOR 2 ────────────────
export const resetPasswordSchema = z.object({
  email: z.string().email({ message: 'Email tidak valid' }).transform(emailTransform),
  otp: z.string().length(6, { message: 'OTP harus 6 digit' }).transform(stringTrim),
  newPassword: z
    .string()
    .min(8, { message: 'Password minimal 8 karakter' })
    .regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/, {
      message: 'Password harus mengandung uppercase, lowercase, dan angka',
    })
    .transform(stringTrim),
});


// =================== CLIENT FORGOT PASSWORD DTOs ===================
// Step 1: Request password reset (email)
export const forgotPasswordSchema = z.object({
  email: z.string().email({ message: 'Invalid email format' }).transform(emailTransform),
});

// Step 2: Verify OTP & set new password
export const forgotPasswordVerifySchema = z.object({
  email: z.string().email({ message: 'Invalid email format' }).transform(emailTransform),
  otp: z
    .string()
    .length(6, { message: 'OTP must be 6 digits' })
    .regex(/^\d+$/, { message: 'OTP must be numeric' })
    .transform(stringTrim),
  newPassword: z
    .string()
    .min(8, { message: 'Password must be at least 8 characters' })
    .regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/, {
      message: 'Password must contain uppercase, lowercase, and number',
    })
    .transform(stringTrim),
});






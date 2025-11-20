import { z } from 'zod';

const emailTransform = (val: string) => val.trim().toLowerCase();
const stringTrim = (val: string) => val.trim();


// Admin Login
// Admin login: step 1 (password → OTP)
export const adminLoginRequestSchema = z.object({
  email: z.string().email({ message: 'Invalid email format' }).transform(emailTransform),
  password: z.string().min(8, { message: 'Password must be at least 8 characters' }).transform(stringTrim),
});

// Admin login: step 2 (verify OTP)
export const adminLoginVerifySchema = z.object({
  email: z.string().email({ message: 'Invalid email format' }).transform(emailTransform),
  otp: z
    .string()
    .length(6, { message: 'OTP must be 6 digits' })
    .regex(/^\d+$/, { message: 'OTP must be numeric' })
    .transform(stringTrim),
});

// Admin Forgot Password
// Step 1: Request password reset (email)
export const adminForgotPasswordRequestSchema = z.object({
  email: z
    .string()
    .email({ message: "Invalid email format" })
    .transform((val) => val.trim().toLowerCase()),
});

// Step 2: Verify OTP & set new password
export const adminForgotPasswordVerifySchema = z.object({
  email: z
    .string()
    .email({ message: "Invalid email format" })
    .transform((val) => val.trim().toLowerCase()),

  otp: z
    .string()
    .length(6, { message: "OTP must be 6 digits" })
    .regex(/^\d+$/, "OTP must be numeric"),

  newPassword: z
    .string()
    .min(8, "Password must be at least 8 characters")
    .regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/, {
      message: "Password must contain uppercase, lowercase, and number",
    })
    .transform((val) => val.trim()),
});



import redis from '../db/redis';
import { hashOtp, generateOtp } from '../utils/otp';
import { comparePassword } from '../utils/bcrypt';
import { sendOtpEmail } from '../utils/email';

const OTP_TTL = 5 * 60;    // 5 menit
const OTP_COOLDOWN = 60;   // 60 detik
const MAX_ATTEMPTS = 3;

const getOtpKey = (email: string) => `otp:${email}`;
const getAttemptsKey = (email: string) => `otp:attempts:${email}`;
const getCooldownKey = (email: string) => `otp:cooldown:${email}`;

export const requestOtp = async (email: string) => {
  const cooldownKey = getCooldownKey(email);
  const cooldownEnd = await redis.get(cooldownKey);

  if (cooldownEnd) {
    const waitMs = parseInt(cooldownEnd) - Date.now();
    if (waitMs > 0) {
      return { success: false, message: `Try again in ${Math.ceil(waitMs / 1000)}s` };
    }
  }

  const otp = generateOtp();
  const hash = await hashOtp(otp);

  await redis.set(getOtpKey(email), hash, { EX: OTP_TTL });
  await redis.set(cooldownKey, (Date.now() + OTP_COOLDOWN * 1000).toString(), { EX: OTP_COOLDOWN });

  await sendOtpEmail(email, otp);
  return { success: true };
};

export const verifyOtp = async (email: string, inputOtp: string) => {
  const otpKey = getOtpKey(email);
  const hash = await redis.get(otpKey);

  if (!hash) return { success: false, message: 'OTP expired or not requested' };

  const attemptsKey = getAttemptsKey(email);
  const attempts = parseInt(await redis.get(attemptsKey) || '0', 10);

  if (attempts >= MAX_ATTEMPTS) {
    await redis.del([otpKey, attemptsKey, getCooldownKey(email)]);
    return { success: false, message: 'Too many OTP attempts. Request a new one.' };
  }

  const isValid = await comparePassword(inputOtp, hash);
  if (!isValid) {
    await redis.set(attemptsKey, (attempts + 1).toString(), { EX: OTP_TTL });
    const remaining = MAX_ATTEMPTS - (attempts + 1);
    return { success: false, message: `Invalid OTP. ${remaining > 0 ? `${remaining} attempts left.` : 'No attempts left.'}` };
  }

  await redis.del([otpKey, attemptsKey, getCooldownKey(email)]);
  return { success: true };
};

import crypto from 'crypto';
import { hashPassword } from './bcrypt';

export const generateOtp = () => Math.floor(100000 + Math.random() * 900000).toString();
export const hashOtp = (otp: string) => hashPassword(otp); // pakai bcrypt juga
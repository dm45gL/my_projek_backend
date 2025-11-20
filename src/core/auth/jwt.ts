import jwt, { SignOptions, JwtPayload } from 'jsonwebtoken';
import dotenv from 'dotenv';

dotenv.config();

const PRIVATE_KEY = process.env.JWT_PRIVATE_KEY!;
const PUBLIC_KEY = process.env.JWT_PUBLIC_KEY!;
const JWT_ALG = 'ES256';
const JWT_EXPIRES_IN = '1h'; 

export interface JwtSignPayload extends JwtPayload {
  sub: string;          
  type: 'ADMIN' | 'CLIENT';
}

// Sign JWT dengan sub (id) dan type (role)
export const signJwt = (sub: string, type: 'ADMIN' | 'CLIENT', options?: SignOptions) => {
  const payload: JwtSignPayload = { sub, type };
  return jwt.sign(payload, PRIVATE_KEY, { algorithm: JWT_ALG, expiresIn: JWT_EXPIRES_IN, ...options });
};

// Verify JWT menggunakan public key
export const verifyJwt = (token: string): JwtSignPayload | null => {
  try {
    return jwt.verify(token, PUBLIC_KEY, { algorithms: [JWT_ALG] }) as JwtSignPayload;
  } catch (err) {
    console.error('JWT verification failed:', err);
    return null;
  }
};

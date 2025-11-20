// src/core/jobs/cleanup-tokens.ts
import { prisma } from '../db/client';

export const cleanupExpiredTokens = async () => {
  const deleted = await prisma.refreshToken.deleteMany({
    where: { expiresAt: { lt: new Date() } },
  });
  console.log(`🧹 Cleaned up ${deleted.count} expired refresh tokens`);
};
// src/server.ts
import 'dotenv/config'; // ✅ harus paling atas
import http from 'http';
import app from './app'; // app Express sudah di-setup di src/app.ts
import { connectRedis } from './core/db/redis';
import { prisma } from './core/db/client';

const startServer = async () => {
  try {
    // ✅ Pastikan Redis terhubung sebelum server jalan
    await connectRedis();

    const PORT = Number(process.env.PORT) || 3000;
    const server = http.createServer(app);

    // ── Graceful shutdown ─────────────
    const shutdown = async () => {
      console.log('\nShutting down...');
      server.close(async () => {
        try {
          await prisma.$disconnect();
          console.log('Database disconnected.');
          process.exit(0);
        } catch (err) {
          console.error('Error during shutdown:', err);
          process.exit(1);
        }
      });
    };

    process.on('SIGTERM', shutdown);
    process.on('SIGINT', shutdown);

    // ── Start server ─────────────
    server.listen(PORT, () => {
      console.log(`✅ Server running at http://localhost:${PORT}`);
    });

  } catch (err) {
    console.error('❌ Server failed to start:', err);
    process.exit(1);
  }
};

startServer();

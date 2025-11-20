import { createClient, RedisClientOptions } from 'redis';

const redisOptions: RedisClientOptions = {
  socket: {
    host: process.env.REDIS_HOST || '127.0.0.1',
    port: parseInt(process.env.REDIS_PORT || '6379', 10),
  },
  ...(process.env.REDIS_PASSWORD ? { password: process.env.REDIS_PASSWORD } : {}),
};

const redis = createClient(redisOptions);

redis.on('error', (err) => console.error('❌ Redis Client Error:', err.message));

export const connectRedis = async () => {
  if (!redis.isOpen) {
    console.log('🔌 Connecting to Redis...');
    await redis.connect();
    console.log('✅ Connected to Redis');
  }
};

export default redis;

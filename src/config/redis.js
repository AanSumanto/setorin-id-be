import { createClient } from "redis";
import { createLogger } from "../utils/logger.js";

const logger = createLogger("Redis");

class RedisConnection {
  constructor() {
    this.client = null;
    this.isConnected = false;
    this.retryCount = 0;
    this.maxRetries = 5;
    this.retryDelay = 3000; // 3 seconds
  }

  async connect() {
    if (this.isConnected && this.client) {
      logger.info("Redis already connected");
      return this.client;
    }

    const redisConfig = {
      host: process.env.REDIS_HOST || "localhost",
      port: process.env.REDIS_PORT || 6379,
      db: process.env.REDIS_DB || 0,
      retryDelayOnFailover: 100,
      enableReadyCheck: false,
      maxRetriesPerRequest: null,
    };

    // Add password if provided
    if (process.env.REDIS_PASSWORD) {
      redisConfig.password = process.env.REDIS_PASSWORD;
    }

    try {
      this.client = createClient({
        socket: {
          host: redisConfig.host,
          port: redisConfig.port,
        },
        password: redisConfig.password,
        database: redisConfig.db,
      });

      // Event listeners
      this.setupEventListeners();

      // Connect
      await this.client.connect();

      this.isConnected = true;
      this.retryCount = 0;

      logger.info(
        `Redis connected successfully to ${redisConfig.host}:${redisConfig.port}`
      );

      return this.client;
    } catch (error) {
      logger.error("Redis connection error:", error.message);
      await this.handleConnectionError();
    }
  }

  setupEventListeners() {
    this.client.on("connect", () => {
      logger.info("Redis client connected");
    });

    this.client.on("ready", () => {
      logger.info("Redis client ready");
      this.isConnected = true;
    });

    this.client.on("error", (error) => {
      logger.error("Redis client error:", error.message);
      this.isConnected = false;
    });

    this.client.on("end", () => {
      logger.warn("Redis client connection ended");
      this.isConnected = false;
    });

    this.client.on("reconnecting", () => {
      logger.info("Redis client reconnecting...");
    });
  }

  async handleConnectionError() {
    if (this.retryCount < this.maxRetries) {
      this.retryCount++;
      logger.info(
        `Retrying Redis connection... Attempt ${this.retryCount}/${this.maxRetries}`
      );

      await new Promise((resolve) => setTimeout(resolve, this.retryDelay));
      await this.connect();
    } else {
      logger.error(
        "Redis: Maximum retry attempts reached. Continuing without Redis..."
      );
      // Don't exit process, continue without Redis
      this.client = null;
      this.isConnected = false;
    }
  }

  async disconnect() {
    if (!this.client || !this.isConnected) return;

    try {
      await this.client.quit();
      this.isConnected = false;
      logger.info("Redis connection closed successfully");
    } catch (error) {
      logger.error("Error closing Redis connection:", error.message);
    }
  }

  // Cache helper methods
  async set(key, value, expireInSeconds = 3600) {
    if (!this.isConnected) return null;

    try {
      const serializedValue = JSON.stringify(value);
      await this.client.setEx(key, expireInSeconds, serializedValue);
      return true;
    } catch (error) {
      logger.error("Redis SET error:", error.message);
      return null;
    }
  }

  async get(key) {
    if (!this.isConnected) return null;

    try {
      const value = await this.client.get(key);
      return value ? JSON.parse(value) : null;
    } catch (error) {
      logger.error("Redis GET error:", error.message);
      return null;
    }
  }

  async del(key) {
    if (!this.isConnected) return null;

    try {
      return await this.client.del(key);
    } catch (error) {
      logger.error("Redis DEL error:", error.message);
      return null;
    }
  }

  async exists(key) {
    if (!this.isConnected) return false;

    try {
      return await this.client.exists(key);
    } catch (error) {
      logger.error("Redis EXISTS error:", error.message);
      return false;
    }
  }

  getConnectionState() {
    return {
      isConnected: this.isConnected,
      client: !!this.client,
    };
  }
}

// Create singleton instance
const redisConnection = new RedisConnection();

export default redisConnection;

import mongoose from "mongoose";
import { createLogger } from "../utils/logger.js";

const logger = createLogger("Database");

class DatabaseConnection {
  constructor() {
    this.isConnected = false;
    this.retryCount = 0;
    this.maxRetries = 5;
    this.retryDelay = 5000; // 5 seconds
  }

  async connect() {
    if (this.isConnected) {
      logger.info("Database already connected");
      return;
    }

    const mongoUri =
      process.env.NODE_ENV === "test"
        ? process.env.MONGODB_TEST_URI
        : process.env.MONGODB_URI;

    const options = {
      maxPoolSize: 10,
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
      family: 4, // Use IPv4
      retryWrites: true,
      w: "majority",
    };

    try {
      await mongoose.connect(mongoUri, options);
      this.isConnected = true;
      this.retryCount = 0;

      logger.info(
        `MongoDB connected successfully to: ${mongoose.connection.host}`
      );

      // Event listeners
      this.setupEventListeners();
    } catch (error) {
      logger.error("MongoDB connection error:", error.message);
      await this.handleConnectionError();
    }
  }

  setupEventListeners() {
    mongoose.connection.on("connected", () => {
      logger.info("Mongoose connected to MongoDB");
    });

    mongoose.connection.on("error", (error) => {
      logger.error("Mongoose connection error:", error);
      this.isConnected = false;
    });

    mongoose.connection.on("disconnected", () => {
      logger.warn("Mongoose disconnected from MongoDB");
      this.isConnected = false;
    });

    // Graceful shutdown
    process.on("SIGINT", async () => {
      await this.disconnect();
      process.exit(0);
    });
  }

  async handleConnectionError() {
    if (this.retryCount < this.maxRetries) {
      this.retryCount++;
      logger.info(
        `Retrying database connection... Attempt ${this.retryCount}/${this.maxRetries}`
      );

      await new Promise((resolve) => setTimeout(resolve, this.retryDelay));
      await this.connect();
    } else {
      logger.error("Maximum retry attempts reached. Exiting...");
      process.exit(1);
    }
  }

  async disconnect() {
    if (!this.isConnected) return;

    try {
      await mongoose.connection.close();
      this.isConnected = false;
      logger.info("Database connection closed successfully");
    } catch (error) {
      logger.error("Error closing database connection:", error.message);
    }
  }

  getConnectionState() {
    return {
      isConnected: this.isConnected,
      readyState: mongoose.connection.readyState,
      host: mongoose.connection.host,
      name: mongoose.connection.name,
    };
  }
}

// Create singleton instance
const dbConnection = new DatabaseConnection();

export default dbConnection;

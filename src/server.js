import "dotenv/config";
import App from "./app.js";
import { createLogger } from "./utils/logger.js";

const logger = createLogger("Server");

class Server {
  constructor() {
    this.app = new App();
    this.port = process.env.PORT || 3000;
    this.server = null;
  }

  async start() {
    try {
      // Initialize all connections (DB, Redis, etc.)
      await this.app.initializeConnections();

      // Start the server
      this.server = this.app.getApp().listen(this.port, () => {
        logger.info(
          `🚀 Server running in ${process.env.NODE_ENV} mode on port ${this.port}`
        );
        logger.info(`📱 API URL: http://localhost:${this.port}/api`);
        logger.info(`🏥 Health Check: http://localhost:${this.port}/health`);
      });

      this.setupGracefulShutdown();
    } catch (error) {
      logger.error("❌ Failed to start server:", error);
      process.exit(1);
    }
  }

  setupGracefulShutdown() {
    const gracefulShutdown = async (signal) => {
      logger.info(`📴 Received ${signal}. Starting graceful shutdown...`);

      if (this.server) {
        this.server.close(async () => {
          logger.info("🔒 HTTP server closed");

          try {
            await this.app.close();
            logger.info("✅ Graceful shutdown completed");
            process.exit(0);
          } catch (error) {
            logger.error("❌ Error during graceful shutdown:", error);
            process.exit(1);
          }
        });

        // Force close server after 30s
        setTimeout(() => {
          logger.error(
            "⚠️ Could not close connections in time, forcefully shutting down"
          );
          process.exit(1);
        }, 30000);
      }
    };

    // Listen for termination signals
    process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));
    process.on("SIGINT", () => gracefulShutdown("SIGINT"));

    // Handle uncaught exceptions
    process.on("uncaughtException", (error) => {
      logger.error("💥 Uncaught Exception:", error);
      gracefulShutdown("uncaughtException");
    });

    // Handle unhandled promise rejections
    process.on("unhandledRejection", (reason, promise) => {
      logger.error("💥 Unhandled Rejection at:", promise, "reason:", reason);
      gracefulShutdown("unhandledRejection");
    });
  }
}

// Start the server
const server = new Server();
server.start();

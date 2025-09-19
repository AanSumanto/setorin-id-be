import express from "express";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";
import compression from "compression";
import rateLimit from "express-rate-limit";

// Import configurations
import dbConnection from "./config/database.js";
import redisConnection from "./config/redis.js";
import { createLogger } from "./utils/logger.js";

// Import middlewares
import { errorHandler, notFound } from "./middlewares/errorMiddleware.js";
import { requestLogger } from "./middlewares/loggerMiddleware.js";
import {
  multilingualResponse,
  translationHelpers,
  multilingualErrorHandler,
} from "./middlewares/responseMiddleware.js";

// Import routes
import authRoutes from "./routes/authRoutes.js";
// import userRoutes from './src/routes/userRoutes.js';
// import productRoutes from './src/routes/productRoutes.js';
// import orderRoutes from './src/routes/orderRoutes.js';
// import ratingRoutes from './src/routes/ratingRoutes.js';
// import pointRoutes from './src/routes/pointRoutes.js';

const logger = createLogger("App");

class App {
  constructor() {
    this.app = express();
    this.setupMiddlewares();
    this.setupRoutes();
    this.setupErrorHandling();
  }

  setupMiddlewares() {
    // Security middleware
    this.app.use(
      helmet({
        contentSecurityPolicy: {
          directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'"],
            imgSrc: ["'self'", "data:", "https:"],
          },
        },
        crossOriginEmbedderPolicy: false,
      })
    );

    // CORS configuration
    this.app.use(
      cors({
        origin:
          process.env.NODE_ENV === "production"
            ? ["https://yourdomain.com"]
            : ["http://localhost:3000", "http://localhost:3001"],
        credentials: true,
        methods: ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
        allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With"],
      })
    );

    // Rate limiting
    const limiter = rateLimit({
      windowMs: process.env.RATE_LIMIT_WINDOW_MS || 15 * 60 * 1000, // 15 minutes
      max: process.env.RATE_LIMIT_MAX_REQUESTS || 100, // limit each IP to 100 requests per windowMs
      message: {
        error: "Too many requests from this IP, please try again later.",
        retryAfter: Math.ceil(
          (process.env.RATE_LIMIT_WINDOW_MS || 900000) / 1000
        ),
      },
      standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
      legacyHeaders: false, // Disable the `X-RateLimit-*` headers
    });
    this.app.use("/api", limiter);

    // Body parsing middleware
    this.app.use(
      express.json({
        limit: "10mb",
        type: "application/json",
      })
    );
    this.app.use(
      express.urlencoded({
        extended: true,
        limit: "10mb",
      })
    );

    // Compression middleware
    this.app.use(compression());

    // Logging middleware
    if (process.env.NODE_ENV === "development") {
      this.app.use(morgan("dev"));
    } else {
      this.app.use(morgan("combined"));
    }
    this.app.use(requestLogger);

    // Multilingual response middleware
    this.app.use(multilingualResponse);
    this.app.use(translationHelpers);

    // Trust proxy (important for rate limiting behind reverse proxy)
    this.app.set("trust proxy", 1);
  }

  setupRoutes() {
    // Health check endpoint
    this.app.get("/health", (req, res) => {
      const dbState = dbConnection.getConnectionState();
      const redisState = redisConnection.getConnectionState();

      res.status(200).json({
        status: "OK",
        timestamp: new Date().toISOString(),
        uptime: Math.floor(process.uptime()),
        environment: process.env.NODE_ENV,
        version: process.env.npm_package_version || "1.0.0",
        database: {
          connected: dbState.isConnected,
          readyState: dbState.readyState,
        },
        redis: {
          connected: redisState.isConnected,
        },
      });
    });

    // API base route
    this.app.get("/api", (req, res) => {
      res.json({
        message: "Setorin Waste Management API",
        version: process.env.npm_package_version || "1.0.0",
        environment: process.env.NODE_ENV,
        timestamp: new Date().toISOString(),
      });
    });

    // API Routes
    this.app.use("/api/auth", authRoutes);
    // this.app.use('/api/users', userRoutes);
    // this.app.use('/api/products', productRoutes);
    // this.app.use('/api/orders', orderRoutes);
    // this.app.use('/api/ratings', ratingRoutes);
    // this.app.use('/api/points', pointRoutes);
  }

  setupErrorHandling() {
    // 404 handler
    this.app.use(notFound);

    // Multilingual error handler
    this.app.use(multilingualErrorHandler);

    // Global error handler (fallback)
    this.app.use(errorHandler);
  }

  getApp() {
    return this.app;
  }

  async initializeConnections() {
    try {
      // Initialize database connection
      await dbConnection.connect();

      // Initialize Redis connection
      await redisConnection.connect();

      logger.info("All connections initialized successfully");
    } catch (error) {
      logger.error("Failed to initialize connections:", error);
      throw error;
    }
  }

  async close() {
    try {
      await dbConnection.disconnect();
      await redisConnection.disconnect();
      logger.info("Application connections closed successfully");
    } catch (error) {
      logger.error("Error closing application connections:", error);
    }
  }
}

export default App;

import winston from "winston";
import path from "path";

const { combine, timestamp, errors, json, printf, colorize, label } =
  winston.format;

// Custom format for console output
const consoleFormat = printf(({ level, message, label, timestamp, stack }) => {
  return `${timestamp} [${label}] ${level}: ${stack || message}`;
});

// Create logs directory if it doesn't exist
const logsDir = path.join(process.cwd(), "logs");

// Base logger configuration
const createLogger = (service = "App") => {
  return winston.createLogger({
    level: process.env.NODE_ENV === "development" ? "debug" : "info",
    format: combine(
      label({ label: service }),
      timestamp({ format: "YYYY-MM-DD HH:mm:ss" }),
      errors({ stack: true }),
      json()
    ),
    transports: [
      // Console transport
      new winston.transports.Console({
        format: combine(
          colorize(),
          label({ label: service }),
          timestamp({ format: "HH:mm:ss" }),
          consoleFormat
        ),
      }),

      // File transport for errors
      new winston.transports.File({
        filename: path.join(logsDir, "error.log"),
        level: "error",
        maxsize: 5242880, // 5MB
        maxFiles: 5,
      }),

      // File transport for all logs
      new winston.transports.File({
        filename: path.join(logsDir, "combined.log"),
        maxsize: 5242880, // 5MB
        maxFiles: 5,
      }),
    ],

    // Handle uncaught exceptions
    exceptionHandlers: [
      new winston.transports.File({
        filename: path.join(logsDir, "exceptions.log"),
      }),
    ],

    // Handle unhandled promise rejections
    rejectionHandlers: [
      new winston.transports.File({
        filename: path.join(logsDir, "rejections.log"),
      }),
    ],
  });
};

// Create default logger instance
const logger = createLogger();

export { createLogger };
export default logger;

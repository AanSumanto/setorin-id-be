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
      new winston.transports.Console({
        format: combine(
          colorize(),
          label({ label: service }),
          timestamp({ format: "HH:mm:ss" }),
          consoleFormat
        ),
      }),
      new winston.transports.File({
        filename: path.join(logsDir, "error.log"),
        level: "error",
        maxsize: 5242880,
        maxFiles: 5,
      }),
      new winston.transports.File({
        filename: path.join(logsDir, "combined.log"),
        maxsize: 5242880,
        maxFiles: 5,
      }),
    ],
  });
};

// Create default logger instance
const logger = createLogger();

export { createLogger };
export default logger;

import { createLogger } from "../utils/logger.js";

const logger = createLogger("RequestLogger");

export const requestLogger = (req, res, next) => {
  const start = Date.now();

  // Log request
  const requestInfo = {
    method: req.method,
    url: req.url,
    ip: req.ip,
    userAgent: req.get("User-Agent"),
    timestamp: new Date().toISOString(),
  };

  // Don't log sensitive data
  if (req.body && !req.url.includes("/auth/")) {
    requestInfo.body = req.body;
  }

  logger.info("Incoming request", requestInfo);

  // Override res.json to log response
  const originalJson = res.json;
  res.json = function (data) {
    const duration = Date.now() - start;

    // Log response
    logger.info("Outgoing response", {
      method: req.method,
      url: req.url,
      statusCode: res.statusCode,
      duration: `${duration}ms`,
      timestamp: new Date().toISOString(),
    });

    return originalJson.call(this, data);
  };

  next();
};

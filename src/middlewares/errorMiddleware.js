import { createLogger } from "../utils/logger.js";
import i18n from "../utils/i18n.js";

const logger = createLogger("ErrorMiddleware");

// Custom error class with multilingual support
export class AppError extends Error {
  constructor(
    messageKey,
    statusCode = 400,
    interpolations = {},
    isOperational = true
  ) {
    // If messageKey is already a string (for backward compatibility)
    if (typeof messageKey === "string" && !messageKey.includes(".")) {
      super(messageKey);
      this.messageKey = null;
      this.multilingualMessage = null;
    } else {
      // New multilingual approach
      const multilingualMessage = i18n.translate(messageKey, interpolations);
      super(multilingualMessage.en || multilingualMessage.id || messageKey);
      this.messageKey = messageKey;
      this.multilingualMessage = multilingualMessage;
    }

    this.statusCode = statusCode;
    this.status = `${statusCode}`.startsWith("4") ? "fail" : "error";
    this.isOperational = isOperational;
    this.interpolations = interpolations;

    Error.captureStackTrace(this, this.constructor);
  }
}

// 404 Not Found Handler
export const notFound = (req, res, next) => {
  const error = new AppError("errors.not_found", 404);
  next(error);
};

// Development error response
const sendErrorDev = (err, res) => {
  const response = {
    status: err.status || "error",
    statusCode: err.statusCode || 500,
    message: err.multilingualMessage || {
      id: err.message,
      en: err.message,
    },
    error: {
      name: err.name,
      message: err.message,
      stack: err.stack,
    },
    timestamp: new Date().toISOString(),
  };

  res.status(err.statusCode || 500).json(response);
};

// Production error response
const sendErrorProd = (err, res) => {
  // Operational, trusted error: send message to client
  if (err.isOperational) {
    const response = {
      status: err.status,
      statusCode: err.statusCode,
      message:
        err.multilingualMessage ||
        i18n.translate("errors.internal_server_error"),
      timestamp: new Date().toISOString(),
    };

    res.status(err.statusCode).json(response);
  } else {
    // Programming or other unknown error: don't leak error details
    logger.error("ERROR 💥", err);

    res.status(500).json({
      status: "error",
      statusCode: 500,
      message: i18n.translate("errors.internal_server_error"),
      timestamp: new Date().toISOString(),
    });
  }
};

// Handle different types of errors with multilingual messages
const handleCastErrorDB = (err) => {
  const message = i18n.translate("errors.invalid_id", { value: err.value });
  return new AppError("errors.invalid_id", 400, { value: err.value });
};

const handleDuplicateFieldsDB = (err) => {
  const field = Object.keys(err.keyValue)[0];
  const value = err.keyValue[field];

  if (field === "email") {
    return new AppError("errors.email_already_registered", 400);
  } else if (field === "phone") {
    return new AppError("errors.phone_already_registered", 400);
  } else {
    return new AppError("errors.duplicate_entry", 400, { field, value });
  }
};

const handleValidationErrorDB = (err) => {
  const errors = Object.values(err.errors).map((el) => ({
    field: el.path,
    message: el.message,
  }));

  return new AppError("errors.validation_error", 400, {
    details: errors.map((e) => e.message).join(". "),
  });
};

const handleJWTError = () => new AppError("errors.invalid_token", 401);
const handleJWTExpiredError = () => new AppError("errors.token_expired", 401);

// Global Error Handler with multilingual support
export const errorHandler = (err, req, res, next) => {
  let error = { ...err };
  error.message = err.message;
  error.statusCode = err.statusCode || 500;

  // Log error with context
  logger.error(`Error ${error.statusCode}: ${error.message}`, {
    error: {
      name: error.name,
      message: error.message,
      stack: err.stack,
    },
    request: {
      url: req.url,
      method: req.method,
      ip: req.ip,
      userAgent: req.get("User-Agent"),
      userId: req.user?._id,
    },
  });

  // Handle specific MongoDB errors
  if (err.name === "CastError") error = handleCastErrorDB(error);
  if (err.code === 11000) error = handleDuplicateFieldsDB(error);
  if (err.name === "ValidationError") error = handleValidationErrorDB(error);

  // Handle JWT errors
  if (err.name === "JsonWebTokenError") error = handleJWTError();
  if (err.name === "TokenExpiredError") error = handleJWTExpiredError();

  // Handle Mongoose validation errors
  if (err.name === "MongoServerError" && err.code === 11000) {
    error = handleDuplicateFieldsDB(error);
  }

  // Handle specific application errors by message content
  if (typeof err.message === "string") {
    if (err.message.includes("Email already registered")) {
      error = new AppError("errors.email_already_registered", 400);
    } else if (err.message.includes("Phone number already registered")) {
      error = new AppError("errors.phone_already_registered", 400);
    } else if (err.message.includes("Invalid email or password")) {
      error = new AppError("errors.invalid_credentials", 401);
    } else if (
      err.message.includes("Account locked") ||
      err.message.includes("Account temporarily locked")
    ) {
      error = new AppError("errors.account_locked", 423);
    } else if (err.message.includes("Account has been deactivated")) {
      error = new AppError("errors.account_deactivated", 403);
    } else if (err.message.includes("User not found")) {
      error = new AppError("errors.user_not_found", 404);
    } else if (err.message.includes("Authentication required")) {
      error = new AppError("errors.authentication_required", 401);
    } else if (err.message.includes("Insufficient permissions")) {
      error = new AppError("errors.insufficient_permissions", 403);
    } else if (err.message.includes("Email verification required")) {
      error = new AppError("errors.email_verification_required", 403);
    } else if (err.message.includes("Profile incomplete")) {
      const missing = err.message.match(/Missing: (.+)/);
      error = new AppError("errors.profile_incomplete", 400, {
        fields: missing ? missing[1] : "required fields",
      });
    } else if (err.message.includes("Weak password")) {
      error = new AppError("errors.weak_password", 400);
    } else if (
      err.message.includes("password has been found in data breaches")
    ) {
      error = new AppError("errors.password_breached", 400);
    } else if (err.message.includes("Current password is incorrect")) {
      error = new AppError("errors.current_password_incorrect", 400);
    } else if (err.message.includes("New password must be different")) {
      error = new AppError("errors.new_password_same_as_current", 400);
    } else if (err.message.includes("Invalid or expired OTP")) {
      error = new AppError("errors.invalid_otp", 400);
    } else if (err.message.includes("OTP already sent")) {
      error = new AppError("errors.otp_already_sent", 429);
    } else if (
      err.message.includes("Rate limit exceeded") ||
      err.message.includes("Too many requests")
    ) {
      error = new AppError("errors.rate_limit_exceeded", 429);
    } else if (err.message.includes("business hours")) {
      error = new AppError("errors.business_hours_only", 403);
    } else if (err.message.includes("Account must be at least")) {
      const match = err.message.match(/(\d+) days/);
      const days = match ? match[1] : "7";
      error = new AppError("errors.account_age_requirement", 403, { days });
    } else if (err.message.includes("Location outside service area")) {
      const match = err.message.match(/\((\d+)km/);
      const radius = match ? match[1] : "10";
      error = new AppError("errors.location_outside_service_area", 403, {
        radius,
      });
    }
  }

  // Send error response
  if (process.env.NODE_ENV === "development") {
    sendErrorDev(error, res);
  } else {
    sendErrorProd(error, res);
  }
};

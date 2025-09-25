import i18n from "../utils/i18n.js";
import { createLogger } from "../utils/logger.js";

const logger = createLogger("ResponseMiddleware");

// Middleware to add multilingual response helpers to res object
export const multilingualResponse = (req, res, next) => {
  // Detect user's preferred language
  const preferredLanguage = i18n.detectLanguage(req);
  req.preferredLanguage = preferredLanguage;

  // Add success response helper
  res.success = (
    messageKey,
    data = null,
    statusCode = 200,
    interpolations = {}
  ) => {
    try {
      const response = i18n.createResponse(
        "success",
        messageKey,
        data,
        interpolations
      );

      // Log for debugging in development
      if (process.env.NODE_ENV === "development") {
        logger.info(`Success response: ${messageKey}`, {
          statusCode,
          preferredLanguage,
          userId: req.user?._id,
        });
      }

      return res.status(statusCode).json(response);
    } catch (error) {
      logger.error("Error creating success response:", error);
      return res.status(500).json({
        status: "error",
        message: {
          id: "Terjadi kesalahan dalam membuat response",
          en: "Error occurred while creating response",
        },
        timestamp: new Date().toISOString(),
      });
    }
  };

  // Add error response helper
  res.error = (messageKey, statusCode = 400, interpolations = {}) => {
    try {
      const response = i18n.createErrorResponse(
        statusCode,
        messageKey,
        interpolations
      );

      // Log error for monitoring
      logger.error(`Error response: ${messageKey}`, {
        statusCode,
        preferredLanguage,
        userId: req.user?._id,
        url: req.url,
        method: req.method,
      });

      return res.status(statusCode).json(response);
    } catch (error) {
      logger.error("Error creating error response:", error);
      return res.status(500).json({
        status: "error",
        statusCode: 500,
        message: {
          id: "Terjadi kesalahan internal server",
          en: "Internal server error occurred",
        },
        timestamp: new Date().toISOString(),
      });
    }
  };

  // Add validation error response helper
  res.validationError = (errors) => {
    try {
      const response = i18n.createValidationErrorResponse(errors);

      logger.warn("Validation error response", {
        errors,
        userId: req.user?._id,
        url: req.url,
        method: req.method,
      });

      return res.status(400).json(response);
    } catch (error) {
      logger.error("Error creating validation error response:", error);
      return res.status(500).json({
        status: "error",
        statusCode: 500,
        message: {
          id: "Terjadi kesalahan dalam validasi",
          en: "Error occurred during validation",
        },
        timestamp: new Date().toISOString(),
      });
    }
  };

  // Add custom response helper (for cases where you need custom message structure)
  res.custom = (data, statusCode = 200) => {
    try {
      return res.status(statusCode).json({
        ...data,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      logger.error("Error creating custom response:", error);
      return res.status(500).json({
        status: "error",
        message: {
          id: "Terjadi kesalahan dalam membuat response",
          en: "Error occurred while creating response",
        },
        timestamp: new Date().toISOString(),
      });
    }
  };

  next();
};

// Middleware to format API documentation responses (non-user facing)
export const apiDocResponse = (req, res, next) => {
  // Add simple response for developer-facing endpoints
  res.apiSuccess = (message, data = null, statusCode = 200) => {
    return res.status(statusCode).json({
      status: "success",
      message,
      data,
      timestamp: new Date().toISOString(),
    });
  };

  res.apiError = (message, statusCode = 400) => {
    return res.status(statusCode).json({
      status: "error",
      message,
      statusCode,
      timestamp: new Date().toISOString(),
    });
  };

  next();
};

// Middleware to add translation helpers to controllers
export const translationHelpers = (req, res, next) => {
  // Add translation function to request object
  req.t = (key, interpolations = {}) => {
    return i18n.translate(key, interpolations);
  };

  // Add single language translation
  req.tSingle = (key, language = null, interpolations = {}) => {
    const lang = language || req.preferredLanguage || "id";
    return i18n.translateSingle(key, lang, interpolations);
  };

  // Add function to get user's preferred language translation only
  req.tPreferred = (key, interpolations = {}) => {
    const lang = req.preferredLanguage || "id";
    return i18n.translateSingle(key, lang, interpolations);
  };

  next();
};

// Error handler that formats errors in multilingual format
export const multilingualErrorHandler = (err, req, res, next) => {
  // Default error response
  let statusCode = err.statusCode || 500;
  let messageKey = "errors.internal_server_error";
  let interpolations = {};

  // Handle different types of errors
  if (err.name === "ValidationError") {
    statusCode = 400;
    messageKey = "errors.validation_error";
  } else if (err.name === "CastError") {
    statusCode = 400;
    messageKey = "errors.invalid_id";
  } else if (err.code === 11000) {
    statusCode = 400;
    // Handle duplicate key errors
    const field = Object.keys(err.keyValue)[0];
    if (field === "email") {
      messageKey = "errors.email_already_registered";
    } else if (field === "phone") {
      messageKey = "errors.phone_already_registered";
    } else {
      messageKey = "errors.duplicate_entry";
      interpolations = { field };
    }
  } else if (err.name === "JsonWebTokenError") {
    statusCode = 401;
    messageKey = "errors.invalid_token";
  } else if (err.name === "TokenExpiredError") {
    statusCode = 401;
    messageKey = "errors.token_expired";
  } else if (err.message && err.message.includes("Email already registered")) {
    statusCode = 400;
    messageKey = "errors.email_already_registered";
  } else if (
    err.message &&
    err.message.includes("Phone number already registered")
  ) {
    statusCode = 400;
    messageKey = "errors.phone_already_registered";
    
  } 
  else if (
    err.message &&
    err.message.includes("Phone number already registered different user")
  ) {
    statusCode = 400;
    messageKey = "errors.phone_used_by_different_user";
  } else if (err.message && err.message.includes("Invalid login or password")) {
    statusCode = 401;
    messageKey = "errors.invalid_credentials";
  } else if (err.message && err.message.includes("Account temporarily locked due to too many failed login attempts")) {
    statusCode = 423;
    messageKey = "errors.account_locked";
  } else if (
    err.message &&
    err.message.includes("Account has been deactivated")
  ) {
    statusCode = 403;
    messageKey = "errors.account_deactivated";
  } else if (err.message && err.message.includes("User not found")) {
    statusCode = 404;
    messageKey = "errors.user_not_found";
  } else if (err.message && err.message.includes("Authentication required")) {
    statusCode = 401;
    messageKey = "errors.authentication_required";
  } else if (err.message && err.message.includes("Insufficient permissions")) {
    statusCode = 403;
    messageKey = "errors.insufficient_permissions";
  } else if (
    err.message &&
    err.message.includes("Email verification required")
  ) {
    statusCode = 403;
    messageKey = "errors.email_verification_required";
  } else if (err.message && err.message.includes("Profile incomplete")) {
    statusCode = 400;
    messageKey = "errors.profile_incomplete";
  }

  // Create multilingual error response
  const response = i18n.createErrorResponse(
    statusCode,
    messageKey,
    interpolations
  );

  // Log error for debugging
  logger.error("Multilingual error response:", {
    error: err.message,
    stack: err.stack,
    statusCode,
    messageKey,
    userId: req.user?._id,
    url: req.url,
    method: req.method,
  });

  res.status(statusCode).json(response);
};

// Middleware to add response metadata (pagination, etc.)
export const responseMetadata = (req, res, next) => {
  // Add pagination helper
  res.paginated = (messageKey, data, pagination, statusCode = 200) => {
    const response = i18n.createResponse("success", messageKey, {
      items: data,
      pagination: {
        currentPage: pagination.page,
        totalPages: pagination.totalPages,
        totalItems: pagination.totalItems,
        itemsPerPage: pagination.limit,
        hasNext: pagination.hasNext,
        hasPrev: pagination.hasPrev,
      },
    });

    return res.status(statusCode).json(response);
  };

  next();
};

export default {
  multilingualResponse,
  apiDocResponse,
  translationHelpers,
  multilingualErrorHandler,
  responseMetadata,
};

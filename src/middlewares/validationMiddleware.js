import Joi from "joi";
import { AppError } from "./errorMiddleware.js";

// Helper function to validate request data
const validateRequest = (schema) => {
  return (req, res, next) => {
    const { error, value } = schema.validate(req.body, {
      abortEarly: false,
      stripUnknown: true,
    });

    if (error) {
      const errorMessage = error.details
        .map((detail) => detail.message)
        .join(", ");
      return next(new AppError(`Validation error: ${errorMessage}`, 400));
    }

    req.body = value;
    next();
  };
};

// Indonesian phone number validation
const indonesianPhoneSchema = Joi.string()
  .pattern(/^(\+62|62|0)[0-9]{9,13}$/)
  .messages({
    "string.pattern.base":
      "Phone number must be a valid Indonesian phone number",
  });

// Address schema
const addressSchema = Joi.object({
  street: Joi.string().required().trim().min(5).max(200),
  village: Joi.string().required().trim().min(2).max(100),
  district: Joi.string().required().trim().min(2).max(100),
  city: Joi.string().required().trim().min(2).max(100),
  province: Joi.string().required().trim().min(2).max(100),
  postalCode: Joi.string()
    .required()
    .pattern(/^\d{5}$/)
    .messages({
      "string.pattern.base": "Postal code must be 5 digits",
    }),
  coordinates: Joi.object({
    latitude: Joi.number().required().min(-90).max(90),
    longitude: Joi.number().required().min(-180).max(180),
  }).required(),
  isDefault: Joi.boolean().default(false),
});

// RT/RW data schema
const rtRwDataSchema = Joi.object({
  rtNumber: Joi.string()
    .when("$role", {
      is: Joi.string().valid("rt", "rw"),
      then: Joi.required(),
      otherwise: Joi.optional(),
    })
    .trim()
    .min(1)
    .max(10),
  rwNumber: Joi.string()
    .when("$role", {
      is: "rw",
      then: Joi.required(),
      otherwise: Joi.optional(),
    })
    .trim()
    .min(1)
    .max(10),
  area: Joi.string()
    .when("$role", {
      is: Joi.string().valid("rt", "rw"),
      then: Joi.required(),
      otherwise: Joi.optional(),
    })
    .trim()
    .min(5)
    .max(200),
  memberCount: Joi.number().integer().min(0).default(0),
});

// Collector data schema
const collectorDataSchema = Joi.object({
  businessName: Joi.string()
    .when("$role", {
      is: "collector",
      then: Joi.required(),
      otherwise: Joi.optional(),
    })
    .trim()
    .min(2)
    .max(100),
  businessLicense: Joi.string().trim().max(50).optional(),
  serviceRadius: Joi.number().min(1).max(50).default(10),
  vehicleType: Joi.string()
    .valid("motorcycle", "car", "truck", "pickup")
    .when("$role", {
      is: "collector",
      then: Joi.required(),
      otherwise: Joi.optional(),
    }),
  operatingHours: Joi.object({
    start: Joi.string()
      .pattern(/^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/)
      .default("08:00"),
    end: Joi.string()
      .pattern(/^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/)
      .default("17:00"),
  }).optional(),
  isAvailable: Joi.boolean().default(true),
});

// Registration validation
const registrationSchema = Joi.object({
  name: Joi.string().required().trim().min(2).max(100),
  email: Joi.string().required().email().lowercase().trim(),
  phone: indonesianPhoneSchema.required(),
  password: Joi.string().required().min(8).max(128),
  role: Joi.string()
    .valid("individual", "rt", "rw", "collector")
    .default("individual"),
  addresses: Joi.array().items(addressSchema).min(0).max(5).optional(),
  rtRwData: rtRwDataSchema.optional(),
  collectorData: collectorDataSchema.optional(),
  dateOfBirth: Joi.date().max("now").optional(),
  gender: Joi.string().valid("male", "female", "other").optional(),
  platform: Joi.string().valid("mobile_app", "web_app").default("web_app"),
}).custom((value, helpers) => {
  // Validate role-specific required data
  if ((value.role === "rt" || value.role === "rw") && !value.rtRwData) {
    return helpers.error("any.required", { label: "rtRwData" });
  }
  if (value.role === "collector" && !value.collectorData) {
    return helpers.error("any.required", { label: "collectorData" });
  }
  return value;
});

// Login validation
const loginSchema = Joi.object({
  email: Joi.string().required().email().lowercase().trim(),
  password: Joi.string().required(),
  rememberMe: Joi.boolean().default(false),
  platform: Joi.string().valid("mobile_app", "web_app").default("web_app"),
});

// Password reset validation
const passwordResetSchema = Joi.object({
  token: Joi.string().required().length(64), // SHA-256 hex length
  newPassword: Joi.string().required().min(8).max(128),
  confirmPassword: Joi.string()
    .required()
    .valid(Joi.ref("newPassword"))
    .messages({
      "any.only": "Confirm password must match new password",
    }),
});

// Password change validation
const passwordChangeSchema = Joi.object({
  currentPassword: Joi.string().required(),
  newPassword: Joi.string().required().min(8).max(128),
  confirmPassword: Joi.string()
    .required()
    .valid(Joi.ref("newPassword"))
    .messages({
      "any.only": "Confirm password must match new password",
    }),
}).custom((value, helpers) => {
  // Ensure new password is different from current password
  if (value.currentPassword === value.newPassword) {
    return helpers.error("any.invalid", {
      message: "New password must be different from current password",
    });
  }
  return value;
});

// Email validation
const emailSchema = Joi.object({
  email: Joi.string().required().email().lowercase().trim(),
});

// Phone OTP validation
const phoneOTPSchema = Joi.object({
  phoneNumber: indonesianPhoneSchema.required(),
});

// OTP verification validation
const otpVerificationSchema = Joi.object({
  otp: Joi.string()
    .required()
    .length(6)
    .pattern(/^\d{6}$/)
    .messages({
      "string.pattern.base": "OTP must be 6 digits",
      "string.length": "OTP must be 6 digits",
    }),
});

// Password strength check validation
const passwordStrengthSchema = Joi.object({
  password: Joi.string().required(),
});

// Profile update validation
const profileUpdateSchema = Joi.object({
  name: Joi.string().trim().min(2).max(100).optional(),
  phone: indonesianPhoneSchema.optional(),
  dateOfBirth: Joi.date().max("now").optional(),
  gender: Joi.string().valid("male", "female", "other").optional(),
  addresses: Joi.array().items(addressSchema).min(0).max(5).optional(),
  rtRwData: rtRwDataSchema.optional(),
  collectorData: collectorDataSchema.optional(),
  preferences: Joi.object({
    notifications: Joi.object({
      email: Joi.boolean().optional(),
      push: Joi.boolean().optional(),
      sms: Joi.boolean().optional(),
    }).optional(),
    language: Joi.string().valid("id", "en").optional(),
  }).optional(),
});

// Query parameter validation for pagination
const paginationSchema = Joi.object({
  page: Joi.number().integer().min(1).default(1),
  limit: Joi.number().integer().min(1).max(100).default(20),
  sort: Joi.string()
    .valid("createdAt", "updatedAt", "name", "email", "role")
    .default("createdAt"),
  order: Joi.string().valid("asc", "desc").default("desc"),
});

// Search validation
const searchSchema = Joi.object({
  q: Joi.string().trim().min(1).max(100).optional(),
  role: Joi.string()
    .valid("individual", "rt", "rw", "collector", "admin")
    .optional(),
  isActive: Joi.boolean().optional(),
  isEmailVerified: Joi.boolean().optional(),
  ...paginationSchema.describe().keys,
});

// Location validation
const locationSchema = Joi.object({
  latitude: Joi.number().required().min(-90).max(90),
  longitude: Joi.number().required().min(-180).max(180),
});

// Coordinates with radius validation
const coordinatesWithRadiusSchema = Joi.object({
  coordinates: locationSchema.required(),
  radius: Joi.number().min(1).max(100).default(10), // km
});

// Validate query parameters
const validateQuery = (schema) => {
  return (req, res, next) => {
    const { error, value } = schema.validate(req.query, {
      abortEarly: false,
      stripUnknown: true,
    });

    if (error) {
      const errorMessage = error.details
        .map((detail) => detail.message)
        .join(", ");
      return next(new AppError(`Query validation error: ${errorMessage}`, 400));
    }

    req.query = value;
    next();
  };
};

// Validate URL parameters
const validateParams = (schema) => {
  return (req, res, next) => {
    const { error, value } = schema.validate(req.params, {
      abortEarly: false,
      stripUnknown: true,
    });

    if (error) {
      const errorMessage = error.details
        .map((detail) => detail.message)
        .join(", ");
      return next(
        new AppError(`Parameter validation error: ${errorMessage}`, 400)
      );
    }

    req.params = value;
    next();
  };
};

// MongoDB ObjectId validation
const objectIdSchema = Joi.object({
  id: Joi.string()
    .required()
    .pattern(/^[0-9a-fA-F]{24}$/)
    .messages({
      "string.pattern.base": "Invalid ID format",
    }),
});

// Token validation
const tokenSchema = Joi.object({
  token: Joi.string().required().min(10).max(200),
});

// Export validation middleware functions
export const validateRegistration = validateRequest(registrationSchema);
export const validateLogin = validateRequest(loginSchema);
export const validatePasswordReset = validateRequest(passwordResetSchema);
export const validatePasswordChange = validateRequest(passwordChangeSchema);
export const validateEmail = validateRequest(emailSchema);
export const validatePhoneOTP = validateRequest(phoneOTPSchema);
export const validateOTPVerification = validateRequest(otpVerificationSchema);
export const validatePasswordStrength = validateRequest(passwordStrengthSchema);
export const validateProfileUpdate = validateRequest(profileUpdateSchema);
export const validateCoordinatesWithRadius = validateRequest(
  coordinatesWithRadiusSchema
);

// Query validation
export const validatePagination = validateQuery(paginationSchema);
export const validateSearch = validateQuery(searchSchema);

// Parameter validation
export const validateObjectId = validateParams(objectIdSchema);
export const validateToken = validateParams(tokenSchema);

// Custom validation helpers
export const validateIndonesianPostalCode = (postalCode) => {
  return /^\d{5}$/.test(postalCode);
};

export const validateIndonesianPhoneNumber = (phone) => {
  return /^(\+62|62|0)[0-9]{9,13}$/.test(phone);
};

export const validateCoordinatesInIndonesia = (latitude, longitude) => {
  // Indonesia bounding box (approximate)
  const minLat = -11.0;
  const maxLat = 6.0;
  const minLng = 95.0;
  const maxLng = 141.0;

  return (
    latitude >= minLat &&
    latitude <= maxLat &&
    longitude >= minLng &&
    longitude <= maxLng
  );
};

// Business logic validation
export const validateMinimumAge = (dateOfBirth, minimumAge = 17) => {
  if (!dateOfBirth) return false;

  const today = new Date();
  const birthDate = new Date(dateOfBirth);
  const age = Math.floor((today - birthDate) / (365.25 * 24 * 60 * 60 * 1000));

  return age >= minimumAge;
};

// File upload validation (for future use)
export const validateImageUpload = (req, res, next) => {
  if (!req.file && !req.files) {
    return next();
  }

  const allowedTypes = ["image/jpeg", "image/jpg", "image/png"];
  const maxSize = 5 * 1024 * 1024; // 5MB

  const files = req.files || [req.file];

  for (const file of files) {
    if (!allowedTypes.includes(file.mimetype)) {
      return next(
        new AppError("Only JPEG, JPG, and PNG images are allowed", 400)
      );
    }

    if (file.size > maxSize) {
      return next(new AppError("Image size must be less than 5MB", 400));
    }
  }

  next();
};

// Rate limiting validation
export const validateRateLimit = (
  maxRequests = 5,
  windowMs = 15 * 60 * 1000
) => {
  const requests = new Map();

  return (req, res, next) => {
    const identifier = req.ip || req.get("X-Forwarded-For");
    const now = Date.now();
    const windowStart = now - windowMs;

    if (!requests.has(identifier)) {
      requests.set(identifier, []);
    }

    const userRequests = requests
      .get(identifier)
      .filter((time) => time > windowStart);
    requests.set(identifier, userRequests);

    if (userRequests.length >= maxRequests) {
      return next(
        new AppError("Too many requests. Please try again later.", 429)
      );
    }

    userRequests.push(now);
    next();
  };
};

export default {
  validateRegistration,
  validateLogin,
  validatePasswordReset,
  validatePasswordChange,
  validateEmail,
  validatePhoneOTP,
  validateOTPVerification,
  validatePasswordStrength,
  validateProfileUpdate,
  validateCoordinatesWithRadius,
  validatePagination,
  validateSearch,
  validateObjectId,
  validateToken,
  validateImageUpload,
  validateRateLimit,
};

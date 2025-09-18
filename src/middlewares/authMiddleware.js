import jwtManager from "../utils/jwt.js";
import { createLogger } from "../utils/logger.js";
import { AppError } from "./errorMiddleware.js";
import { User } from "../models/index.js";

const logger = createLogger("AuthMiddleware");

// Authenticate user with JWT token
export const authenticate = async (req, res, next) => {
  try {
    // Extract token from Authorization header
    const authHeader = req.headers.authorization;
    const token = jwtManager.extractTokenFromHeader(authHeader);

    if (!token) {
      return next(new AppError("Access token is required", 401));
    }

    // Check if token is blacklisted
    if (await jwtManager.isTokenBlacklisted(token)) {
      return next(new AppError("Token has been invalidated", 401));
    }

    // Verify token
    const decoded = jwtManager.verifyAccessToken(token);

    // Get user from database with fresh data
    const user = await User.findById(decoded.id).select("+isActive");

    if (!user) {
      return next(new AppError("User not found", 401));
    }

    // Check if user is active
    if (!user.isActive) {
      return next(new AppError("Account has been deactivated", 403));
    }

    // Check if user is locked
    if (user.isLocked) {
      return next(new AppError("Account is temporarily locked", 423));
    }

    // Attach user to request
    req.user = user;
    req.token = token;

    // Log successful authentication
    logger.info(`User authenticated: ${user.email} (${user.role})`);

    next();
  } catch (error) {
    logger.error("Authentication error:", error.message);

    if (error.message === "Token expired") {
      return next(new AppError("Access token has expired", 401));
    } else if (error.message === "Invalid token") {
      return next(new AppError("Invalid access token", 401));
    } else {
      return next(new AppError("Authentication failed", 401));
    }
  }
};

// Optional authentication (for public endpoints that can work with or without auth)
export const optionalAuth = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    const token = jwtManager.extractTokenFromHeader(authHeader);

    if (!token) {
      req.user = null;
      return next();
    }

    // Try to authenticate, but don't fail if it doesn't work
    try {
      const decoded = jwtManager.verifyAccessToken(token);
      const user = await User.findById(decoded.id).select("+isActive");

      if (user && user.isActive && !user.isLocked) {
        req.user = user;
        req.token = token;
      } else {
        req.user = null;
      }
    } catch (authError) {
      req.user = null;
    }

    next();
  } catch (error) {
    logger.error("Optional authentication error:", error.message);
    req.user = null;
    next();
  }
};

// Role-based authorization
export const authorize = (...allowedRoles) => {
  return (req, res, next) => {
    if (!req.user) {
      return next(new AppError("Authentication required", 401));
    }

    if (!allowedRoles.includes(req.user.role)) {
      return next(
        new AppError("Insufficient permissions for this resource", 403)
      );
    }

    logger.info(
      `Authorization granted: ${req.user.email} accessing ${req.method} ${req.path}`
    );
    next();
  };
};

// Check if user owns the resource or has admin privileges
export const authorizeOwnershipOrAdmin = (resourceUserField = "user") => {
  return async (req, res, next) => {
    if (!req.user) {
      return next(new AppError("Authentication required", 401));
    }

    // Admins can access everything
    if (req.user.role === "admin") {
      return next();
    }

    try {
      // For routes with :id parameter, check if user owns the resource
      if (req.params.id) {
        const resourceId = req.params.id;

        // If the resource ID is the same as user ID (e.g., /users/:id)
        if (resourceId === req.user._id.toString()) {
          return next();
        }

        // For other resources, we need to check the resource's owner
        // This will be handled in the specific route handlers
        req.checkOwnership = true;
        return next();
      }

      // For POST/PUT requests, allow if user is creating/updating their own resource
      if (["POST", "PUT", "PATCH"].includes(req.method)) {
        return next();
      }

      return next(new AppError("Access denied", 403));
    } catch (error) {
      logger.error("Ownership authorization error:", error);
      return next(new AppError("Authorization failed", 500));
    }
  };
};

// Check email verification requirement
export const requireEmailVerification = (req, res, next) => {
  if (!req.user) {
    return next(new AppError("Authentication required", 401));
  }

  if (!req.user.isEmailVerified) {
    return next(new AppError("Email verification required", 403));
  }

  next();
};

// Check account completion (for users who need to complete profile)
export const requireCompleteProfile = (req, res, next) => {
  if (!req.user) {
    return next(new AppError("Authentication required", 401));
  }

  // Check if required fields are completed based on user role
  const requiredFields = {
    individual: ["name", "phone", "addresses"],
    rt: ["name", "phone", "addresses", "rtRwData"],
    rw: ["name", "phone", "addresses", "rtRwData"],
    collector: ["name", "phone", "addresses", "collectorData"],
    admin: ["name", "phone"],
  };

  const required = requiredFields[req.user.role] || [];
  const missing = [];

  for (const field of required) {
    if (field === "addresses") {
      if (!req.user.addresses || req.user.addresses.length === 0) {
        missing.push("address");
      }
    } else if (field.includes(".")) {
      // Handle nested fields
      const [parent, child] = field.split(".");
      if (!req.user[parent] || !req.user[parent][child]) {
        missing.push(field);
      }
    } else if (!req.user[field]) {
      missing.push(field);
    }
  }

  if (missing.length > 0) {
    return next(
      new AppError(`Profile incomplete. Missing: ${missing.join(", ")}`, 400)
    );
  }

  next();
};

// Rate limiting per user
export const userRateLimit = (maxRequests = 100, windowMs = 15 * 60 * 1000) => {
  const requests = new Map(); // In production, use Redis

  return (req, res, next) => {
    if (!req.user) {
      return next();
    }

    const userId = req.user._id.toString();
    const now = Date.now();
    const windowStart = now - windowMs;

    // Clean old entries
    if (requests.has(userId)) {
      const userRequests = requests
        .get(userId)
        .filter((time) => time > windowStart);
      requests.set(userId, userRequests);
    } else {
      requests.set(userId, []);
    }

    const userRequests = requests.get(userId);

    if (userRequests.length >= maxRequests) {
      return next(new AppError("Rate limit exceeded for this user", 429));
    }

    userRequests.push(now);
    next();
  };
};

// Check if user can access specific geographic location
export const authorizeLocation = (radiusKm = 50) => {
  return (req, res, next) => {
    if (!req.user) {
      return next(new AppError("Authentication required", 401));
    }

    // Admins can access any location
    if (req.user.role === "admin") {
      return next();
    }

    // Extract coordinates from request (body, query, or params)
    const coordinates =
      req.body.coordinates ||
      req.query.coordinates ||
      req.body.location?.coordinates;

    if (!coordinates) {
      return next(); // No location restriction if coordinates not provided
    }

    // Check if user has default address
    if (!req.user.defaultAddress) {
      return next(new AppError("User location not available", 400));
    }

    // Calculate distance between user location and requested location
    const userCoords = req.user.defaultAddress.coordinates;
    const distance = calculateDistance(
      userCoords.latitude,
      userCoords.longitude,
      coordinates.latitude || coordinates[1],
      coordinates.longitude || coordinates[0]
    );

    // For collectors, use their service radius
    if (
      req.user.role === "collector" &&
      req.user.collectorData?.serviceRadius
    ) {
      const allowedRadius = req.user.collectorData.serviceRadius;
      if (distance > allowedRadius) {
        return next(
          new AppError(
            `Location outside service area (${allowedRadius}km radius)`,
            403
          )
        );
      }
    } else if (distance > radiusKm) {
      return next(
        new AppError(
          `Location too far from your registered address (>${radiusKm}km)`,
          403
        )
      );
    }

    req.locationDistance = distance;
    next();
  };
};

// Helper function to calculate distance between two coordinates
function calculateDistance(lat1, lon1, lat2, lon2) {
  const R = 6371; // Earth's radius in kilometers
  const dLat = ((lat2 - lat1) * Math.PI) / 180;
  const dLon = ((lon2 - lon1) * Math.PI) / 180;
  const a =
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos((lat1 * Math.PI) / 180) *
      Math.cos((lat2 * Math.PI) / 180) *
      Math.sin(dLon / 2) *
      Math.sin(dLon / 2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return R * c;
}

// Middleware to log user activity
export const logUserActivity = (action) => {
  return (req, res, next) => {
    if (req.user) {
      logger.info(
        `User activity: ${req.user.email} (${req.user.role}) - ${action}`,
        {
          userId: req.user._id,
          action,
          ip: req.ip,
          userAgent: req.get("User-Agent"),
          timestamp: new Date(),
        }
      );
    }
    next();
  };
};

// Check if user has specific permissions (for fine-grained control)
export const checkPermission = (permission) => {
  // Define role-based permissions
  const rolePermissions = {
    individual: [
      "create_product",
      "view_own_products",
      "update_own_products",
      "delete_own_products",
      "create_order",
      "view_own_orders",
      "cancel_own_orders",
      "create_rating",
      "view_ratings",
      "redeem_points",
      "update_own_profile",
      "view_own_profile",
    ],
    rt: [
      "create_product",
      "view_own_products",
      "update_own_products",
      "delete_own_products",
      "create_order",
      "view_own_orders",
      "accept_orders",
      "cancel_own_orders",
      "create_rating",
      "view_ratings",
      "manage_rt_area",
      "view_rt_members",
      "manage_rt_cash",
      "update_own_profile",
    ],
    rw: [
      "create_product",
      "view_own_products",
      "update_own_products",
      "delete_own_products",
      "create_order",
      "view_own_orders",
      "accept_orders",
      "cancel_own_orders",
      "create_rating",
      "view_ratings",
      "manage_rw_area",
      "view_rw_members",
      "manage_rw_cash",
      "supervise_rt",
      "update_own_profile",
    ],
    collector: [
      "view_available_orders",
      "accept_orders",
      "update_order_status",
      "create_rating",
      "view_ratings",
      "view_nearby_products",
      "manage_service_area",
      "view_earnings",
      "update_own_profile",
    ],
    admin: [
      "manage_all_users",
      "manage_all_products",
      "manage_all_orders",
      "manage_system_settings",
      "view_analytics",
      "moderate_content",
      "manage_rewards",
      "handle_disputes",
      "manage_locations",
      "system_maintenance",
    ],
  };

  return (req, res, next) => {
    if (!req.user) {
      return next(new AppError("Authentication required", 401));
    }

    const userPermissions = rolePermissions[req.user.role] || [];

    if (!userPermissions.includes(permission)) {
      return next(new AppError(`Permission denied: ${permission}`, 403));
    }

    next();
  };
};

// Middleware to check business hours (for certain operations)
export const checkBusinessHours = (req, res, next) => {
  const now = new Date();
  const currentHour = now.getHours();

  // Define business hours (can be configured via env)
  const businessStart = parseInt(process.env.BUSINESS_HOURS_START) || 6; // 6 AM
  const businessEnd = parseInt(process.env.BUSINESS_HOURS_END) || 22; // 10 PM

  if (currentHour < businessStart || currentHour >= businessEnd) {
    // Allow admins to work outside business hours
    if (req.user?.role === "admin") {
      return next();
    }

    return next(
      new AppError(
        "This operation is only available during business hours (6 AM - 10 PM)",
        403
      )
    );
  }

  next();
};

// Middleware to validate account age (for sensitive operations)
export const requireAccountAge = (minDays = 7) => {
  return (req, res, next) => {
    if (!req.user) {
      return next(new AppError("Authentication required", 401));
    }

    const accountAge =
      (Date.now() - req.user.createdAt.getTime()) / (1000 * 60 * 60 * 24);

    if (accountAge < minDays) {
      return next(
        new AppError(
          `Account must be at least ${minDays} days old for this operation`,
          403
        )
      );
    }

    next();
  };
};

export default {
  authenticate,
  optionalAuth,
  authorize,
  authorizeOwnershipOrAdmin,
  requireEmailVerification,
  requireCompleteProfile,
  userRateLimit,
  authorizeLocation,
  logUserActivity,
  checkPermission,
  checkBusinessHours,
  requireAccountAge,
};

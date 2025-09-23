import jwtManager from "../utils/jwt.js";
import { createLogger } from "../utils/logger.js";
import { AppError } from "./errorMiddleware.js";
import { User } from "../models/index.js";

const logger = createLogger("AuthMiddleware");

// Authenticate user with JWT token (updated for multi-role)
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
    const user = await User.findById(decoded.id || decoded.userId).select(
      "+isActive"
    );

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

    // Check if current role in token matches user's current role (multi-role validation)
    if (decoded.currentRole && decoded.currentRole !== user.currentRole) {
      return next(
        new AppError("Role has been changed, please login again", 401)
      );
    }

    // Attach user and role info to request
    req.user = user;
    req.token = token;
    req.currentRole = user.currentRole;
    req.currentRoleData = user.currentRoleData;

    // Log successful authentication with current role
    logger.info(
      `User authenticated: ${user.email} (current role: ${user.currentRole})`
    );

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

// Optional authentication (updated for multi-role)
export const optionalAuth = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    const token = jwtManager.extractTokenFromHeader(authHeader);

    if (!token) {
      req.user = null;
      req.currentRole = null;
      req.currentRoleData = null;
      return next();
    }

    // Try to authenticate, but don't fail if it doesn't work
    try {
      const decoded = jwtManager.verifyAccessToken(token);
      const user = await User.findById(decoded.id || decoded.userId).select(
        "+isActive"
      );

      if (user && user.isActive && !user.isLocked) {
        req.user = user;
        req.token = token;
        req.currentRole = user.currentRole;
        req.currentRoleData = user.currentRoleData;
      } else {
        req.user = null;
        req.currentRole = null;
        req.currentRoleData = null;
      }
    } catch (authError) {
      req.user = null;
      req.currentRole = null;
      req.currentRoleData = null;
    }

    next();
  } catch (error) {
    logger.error("Optional authentication error:", error.message);
    req.user = null;
    req.currentRole = null;
    req.currentRoleData = null;
    next();
  }
};

// Role-based authorization (updated for current role)
export const authorize = (...allowedRoles) => {
  return (req, res, next) => {
    if (!req.user) {
      return next(new AppError("Authentication required", 401));
    }

    const userCurrentRole = req.currentRole;

    if (!allowedRoles.includes(userCurrentRole)) {
      return next(
        new AppError("Insufficient permissions for this resource", 403)
      );
    }

    logger.info(
      `Authorization granted: ${req.user.email} (${userCurrentRole}) accessing ${req.method} ${req.path}`
    );
    next();
  };
};

// Check if user has any of the specified roles (not necessarily current)
export const hasAnyRole = (...requiredRoles) => {
  return (req, res, next) => {
    if (!req.user) {
      return next(new AppError("Authentication required", 401));
    }

    const userRoles = req.user.roles
      .filter((r) => r.isActive)
      .map((r) => r.role);

    const hasRequiredRole = requiredRoles.some((role) =>
      userRoles.includes(role)
    );

    if (!hasRequiredRole) {
      return next(
        new AppError("Insufficient permissions - missing required roles", 403)
      );
    }

    logger.info(
      `Multi-role authorization granted: ${
        req.user.email
      } has roles: ${userRoles.join(", ")}`
    );
    next();
  };
};

// Check if user has all specified roles
export const hasAllRoles = (...requiredRoles) => {
  return (req, res, next) => {
    if (!req.user) {
      return next(new AppError("Authentication required", 401));
    }

    const userRoles = req.user.roles
      .filter((r) => r.isActive)
      .map((r) => r.role);

    const hasAllRequiredRoles = requiredRoles.every((role) =>
      userRoles.includes(role)
    );

    if (!hasAllRequiredRoles) {
      const missingRoles = requiredRoles.filter(
        (role) => !userRoles.includes(role)
      );
      return next(
        new AppError(`Missing required roles: ${missingRoles.join(", ")}`, 403)
      );
    }

    next();
  };
};

// Check if user is in specific area (for RT/RW roles)
export const authorizeArea = () => {
  return (req, res, next) => {
    if (!req.user) {
      return next(new AppError("Authentication required", 401));
    }

    const currentRole = req.currentRole;
    const currentRoleData = req.currentRoleData;

    // Only applicable for RT/RW roles
    if (!["rt", "rw"].includes(currentRole)) {
      return next(
        new AppError("Area authorization only applicable for RT/RW roles", 403)
      );
    }

    if (!currentRoleData?.rtRwData?.area) {
      return next(new AppError("RT/RW area data missing", 403));
    }

    // Attach area info to request for further processing
    req.userArea = currentRoleData.rtRwData.area;
    req.rtNumber = currentRoleData.rtRwData.rtNumber;
    req.rwNumber = currentRoleData.rtRwData.rwNumber;

    logger.info(
      `Area authorization: ${req.user.email} (${currentRole}) - Area: ${req.userArea}, RT: ${req.rtNumber}`
    );

    next();
  };
};

// Check if collector is available and within service area
export const authorizeCollector = () => {
  return (req, res, next) => {
    if (!req.user) {
      return next(new AppError("Authentication required", 401));
    }

    const currentRole = req.currentRole;
    const currentRoleData = req.currentRoleData;

    if (currentRole !== "collector") {
      return next(new AppError("Collector role required", 403));
    }

    if (!currentRoleData?.collectorData) {
      return next(new AppError("Collector data missing", 403));
    }

    if (!currentRoleData.collectorData.isAvailable) {
      return next(new AppError("Collector is not available", 403));
    }

    // Attach collector info to request
    req.collectorData = currentRoleData.collectorData;

    logger.info(
      `Collector authorization: ${req.user.email} - Business: ${req.collectorData.businessName}`
    );

    next();
  };
};

// Check ownership or admin privileges (updated for multi-role)
export const authorizeOwnershipOrAdmin = (resourceUserField = "user") => {
  return async (req, res, next) => {
    if (!req.user) {
      return next(new AppError("Authentication required", 401));
    }

    // Check if user has admin role (not necessarily current role)
    const hasAdminRole = req.user.roles.some(
      (r) => r.role === "admin" && r.isActive
    );

    if (hasAdminRole) {
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

// Check email verification requirement
export const requirePhoneVerification = (req, res, next) => {
  if (!req.user) {
    return next(new AppError("Authentication required", 401));
  }

  if (!req.user.isPhoneVerified) {
    return next(new AppError("Phone verification required", 403));
  }

  next();
};

// Check account completion (updated for multi-role)
export const requireCompleteProfile = (req, res, next) => {
  if (!req.user) {
    return next(new AppError("Authentication required", 401));
  }

  const currentRole = req.currentRole;
  const currentRoleData = req.currentRoleData;

  // Check if required fields are completed based on current role
  const requiredFields = {
    individual: ["name", "phone", "addresses"],
    rt: ["name", "phone", "addresses", "rtRwData"],
    rw: ["name", "phone", "addresses", "rtRwData"],
    collector: ["name", "phone", "addresses", "collectorData"],
    admin: ["name", "phone"],
  };

  const required = requiredFields[currentRole] || [];
  const missing = [];

  for (const field of required) {
    if (field === "addresses") {
      if (!req.user.addresses || req.user.addresses.length === 0) {
        missing.push("address");
      }
    } else if (field === "rtRwData") {
      if (!currentRoleData?.rtRwData) {
        missing.push("RT/RW data");
      }
    } else if (field === "collectorData") {
      if (!currentRoleData?.collectorData) {
        missing.push("collector data");
      }
    } else if (!req.user[field]) {
      missing.push(field);
    }
  }

  if (missing.length > 0) {
    return next(
      new AppError(
        `Profile incomplete for ${currentRole} role. Missing: ${missing.join(
          ", "
        )}`,
        400
      )
    );
  }

  next();
};

// Rate limiting per role (different limits based on role)
export const roleBasedRateLimit = (limits = {}) => {
  const defaultLimits = {
    individual: 100,
    rt: 200,
    rw: 300,
    collector: 500,
    admin: 1000,
  };

  const roleLimits = { ...defaultLimits, ...limits };
  const requests = new Map(); // In production, use Redis

  return (req, res, next) => {
    if (!req.user) {
      return next();
    }

    const userRole = req.currentRole;
    const userId = req.user._id.toString();
    const limit = roleLimits[userRole] || defaultLimits.individual;
    const windowMs = 15 * 60 * 1000; // 15 minutes
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

    if (userRequests.length >= limit) {
      return next(
        new AppError(`Rate limit exceeded for ${userRole} role`, 429)
      );
    }

    userRequests.push(now);
    next();
  };
};

// Check if user can access specific geographic location (updated for collector service radius)
export const authorizeLocation = (radiusKm = 50) => {
  return (req, res, next) => {
    if (!req.user) {
      return next(new AppError("Authentication required", 401));
    }

    // Admins can access any location
    const hasAdminRole = req.user.roles.some(
      (r) => r.role === "admin" && r.isActive
    );
    if (hasAdminRole) {
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
      userCoords.coordinates[1], // latitude
      userCoords.coordinates[0], // longitude
      coordinates.latitude || coordinates[1],
      coordinates.longitude || coordinates[0]
    );

    // For collectors, use their service radius from current role data
    if (
      req.currentRole === "collector" &&
      req.currentRoleData?.collectorData?.serviceRadius
    ) {
      const allowedRadius = req.currentRoleData.collectorData.serviceRadius;
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

// Middleware to log user activity (updated with role info)
export const logUserActivity = (action) => {
  return (req, res, next) => {
    if (req.user) {
      logger.info(
        `User activity: ${req.user.email} (${req.currentRole}) - ${action}`,
        {
          userId: req.user._id,
          currentRole: req.currentRole,
          availableRoles: req.user.roles
            .filter((r) => r.isActive)
            .map((r) => r.role),
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

// Check if user has specific permissions (updated for multi-role)
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
      "distribute_incentives",
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
      "distribute_incentives",
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
      "update_availability",
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
      "switch_user_roles",
    ],
  };

  return (req, res, next) => {
    if (!req.user) {
      return next(new AppError("Authentication required", 401));
    }

    const currentRole = req.currentRole;
    const userPermissions = rolePermissions[currentRole] || [];

    if (!userPermissions.includes(permission)) {
      return next(
        new AppError(
          `Permission denied: ${permission} (current role: ${currentRole})`,
          403
        )
      );
    }

    logger.info(
      `Permission granted: ${req.user.email} (${currentRole}) - ${permission}`
    );

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
    const hasAdminRole = req.user?.roles?.some(
      (r) => r.role === "admin" && r.isActive
    );
    if (hasAdminRole) {
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
  hasAnyRole,
  hasAllRoles,
  authorizeArea,
  authorizeCollector,
  authorizeOwnershipOrAdmin,
  requireEmailVerification,
  requirePhoneVerification,
  requireCompleteProfile,
  roleBasedRateLimit,
  authorizeLocation,
  logUserActivity,
  checkPermission,
  checkBusinessHours,
  requireAccountAge,
};

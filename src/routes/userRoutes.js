import express from "express";
import userController from "../controllers/userController.js";
import { authenticate, authorize } from "../middlewares/authMiddleware.js";
import {
  validateProfileUpdate,
  validateObjectId,
  validatePagination,
  validateSearch,
  validateImageUpload,
} from "../middlewares/validationMiddleware.js";
import { rateLimit } from "express-rate-limit";

const router = express.Router();

// Rate limiting for user routes
const userRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: "Too many requests from this IP, please try again later.",
  standardHeaders: true,
  legacyHeaders: false,
});

const authRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // limit each IP to 10 requests per windowMs for sensitive operations
  message: "Too many authentication requests, please try again later.",
});

// Apply rate limiting to all user routes
router.use(userRateLimit);

// Custom validation middleware for role switching
const validateRoleSwitch = (req, res, next) => {
  const { role } = req.body;

  if (!role) {
    return res.status(400).json({
      success: false,
      message: "Role is required",
      error: { code: "VALIDATION_ERROR" },
    });
  }

  const validRoles = ["individual", "rt", "rw", "collector", "admin"];
  if (!validRoles.includes(role)) {
    return res.status(400).json({
      success: false,
      message: "Invalid role specified",
      error: { code: "VALIDATION_ERROR" },
    });
  }

  next();
};

// Custom validation for role addition
const validateAddRole = (req, res, next) => {
  const { role, rtRwData, collectorData } = req.body;

  if (!role) {
    return res.status(400).json({
      success: false,
      message: "Role is required",
      error: { code: "VALIDATION_ERROR" },
    });
  }

  const validRoles = ["individual", "rt", "rw", "collector", "admin"];
  if (!validRoles.includes(role)) {
    return res.status(400).json({
      success: false,
      message: "Invalid role specified",
      error: { code: "VALIDATION_ERROR" },
    });
  }

  // Validate role-specific data
  if ((role === "rt" || role === "rw") && !rtRwData) {
    return res.status(400).json({
      success: false,
      message: "RT/RW data is required for this role",
      error: { code: "VALIDATION_ERROR" },
    });
  }

  if (role === "collector" && !collectorData) {
    return res.status(400).json({
      success: false,
      message: "Collector data is required for this role",
      error: { code: "VALIDATION_ERROR" },
    });
  }

  next();
};

// Custom validation for addresses
const validateAddresses = (req, res, next) => {
  const { addresses } = req.body;

  if (!addresses || !Array.isArray(addresses)) {
    return res.status(400).json({
      success: false,
      message: "Addresses must be an array",
      error: { code: "VALIDATION_ERROR" },
    });
  }

  for (const address of addresses) {
    if (!address.street || !address.city || !address.province) {
      return res.status(400).json({
        success: false,
        message: "Address must include street, city, and province",
        error: { code: "VALIDATION_ERROR" },
      });
    }
  }

  next();
};

// Custom validation for coordinates
const validateCoordinates = (req, res, next) => {
  const { lat, lng } = req.query;

  if (!lat || !lng) {
    return res.status(400).json({
      success: false,
      message: "Latitude and longitude are required",
      error: { code: "VALIDATION_ERROR" },
    });
  }

  const latitude = parseFloat(lat);
  const longitude = parseFloat(lng);

  if (isNaN(latitude) || isNaN(longitude)) {
    return res.status(400).json({
      success: false,
      message: "Invalid coordinate format",
      error: { code: "VALIDATION_ERROR" },
    });
  }

  if (latitude < -90 || latitude > 90 || longitude < -180 || longitude > 180) {
    return res.status(400).json({
      success: false,
      message: "Coordinates out of valid range",
      error: { code: "VALIDATION_ERROR" },
    });
  }

  next();
};

// =======================
// PUBLIC ROUTES (no auth required)
// =======================

// Search users (limited public info)
router.get("/search", validateSearch, userController.searchUsers);

// Get users by role (limited public info)
router.get("/role/:role", userController.getUsersByRole);

// Find nearby users (limited public info)
router.get("/nearby", validateCoordinates, userController.findNearbyUsers);

// =======================
// AUTHENTICATED ROUTES
// =======================

// Apply authentication to all routes below
router.use(authenticate);

// =======================
// PROFILE MANAGEMENT
// =======================

// Get current user profile
router.get("/profile", userController.getProfile);

// Update current user profile
router.put("/profile", validateProfileUpdate, userController.updateProfile);

// Get user statistics
router.get("/statistics", userController.getUserStatistics);

// Get specific user statistics (admin or self)
router.get("/:userId/statistics", userController.getUserStatistics);

// =======================
// ROLE MANAGEMENT
// =======================

// Switch current user role
router.put(
  "/roles/switch",
  authRateLimit,
  validateRoleSwitch,
  userController.switchRole
);

// Update role-specific data
router.put("/role-data", userController.updateRoleData);

// =======================
// POINTS & REWARDS
// =======================

// Get current user points summary
router.get("/points", userController.getPointsSummary);

// Get specific user points (admin or self)
router.get(
  "/:userId/points",
  validateObjectId,
  userController.getPointsSummary
);

// =======================
// ADDRESS MANAGEMENT
// =======================

// Get user addresses
router.get("/addresses", userController.getAddresses);

// Add new address
router.post("/addresses", userController.addAddress);

// Update specific address
router.put("/addresses/:addressIndex", userController.updateAddress);

// Delete address
router.delete("/addresses/:addressIndex", userController.deleteAddress);

// Update all addresses at once
router.put("/addresses", validateAddresses, userController.updateAddresses);

// =======================
// PREFERENCES
// =======================

// Update user preferences
router.put("/preferences", userController.updatePreferences);

// =======================
// USER LOOKUP (with auth)
// =======================

// Get user by ID (authenticated users can see more details)
router.get("/:userId", validateObjectId, userController.getUserById);

// =======================
// ACCOUNT MANAGEMENT
// =======================

// Deactivate user account (self or admin)
router.put(
  "/:userId/deactivate",
  authRateLimit,
  validateObjectId,
  userController.deactivateUser
);

// =======================
// ADMIN ONLY ROUTES
// =======================

// Admin: Get user management dashboard
router.get(
  "/admin/dashboard",
  authorize("admin"),
  userController.getUserManagementData
);

// Admin: Add role to user
router.post(
  "/:userId/roles",
  authorize("admin"),
  validateObjectId,
  validateAddRole,
  userController.addRole
);

// Admin: Remove role from user
router.delete(
  "/:userId/roles/:role",
  authorize("admin"),
  validateObjectId,
  userController.removeRole
);

// Admin: Reactivate user account
router.put(
  "/:userId/reactivate",
  authorize("admin"),
  authRateLimit,
  validateObjectId,
  userController.reactivateUser
);

// =======================
// ERROR HANDLING
// =======================

// Handle 404 for user routes
router.use("*", (req, res) => {
  res.status(404).json({
    success: false,
    message: "User route not found",
    error: {
      code: "ROUTE_NOT_FOUND",
      path: req.originalUrl,
      method: req.method,
    },
  });
});

export default router;

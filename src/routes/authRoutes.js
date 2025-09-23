import express from "express";
import authController from "../controllers/authController.js";
import {
  authenticate,
  optionalAuth,
  authorize,
  hasAnyRole,
  hasAllRoles,
  authorizeArea,
  authorizeCollector,
  checkPermission,
  logUserActivity,
  requireEmailVerification,
  requirePhoneVerification,
} from "../middlewares/authMiddleware.js";
import {
  validateRegistration,
  validateLogin,
  validatePasswordReset,
  validatePasswordChange,
  validateRoleSwitch,
  validateAddRole,
} from "../middlewares/validationMiddleware.js";

const router = express.Router();

// Public routes (no authentication required)
router.post("/register", validateRegistration, authController.register);
router.post("/login", validateLogin, authController.login);
router.post("/refresh-token", authController.refreshToken);
router.post("/forgot-password", authController.forgotPassword);
router.post(
  "/reset-password",
  validatePasswordReset,
  authController.resetPassword
);
router.get("/verify-email/:token", authController.verifyEmail);

// Utility routes (public)
router.get("/password-policy", authController.getPasswordPolicy);
router.post("/check-password-strength", authController.checkPasswordStrength);
router.get("/check-email-availability", authController.checkEmailAvailability);
router.get("/check-phone-availability", authController.checkPhoneAvailability);
router.get("/account-lockout-status", authController.getAccountLockoutStatus);

// Protected routes (authentication required)
router.use(authenticate); // All routes below require authentication

// User profile and session management
router.get(
  "/profile",
  logUserActivity("view_profile"),
  authController.getProfile
);
router.post("/logout", logUserActivity("logout"), authController.logout);
router.get("/validate-session", authController.validateSession);

// Password management
router.post(
  "/change-password",
  validatePasswordChange,
  checkPermission("update_own_profile"),
  logUserActivity("change_password"),
  authController.changePassword
);

// Email verification
router.post(
  "/resend-email-verification",
  logUserActivity("resend_email_verification"),
  authController.resendEmailVerification
);

// Phone verification
router.post(
  "/generate-phone-otp",
  logUserActivity("generate_phone_otp"),
  authController.generatePhoneOTP
);

router.post(
  "/verify-phone-otp",
  logUserActivity("verify_phone_otp"),
  authController.verifyPhoneOTP
);

// Session management
router.get(
  "/sessions",
  checkPermission("view_own_profile"),
  logUserActivity("view_sessions"),
  authController.getUserSessions
);

router.delete(
  "/sessions/:tokenId",
  checkPermission("update_own_profile"),
  logUserActivity("revoke_session"),
  authController.revokeSession
);

// Security events
router.get(
  "/security-events",
  checkPermission("view_own_profile"),
  logUserActivity("view_security_events"),
  authController.getSecurityEvents
);

// ===== NEW MULTI-ROLE ROUTES =====

// Role management
router.post(
  "/switch-role",
  validateRoleSwitch,
  logUserActivity("switch_role"),
  authController.switchRole
);

router.get(
  "/available-roles",
  logUserActivity("view_available_roles"),
  authController.getAvailableRoles
);

router.post(
  "/add-role",
  validateAddRole,
  checkPermission("update_own_profile"),
  logUserActivity("add_role"),
  authController.addRole
);

router.delete(
  "/remove-role/:roleName",
  checkPermission("update_own_profile"),
  logUserActivity("remove_role"),
  authController.removeRole
);

router.get(
  "/current-role-data",
  logUserActivity("view_current_role_data"),
  authController.getCurrentRoleData
);

// Role-specific points management
router.get(
  "/points/summary",
  logUserActivity("view_points_summary"),
  authController.getPointsSummary
);

router.post(
  "/points/transfer",
  checkPermission("update_own_profile"),
  logUserActivity("transfer_points"),
  authController.transferPointsBetweenRoles
);

// ===== ROLE-SPECIFIC PROTECTED ROUTES =====

// Individual User Routes
router.get(
  "/individual/dashboard",
  authorize("individual"),
  logUserActivity("view_individual_dashboard"),
  authController.getIndividualDashboard
);

// RT Routes
router.get(
  "/rt/dashboard",
  authorize("rt"),
  authorizeArea(),
  logUserActivity("view_rt_dashboard"),
  authController.getRTDashboard
);

router.get(
  "/rt/members",
  authorize("rt"),
  authorizeArea(),
  checkPermission("view_rt_members"),
  logUserActivity("view_rt_members"),
  authController.getRTMembers
);

router.post(
  "/rt/members/:memberId/add-points",
  authorize("rt"),
  authorizeArea(),
  checkPermission("manage_rt_cash"),
  logUserActivity("add_member_points"),
  authController.addMemberPoints
);

router.get(
  "/rt/reports",
  authorize("rt"),
  authorizeArea(),
  checkPermission("view_rt_members"),
  logUserActivity("view_rt_reports"),
  authController.getRTReports
);

// RW Routes
router.get(
  "/rw/dashboard",
  authorize("rw"),
  authorizeArea(),
  logUserActivity("view_rw_dashboard"),
  authController.getRWDashboard
);

router.get(
  "/rw/members",
  authorize("rw"),
  authorizeArea(),
  checkPermission("view_rw_members"),
  logUserActivity("view_rw_members"),
  authController.getRWMembers
);

router.get(
  "/rw/rt-supervision",
  authorize("rw"),
  authorizeArea(),
  checkPermission("supervise_rt"),
  logUserActivity("view_rt_supervision"),
  authController.getRTSupervision
);

router.post(
  "/rw/distribute-incentives",
  authorize("rw"),
  authorizeArea(),
  checkPermission("manage_rw_cash"),
  logUserActivity("distribute_incentives"),
  authController.distributeIncentives
);

// Collector Routes
router.get(
  "/collector/dashboard",
  authorize("collector"),
  authorizeCollector(),
  logUserActivity("view_collector_dashboard"),
  authController.getCollectorDashboard
);

router.put(
  "/collector/availability",
  authorize("collector"),
  checkPermission("update_availability"),
  logUserActivity("update_availability"),
  authController.updateCollectorAvailability
);

router.get(
  "/collector/stats",
  authorize("collector"),
  checkPermission("view_earnings"),
  logUserActivity("view_collector_stats"),
  authController.getCollectorStats
);

router.put(
  "/collector/operating-hours",
  authorize("collector"),
  checkPermission("manage_service_area"),
  logUserActivity("update_operating_hours"),
  authController.updateOperatingHours
);

router.get(
  "/collector/earnings",
  authorize("collector"),
  checkPermission("view_earnings"),
  logUserActivity("view_earnings"),
  authController.getCollectorEarnings
);

// Admin Routes
router.get(
  "/admin/dashboard",
  authorize("admin"),
  logUserActivity("view_admin_dashboard"),
  authController.getAdminDashboard
);

router.get(
  "/admin/users",
  authorize("admin"),
  checkPermission("manage_all_users"),
  logUserActivity("view_all_users"),
  authController.getAllUsers
);

router.post(
  "/admin/users/:userId/force-role-switch",
  authorize("admin"),
  checkPermission("switch_user_roles"),
  logUserActivity("force_role_switch"),
  authController.forceRoleSwitch
);

router.get(
  "/admin/system-stats",
  authorize("admin"),
  checkPermission("view_analytics"),
  logUserActivity("view_system_stats"),
  authController.getSystemStats
);

// ===== MIXED ROLE ACCESS ROUTES =====

// Routes accessible by multiple roles
router.get(
  "/nearby-collectors",
  hasAnyRole("individual", "rt", "rw"),
  logUserActivity("view_nearby_collectors"),
  authController.getNearbyCollectors
);

router.post(
  "/rate-user/:userId",
  hasAnyRole("individual", "rt", "rw", "collector"),
  checkPermission("create_rating"),
  logUserActivity("rate_user"),
  authController.rateUser
);

router.get(
  "/waste-requests",
  hasAnyRole("individual", "collector", "rt", "rw", "admin"),
  logUserActivity("view_waste_requests"),
  authController.getWasteRequests
);

router.post(
  "/waste-requests",
  authorize("individual"),
  checkPermission("create_order"),
  requirePhoneVerification,
  logUserActivity("create_waste_request"),
  authController.createWasteRequest
);

router.post(
  "/waste-requests/:id/accept",
  authorize("collector"),
  authorizeCollector(),
  checkPermission("accept_orders"),
  logUserActivity("accept_waste_request"),
  authController.acceptWasteRequest
);

router.put(
  "/waste-requests/:id/status",
  hasAnyRole("collector", "admin"),
  checkPermission("update_order_status"),
  logUserActivity("update_waste_request_status"),
  authController.updateWasteRequestStatus
);

// Community management (RT/RW can both access)
router.get(
  "/community/members",
  hasAnyRole("rt", "rw"),
  authorizeArea(),
  logUserActivity("view_community_members"),
  authController.getCommunityMembers
);

router.post(
  "/community/announcements",
  hasAnyRole("rt", "rw"),
  authorizeArea(),
  checkPermission("manage_rt_area"),
  logUserActivity("create_announcement"),
  authController.createAnnouncement
);

// ===== OPTIONAL AUTH ROUTES =====

// Public endpoints that benefit from user context
router.get(
  "/public/collectors/nearby",
  optionalAuth,
  authController.getPublicNearbyCollectors
);

router.get(
  "/public/community-stats",
  optionalAuth,
  authController.getPublicCommunityStats
);

// ===== VALIDATION ROUTES FOR DEVELOPMENT =====

if (process.env.NODE_ENV === "development") {
  router.get("/dev/test-roles", authenticate, (req, res) => {
    res.json({
      user: req.user.email,
      currentRole: req.currentRole,
      availableRoles: req.user.roles
        .filter((r) => r.isActive)
        .map((r) => r.role),
      currentRoleData: req.currentRoleData,
    });
  });

  router.post(
    "/dev/test-permission/:permission",
    authenticate,
    (req, res, next) => {
      checkPermission(req.params.permission)(req, res, next);
    },
    (req, res) => {
      res.json({
        message: `Permission ${req.params.permission} granted for role ${req.currentRole}`,
      });
    }
  );
}

export default router;

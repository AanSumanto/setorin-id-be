import express from "express";
import authController from "../controllers/authController.js";
import {
  authenticate,
  optionalAuth,
  checkPermission,
  logUserActivity,
} from "../middlewares/authMiddleware.js";
import {
  validateRegistration,
  validateLogin,
  validatePasswordReset,
  validatePasswordChange,
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

export default router;

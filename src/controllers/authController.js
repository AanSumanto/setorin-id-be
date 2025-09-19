import authService from "../services/authService.js";
import { createLogger } from "../utils/logger.js";
import { AppError } from "../middlewares/errorMiddleware.js";

const logger = createLogger("AuthController");

class AuthController {
  // Register new user
  async register(req, res, next) {
    try {
      const {
        name,
        email,
        phone,
        password,
        role,
        addresses,
        rtRwData,
        collectorData,
      } = req.body;

      // Basic validation
      if (!name || !email || !phone || !password) {
        return next(
          new AppError("errors.required_field", 400, {
            field: "name, email, phone, password",
          })
        );
      }

      // Prepare user data
      const userData = {
        name: name.trim(),
        email: email.toLowerCase().trim(),
        phone: phone.trim(),
        password,
        role: role || "individual",
      };

      // Add role-specific data
      if (addresses && addresses.length > 0) {
        userData.addresses = addresses;
      }

      if (role === "rt" || role === "rw") {
        if (!rtRwData) {
          return next(
            new AppError("errors.missing_required_data", 400, {
              fields: "RT/RW data",
            })
          );
        }
        userData.rtRwData = rtRwData;
      }

      if (role === "collector") {
        if (!collectorData) {
          return next(
            new AppError("errors.missing_required_data", 400, {
              fields: "Collector data",
            })
          );
        }
        userData.collectorData = collectorData;
      }

      // Get device info
      const deviceInfo = {
        ip: req.ip,
        userAgent: req.get("User-Agent"),
        platform: req.body.platform || "web",
      };

      const result = await authService.register(userData);

      // Log security event
      await authService.logSecurityEvent(
        result.user._id,
        "account_created",
        deviceInfo
      );

      res.success("auth.registration_success", result, 201);
    } catch (error) {
      next(error);
    }
  }

  // Login user
  async login(req, res, next) {
    try {
      const { email, password, rememberMe } = req.body;

      if (!email || !password) {
        return next(
          new AppError("errors.required_field", 400, {
            field: "email, password",
          })
        );
      }

      const credentials = {
        email: email.toLowerCase().trim(),
        password,
        rememberMe: rememberMe || false,
      };

      const deviceInfo = {
        ip: req.ip,
        userAgent: req.get("User-Agent"),
        platform: req.body.platform || "web",
      };

      const result = await authService.login(credentials, deviceInfo);

      // Log security event
      await authService.logSecurityEvent(
        result.user._id,
        "login_success",
        deviceInfo
      );

      res.success("auth.login_success", result);
    } catch (error) {
      // Log failed login attempt
      if (req.body.email) {
        try {
          const deviceInfo = {
            ip: req.ip,
            userAgent: req.get("User-Agent"),
            email: req.body.email,
          };
          await authService.logSecurityEvent(null, "login_failed", deviceInfo);
        } catch (logError) {
          logger.error("Failed to log security event:", logError);
        }
      }
      next(error);
    }
  }

  // Refresh access token
  async refreshToken(req, res, next) {
    try {
      const { refreshToken } = req.body;

      if (!refreshToken) {
        return next(
          new AppError("errors.required_field", 400, { field: "refresh token" })
        );
      }

      const result = await authService.refreshToken(refreshToken);

      res.success("auth.token_refreshed", result);
    } catch (error) {
      next(error);
    }
  }

  // Logout user
  async logout(req, res, next) {
    try {
      const { refreshToken, logoutAllDevices } = req.body;
      const userId = req.user._id;

      const result = await authService.logout(
        userId,
        refreshToken,
        logoutAllDevices
      );

      // Log security event
      const deviceInfo = {
        ip: req.ip,
        userAgent: req.get("User-Agent"),
      };
      await authService.logSecurityEvent(
        userId,
        logoutAllDevices ? "logout_all_devices" : "logout",
        deviceInfo
      );

      res.success("auth.logout_success", result);
    } catch (error) {
      next(error);
    }
  }

  // Verify email
  async verifyEmail(req, res, next) {
    try {
      const { token } = req.params;

      if (!token) {
        return next(
          new AppError("errors.required_field", 400, {
            field: "verification token",
          })
        );
      }

      const result = await authService.verifyEmail(token);

      res.success("auth.email_verified", result);
    } catch (error) {
      next(error);
    }
  }

  // Resend email verification
  async resendEmailVerification(req, res, next) {
    try {
      const userId = req.user._id;

      const result = await authService.resendEmailVerification(userId);

      res.success("auth.verification_email_sent", result);
    } catch (error) {
      next(error);
    }
  }

  // Forgot password
  async forgotPassword(req, res, next) {
    try {
      const { email } = req.body;

      if (!email) {
        return next(
          new AppError("errors.required_field", 400, { field: "email" })
        );
      }

      const result = await authService.forgotPassword(
        email.toLowerCase().trim()
      );

      // Log security event (don't log userId to avoid revealing if email exists)
      const deviceInfo = {
        ip: req.ip,
        userAgent: req.get("User-Agent"),
        email: email,
      };
      await authService.logSecurityEvent(
        null,
        "password_reset_requested",
        deviceInfo
      );

      res.success("auth.password_reset_email_sent", result);
    } catch (error) {
      next(error);
    }
  }

  // Reset password
  async resetPassword(req, res, next) {
    try {
      const { token, newPassword, confirmPassword } = req.body;

      if (!token || !newPassword || !confirmPassword) {
        return next(
          new AppError("errors.required_field", 400, {
            field: "token, new password, confirm password",
          })
        );
      }

      if (newPassword !== confirmPassword) {
        return next(new AppError("errors.passwords_not_match", 400));
      }

      const result = await authService.resetPassword(token, newPassword);

      res.success("auth.password_reset", result);
    } catch (error) {
      next(error);
    }
  }

  // Change password
  async changePassword(req, res, next) {
    try {
      const { currentPassword, newPassword, confirmPassword } = req.body;
      const userId = req.user._id;

      if (!currentPassword || !newPassword || !confirmPassword) {
        return next(
          new AppError("errors.required_field", 400, {
            field: "current password, new password, confirm password",
          })
        );
      }

      if (newPassword !== confirmPassword) {
        return next(new AppError("errors.passwords_not_match", 400));
      }

      const result = await authService.changePassword(
        userId,
        currentPassword,
        newPassword
      );

      // Log security event
      const deviceInfo = {
        ip: req.ip,
        userAgent: req.get("User-Agent"),
      };
      await authService.logSecurityEvent(
        userId,
        "password_changed",
        deviceInfo
      );

      res.success("auth.password_changed", result);
    } catch (error) {
      next(error);
    }
  }

  // Get current user profile
  async getProfile(req, res, next) {
    try {
      const user = req.user;

      // Remove sensitive information
      const userProfile = user.toObject();
      delete userProfile.password;
      delete userProfile.emailVerificationToken;
      delete userProfile.passwordResetToken;

      res.success("auth.profile_retrieved", { user: userProfile });
    } catch (error) {
      next(error);
    }
  }

  // Generate phone OTP
  async generatePhoneOTP(req, res, next) {
    try {
      const { phoneNumber } = req.body;
      const userId = req.user._id;

      if (!phoneNumber) {
        return next(
          new AppError("errors.required_field", 400, { field: "phone number" })
        );
      }

      // Validate Indonesian phone number format
      const phoneRegex = /^(\+62|62|0)[0-9]{9,13}$/;
      if (!phoneRegex.test(phoneNumber)) {
        return next(new AppError("errors.invalid_phone", 400));
      }

      const result = await authService.generatePhoneOTP(userId, phoneNumber);

      res.success("auth.otp_sent", result);
    } catch (error) {
      next(error);
    }
  }

  // Verify phone OTP
  async verifyPhoneOTP(req, res, next) {
    try {
      const { otp } = req.body;
      const userId = req.user._id;

      if (!otp) {
        return next(
          new AppError("errors.required_field", 400, { field: "OTP" })
        );
      }

      const result = await authService.verifyPhoneOTP(userId, otp);

      // Log security event
      const deviceInfo = {
        ip: req.ip,
        userAgent: req.get("User-Agent"),
      };
      await authService.logSecurityEvent(userId, "phone_verified", deviceInfo);

      res.success("auth.phone_verified", result);
    } catch (error) {
      next(error);
    }
  }

  // Check password strength
  async checkPasswordStrength(req, res, next) {
    try {
      const { password } = req.body;

      if (!password) {
        return next(
          new AppError("errors.required_field", 400, { field: "password" })
        );
      }

      const result = await authService.checkPasswordRequirements(password);

      res.success("auth.password_strength_checked", result);
    } catch (error) {
      next(error);
    }
  }

  // Get password policy
  async getPasswordPolicy(req, res, next) {
    try {
      const policy = authService.getPasswordPolicy();

      // Transform policy to multilingual format
      const multilingualPolicy = {
        title: req.t("password_policy.title"),
        requirements: {
          title: req.t("password_policy.requirements"),
          items: [
            req.t("password_policy.min_length"),
            req.t("password_policy.lowercase"),
            req.t("password_policy.uppercase"),
            req.t("password_policy.numbers"),
            req.t("password_policy.symbols"),
            req.t("password_policy.no_common_patterns"),
            req.t("password_policy.not_breached"),
          ],
        },
        recommendations: {
          title: req.t("password_policy.recommendations_title"),
          items: [
            req.t("password_policy.unique_password"),
            req.t("password_policy.password_manager"),
            req.t("password_policy.two_factor"),
            req.t("password_policy.regular_update"),
          ],
        },
        minLength: policy.minLength,
        maxLength: policy.maxLength,
      };

      res.success("auth.password_policy_retrieved", multilingualPolicy);
    } catch (error) {
      next(error);
    }
  }

  // Get user sessions
  async getUserSessions(req, res, next) {
    try {
      const userId = req.user._id;

      const sessions = await authService.getUserSessions(userId);

      res.success("auth.sessions_retrieved", { sessions });
    } catch (error) {
      next(error);
    }
  }

  // Revoke session
  async revokeSession(req, res, next) {
    try {
      const { tokenId } = req.params;
      const userId = req.user._id;

      if (!tokenId) {
        return next(
          new AppError("errors.required_field", 400, { field: "token ID" })
        );
      }

      const result = await authService.revokeSession(userId, tokenId);

      // Log security event
      const deviceInfo = {
        ip: req.ip,
        userAgent: req.get("User-Agent"),
      };
      await authService.logSecurityEvent(userId, "session_revoked", {
        ...deviceInfo,
        tokenId,
      });

      res.success("auth.session_revoked", result);
    } catch (error) {
      next(error);
    }
  }

  // Get account lockout status
  async getAccountLockoutStatus(req, res, next) {
    try {
      const { email } = req.query;

      if (!email) {
        return next(
          new AppError("errors.required_field", 400, { field: "email" })
        );
      }

      const status = await authService.getAccountLockoutStatus(email);

      res.success("auth.lockout_status_retrieved", status);
    } catch (error) {
      next(error);
    }
  }

  // Get security events
  async getSecurityEvents(req, res, next) {
    try {
      const userId = req.user._id;
      const limit = parseInt(req.query.limit) || 20;

      const events = await authService.getSecurityEvents(userId, limit);

      res.success("auth.security_events_retrieved", { events });
    } catch (error) {
      next(error);
    }
  }

  // Validate current session
  async validateSession(req, res, next) {
    try {
      const userId = req.user._id;
      const token = req.token;

      const validation = await authService.validateSession(userId, token);

      res.success("auth.session_validated", {
        valid: validation.valid,
        user: validation.user,
      });
    } catch (error) {
      next(error);
    }
  }

  // Check if email is available
  async checkEmailAvailability(req, res, next) {
    try {
      const { email } = req.query;

      if (!email) {
        return next(
          new AppError("errors.required_field", 400, { field: "email" })
        );
      }

      const { User } = await import("../models/index.js");
      const existingUser = await User.findOne({ email: email.toLowerCase() });

      res.success("auth.email_availability_checked", {
        available: !existingUser,
        email: email.toLowerCase(),
      });
    } catch (error) {
      next(error);
    }
  }

  // Check if phone number is available
  async checkPhoneAvailability(req, res, next) {
    try {
      const { phone } = req.query;

      if (!phone) {
        return next(
          new AppError("errors.required_field", 400, { field: "phone number" })
        );
      }

      const { User } = await import("../models/index.js");
      const existingUser = await User.findOne({ phone });

      res.success("auth.phone_availability_checked", {
        available: !existingUser,
        phone,
      });
    } catch (error) {
      next(error);
    }
  }
}

// Create singleton instance
const authController = new AuthController();

export default authController;

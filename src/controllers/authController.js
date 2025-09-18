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
          new AppError("Name, email, phone, and password are required", 400)
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
            new AppError("RT/RW data is required for this role", 400)
          );
        }
        userData.rtRwData = rtRwData;
      }

      if (role === "collector") {
        if (!collectorData) {
          return next(
            new AppError("Collector data is required for this role", 400)
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

      res.status(201).json({
        status: "success",
        message: "Account created successfully",
        data: result,
      });
    } catch (error) {
      next(error);
    }
  }

  // Login user
  async login(req, res, next) {
    try {
      const { email, password, rememberMe } = req.body;

      if (!email || !password) {
        return next(new AppError("Email and password are required", 400));
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

      res.json({
        status: "success",
        message: "Login successful",
        data: result,
      });
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
        return next(new AppError("Refresh token is required", 400));
      }

      const result = await authService.refreshToken(refreshToken);

      res.json({
        status: "success",
        message: "Token refreshed successfully",
        data: result,
      });
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

      res.json({
        status: "success",
        data: result,
      });
    } catch (error) {
      next(error);
    }
  }

  // Verify email
  async verifyEmail(req, res, next) {
    try {
      const { token } = req.params;

      if (!token) {
        return next(new AppError("Verification token is required", 400));
      }

      const result = await authService.verifyEmail(token);

      res.json({
        status: "success",
        data: result,
      });
    } catch (error) {
      next(error);
    }
  }

  // Resend email verification
  async resendEmailVerification(req, res, next) {
    try {
      const userId = req.user._id;

      const result = await authService.resendEmailVerification(userId);

      res.json({
        status: "success",
        data: result,
      });
    } catch (error) {
      next(error);
    }
  }

  // Forgot password
  async forgotPassword(req, res, next) {
    try {
      const { email } = req.body;

      if (!email) {
        return next(new AppError("Email is required", 400));
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

      res.json({
        status: "success",
        data: result,
      });
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
          new AppError(
            "Token, new password, and confirm password are required",
            400
          )
        );
      }

      if (newPassword !== confirmPassword) {
        return next(new AppError("Passwords do not match", 400));
      }

      const result = await authService.resetPassword(token, newPassword);

      res.json({
        status: "success",
        data: result,
      });
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
          new AppError(
            "Current password, new password, and confirm password are required",
            400
          )
        );
      }

      if (newPassword !== confirmPassword) {
        return next(new AppError("New passwords do not match", 400));
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

      res.json({
        status: "success",
        data: result,
      });
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

      res.json({
        status: "success",
        data: {
          user: userProfile,
        },
      });
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
        return next(new AppError("Phone number is required", 400));
      }

      // Validate Indonesian phone number format
      const phoneRegex = /^(\+62|62|0)[0-9]{9,13}$/;
      if (!phoneRegex.test(phoneNumber)) {
        return next(
          new AppError("Invalid Indonesian phone number format", 400)
        );
      }

      const result = await authService.generatePhoneOTP(userId, phoneNumber);

      res.json({
        status: "success",
        data: result,
      });
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
        return next(new AppError("OTP is required", 400));
      }

      const result = await authService.verifyPhoneOTP(userId, otp);

      // Log security event
      const deviceInfo = {
        ip: req.ip,
        userAgent: req.get("User-Agent"),
      };
      await authService.logSecurityEvent(userId, "phone_verified", deviceInfo);

      res.json({
        status: "success",
        data: result,
      });
    } catch (error) {
      next(error);
    }
  }

  // Check password strength
  async checkPasswordStrength(req, res, next) {
    try {
      const { password } = req.body;

      if (!password) {
        return next(new AppError("Password is required", 400));
      }

      const result = await authService.checkPasswordRequirements(password);

      res.json({
        status: "success",
        data: result,
      });
    } catch (error) {
      next(error);
    }
  }

  // Get password policy
  async getPasswordPolicy(req, res, next) {
    try {
      const policy = authService.getPasswordPolicy();

      res.json({
        status: "success",
        data: policy,
      });
    } catch (error) {
      next(error);
    }
  }

  // Get user sessions
  async getUserSessions(req, res, next) {
    try {
      const userId = req.user._id;

      const sessions = await authService.getUserSessions(userId);

      res.json({
        status: "success",
        data: {
          sessions,
        },
      });
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
        return next(new AppError("Token ID is required", 400));
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

      res.json({
        status: "success",
        data: result,
      });
    } catch (error) {
      next(error);
    }
  }

  // Get account lockout status
  async getAccountLockoutStatus(req, res, next) {
    try {
      const { email } = req.query;

      if (!email) {
        return next(new AppError("Email is required", 400));
      }

      const status = await authService.getAccountLockoutStatus(email);

      res.json({
        status: "success",
        data: status,
      });
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

      res.json({
        status: "success",
        data: {
          events,
        },
      });
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

      res.json({
        status: "success",
        data: {
          valid: validation.valid,
          user: validation.user,
        },
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
        return next(new AppError("Email is required", 400));
      }

      const { User } = await import("../models/index.js");
      const existingUser = await User.findOne({ email: email.toLowerCase() });

      res.json({
        status: "success",
        data: {
          available: !existingUser,
          email: email.toLowerCase(),
        },
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
        return next(new AppError("Phone number is required", 400));
      }

      const { User } = await import("../models/index.js");
      const existingUser = await User.findOne({ phone });

      res.json({
        status: "success",
        data: {
          available: !existingUser,
          phone,
        },
      });
    } catch (error) {
      next(error);
    }
  }
}

// Create singleton instance
const authController = new AuthController();

export default authController;

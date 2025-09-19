import { User } from "../models/index.js";
import jwtManager from "../utils/jwt.js";
import passwordManager from "../utils/password.js";
import { createLogger } from "../utils/logger.js";
import { AppError } from "../middlewares/errorMiddleware.js";
import redisConnection from "../config/redis.js";

const logger = createLogger("AuthService");

class AuthService {
  // Register new user
  async register(userData) {
    try {
      const {
        name,
        email,
        phone,
        password,
        role = "individual",
        ...otherData
      } = userData;

      // Check if user already exists
      const existingUser = await User.findOne({
        $or: [{ email }, { phone }],
      });

      if (existingUser) {
        if (existingUser.email === email) {
          throw new AppError("errors.email_already_registered", 400);
        }
        if (existingUser.phone === phone) {
          throw new AppError("errors.phone_already_registered", 400);
        }
      }

      // Validate password strength
      const passwordValidation =
        passwordManager.validatePasswordStrength(password);
      if (!passwordValidation.isValid) {
        throw new AppError("errors.weak_password", 400, {
          feedback: passwordValidation.feedback.join(", "),
        });
      }

      // Check for breached password
      const breachCheck = await passwordManager.checkPasswordBreach(password);
      if (breachCheck.isBreached) {
        throw new AppError("errors.password_breached", 400);
      }

      // Generate email verification token
      const verificationToken = passwordManager.generateVerificationToken();

      // Create user
      const user = new User({
        name,
        email,
        phone,
        password, // Will be hashed by User model middleware
        role,
        emailVerificationToken: verificationToken.token,
        emailVerificationExpires: verificationToken.expires,
        ...otherData,
      });

      await user.save();

      // Generate JWT tokens
      const { accessToken, refreshToken } = jwtManager.generateTokenPair(user);

      // Store refresh token
      const refreshDecoded = jwtManager.verifyRefreshToken(refreshToken);
      await jwtManager.storeRefreshToken(
        user._id,
        refreshDecoded.tokenId,
        refreshToken
      );

      // Remove sensitive data from response
      const userResponse = user.toObject();
      delete userResponse.password;
      delete userResponse.emailVerificationToken;

      logger.info(`New user registered: ${email} (${role})`);

      return {
        user: userResponse,
        tokens: { accessToken, refreshToken },
        verificationRequired: true,
      };
    } catch (error) {
      logger.error("Registration error:", error);
      throw error;
    }
  }

  // Login user
  async login(credentials, deviceInfo = {}) {
    try {
      const { email, password, rememberMe = false } = credentials;

      // Find user by email
      const user = await User.findOne({ email }).select(
        "+password +loginAttempts +lockUntil"
      );

      if (!user) {
        throw new AppError("errors.invalid_credentials", 401);
      }

      // Check if account is locked
      if (user.isLocked) {
        const remainingTime = Math.ceil(
          (user.lockUntil - Date.now()) / 1000 / 60
        );
        throw new AppError("errors.account_locked", 423, { remainingTime });
      }

      // Verify password
      const isPasswordValid = await user.comparePassword(password);

      if (!isPasswordValid) {
        // Increment login attempts
        await user.incrementLoginAttempts();

        const attemptsLeft = 5 - (user.loginAttempts + 1);
        if (attemptsLeft > 0) {
          throw new AppError("errors.invalid_credentials", 401, {
            attemptsLeft,
          });
        } else {
          throw new AppError("errors.account_locked", 423);
        }
      }

      // Check if user is active
      if (!user.isActive) {
        throw new AppError("errors.account_deactivated", 403);
      }

      // Reset login attempts on successful login
      if (user.loginAttempts > 0) {
        await user.resetLoginAttempts();
      }

      // Update last login
      user.lastLogin = new Date();
      await user.save({ validateBeforeSave: false });

      // Generate JWT tokens
      const tokenExpiry = rememberMe ? "30d" : "7d";
      const { accessToken, refreshToken } = jwtManager.generateTokenPair(user);

      // Store refresh token
      const refreshDecoded = jwtManager.verifyRefreshToken(refreshToken);
      await jwtManager.storeRefreshToken(
        user._id,
        refreshDecoded.tokenId,
        refreshToken
      );

      // Log successful login
      logger.info(`User logged in: ${email} (${user.role})`, {
        userId: user._id,
        deviceInfo,
        ip: deviceInfo.ip,
      });

      // Remove sensitive data
      const userResponse = user.toObject();
      delete userResponse.password;
      delete userResponse.loginAttempts;
      delete userResponse.lockUntil;

      return {
        user: userResponse,
        tokens: { accessToken, refreshToken },
        requiresEmailVerification: !user.isEmailVerified,
      };
    } catch (error) {
      logger.error("Login error:", error);
      throw error;
    }
  }

  // Refresh access token
  async refreshToken(refreshToken) {
    try {
      const result = await jwtManager.refreshAccessToken(refreshToken);

      logger.info(`Token refreshed for user: ${result.user.email}`);

      return {
        accessToken: result.accessToken,
        user: result.user,
      };
    } catch (error) {
      logger.error("Token refresh error:", error);
      throw new AppError("Invalid or expired refresh token", 401);
    }
  }

  // Logout user
  async logout(userId, refreshToken, logoutAllDevices = false) {
    try {
      if (logoutAllDevices) {
        // Remove all refresh tokens for user
        await jwtManager.removeAllRefreshTokens(userId);
        logger.info(`User logged out from all devices: ${userId}`);
      } else if (refreshToken) {
        // Remove specific refresh token
        const decoded = jwtManager.verifyRefreshToken(refreshToken);
        await jwtManager.removeRefreshToken(userId, decoded.tokenId);
        logger.info(`User logged out: ${userId}`);
      }

      return { message: "Logged out successfully" };
    } catch (error) {
      logger.error("Logout error:", error);
      throw error;
    }
  }

  // Verify email
  async verifyEmail(token) {
    try {
      const user = await User.findOne({
        emailVerificationToken: token,
        emailVerificationExpires: { $gt: Date.now() },
      });

      if (!user) {
        throw new AppError("Invalid or expired verification token", 400);
      }

      user.isEmailVerified = true;
      user.emailVerificationToken = undefined;
      user.emailVerificationExpires = undefined;
      await user.save();

      logger.info(`Email verified for user: ${user.email}`);

      return { message: "Email verified successfully" };
    } catch (error) {
      logger.error("Email verification error:", error);
      throw error;
    }
  }

  // Resend email verification
  async resendEmailVerification(userId) {
    try {
      const user = await User.findById(userId);

      if (!user) {
        throw new AppError("User not found", 404);
      }

      if (user.isEmailVerified) {
        throw new AppError("Email already verified", 400);
      }

      // Generate new verification token
      const verificationToken = passwordManager.generateVerificationToken();

      user.emailVerificationToken = verificationToken.token;
      user.emailVerificationExpires = verificationToken.expires;
      await user.save();

      logger.info(`Email verification resent for user: ${user.email}`);

      return {
        message: "Verification email sent",
        token: verificationToken.token, // For testing purposes
      };
    } catch (error) {
      logger.error("Resend verification error:", error);
      throw error;
    }
  }

  // Forgot password
  async forgotPassword(email) {
    try {
      const user = await User.findOne({ email });

      if (!user) {
        // Don't reveal if email exists or not
        return { message: "If the email exists, a reset link has been sent" };
      }

      // Generate password reset token
      const resetTokenData = passwordManager.generateResetToken();

      user.passwordResetToken = resetTokenData.hashedToken;
      user.passwordResetExpires = resetTokenData.expires;
      await user.save();

      logger.info(`Password reset requested for user: ${email}`);

      return {
        message: "If the email exists, a reset link has been sent",
        resetToken: resetTokenData.token, // For testing purposes
      };
    } catch (error) {
      logger.error("Forgot password error:", error);
      throw error;
    }
  }

  // Reset password
  async resetPassword(token, newPassword) {
    try {
      // Hash the token to compare with stored token
      const hashedToken = passwordManager.verifyResetToken(token);

      const user = await User.findOne({
        passwordResetToken: hashedToken,
        passwordResetExpires: { $gt: Date.now() },
      });

      if (!user) {
        throw new AppError("Invalid or expired reset token", 400);
      }

      // Validate new password
      const passwordValidation =
        passwordManager.validatePasswordStrength(newPassword);
      if (!passwordValidation.isValid) {
        throw new AppError(
          `Weak password: ${passwordValidation.feedback.join(", ")}`,
          400
        );
      }

      // Check for breached password
      const breachCheck = await passwordManager.checkPasswordBreach(
        newPassword
      );
      if (breachCheck.isBreached) {
        throw new AppError(breachCheck.message, 400);
      }

      // Update password
      user.password = newPassword; // Will be hashed by middleware
      user.passwordResetToken = undefined;
      user.passwordResetExpires = undefined;

      // Reset login attempts
      user.loginAttempts = undefined;
      user.lockUntil = undefined;

      await user.save();

      // Invalidate all existing refresh tokens
      await jwtManager.removeAllRefreshTokens(user._id);

      logger.info(`Password reset completed for user: ${user.email}`);

      return { message: "Password reset successfully" };
    } catch (error) {
      logger.error("Reset password error:", error);
      throw error;
    }
  }

  // Change password (for authenticated users)
  async changePassword(userId, currentPassword, newPassword) {
    try {
      const user = await User.findById(userId).select("+password");

      if (!user) {
        throw new AppError("User not found", 404);
      }

      // Verify current password
      const isCurrentPasswordValid = await user.comparePassword(
        currentPassword
      );
      if (!isCurrentPasswordValid) {
        throw new AppError("Current password is incorrect", 400);
      }

      // Validate new password
      const passwordValidation =
        passwordManager.validatePasswordStrength(newPassword);
      if (!passwordValidation.isValid) {
        throw new AppError(
          `Weak password: ${passwordValidation.feedback.join(", ")}`,
          400
        );
      }

      // Check if new password is different from current
      const isSamePassword = await user.comparePassword(newPassword);
      if (isSamePassword) {
        throw new AppError(
          "New password must be different from current password",
          400
        );
      }

      // Check for breached password
      const breachCheck = await passwordManager.checkPasswordBreach(
        newPassword
      );
      if (breachCheck.isBreached) {
        throw new AppError(breachCheck.message, 400);
      }

      // Update password
      user.password = newPassword; // Will be hashed by middleware
      await user.save();

      // Optionally invalidate all refresh tokens except current session
      // await jwtManager.removeAllRefreshTokens(user._id);

      logger.info(`Password changed for user: ${user.email}`);

      return { message: "Password changed successfully" };
    } catch (error) {
      logger.error("Change password error:", error);
      throw error;
    }
  }

  // Check if user session is valid
  async validateSession(userId, token) {
    try {
      // Check if token is blacklisted
      if (await jwtManager.isTokenBlacklisted(token)) {
        return { valid: false, reason: "Token blacklisted" };
      }

      // Get user
      const user = await User.findById(userId);
      if (!user || !user.isActive) {
        return { valid: false, reason: "User not found or inactive" };
      }

      return { valid: true, user };
    } catch (error) {
      logger.error("Session validation error:", error);
      return { valid: false, reason: "Validation failed" };
    }
  }

  // Get user sessions (refresh tokens)
  async getUserSessions(userId) {
    try {
      const userTokensKey = `user_refresh_tokens:${userId}`;
      const tokenIds =
        (await redisConnection.client?.sMembers(userTokensKey)) || [];

      const sessions = [];
      for (const tokenId of tokenIds) {
        const key = `refresh_token:${userId}:${tokenId}`;
        const token = await redisConnection.get(key);
        if (token) {
          const decoded = jwtManager.decodeToken(token);
          sessions.push({
            tokenId,
            createdAt: new Date(decoded.payload.iat * 1000),
            expiresAt: new Date(decoded.payload.exp * 1000),
            isActive: true,
          });
        }
      }

      return sessions;
    } catch (error) {
      logger.error("Get user sessions error:", error);
      return [];
    }
  }

  // Revoke specific session
  async revokeSession(userId, tokenId) {
    try {
      await jwtManager.removeRefreshToken(userId, tokenId);
      logger.info(`Session revoked for user ${userId}, token ${tokenId}`);
      return { message: "Session revoked successfully" };
    } catch (error) {
      logger.error("Revoke session error:", error);
      throw error;
    }
  }

  // Generate and send OTP for phone verification
  async generatePhoneOTP(userId, phoneNumber) {
    try {
      const user = await User.findById(userId);
      if (!user) {
        throw new AppError("User not found", 404);
      }

      // Check rate limiting
      const otpKey = `phone_otp:${userId}`;
      const existingOTP = await redisConnection.get(otpKey);

      if (existingOTP) {
        throw new AppError(
          "OTP already sent. Please wait before requesting again.",
          429
        );
      }

      // Generate OTP
      const otpData = passwordManager.generateOTP(6);

      // Store OTP in Redis with expiry
      await redisConnection.set(
        otpKey,
        JSON.stringify({
          otp: otpData.otp,
          phone: phoneNumber,
          expires: otpData.expires,
        }),
        300
      ); // 5 minutes

      // In production, send OTP via SMS service
      logger.info(`Phone OTP generated for user ${userId}: ${otpData.otp}`);

      return {
        message: "OTP sent to your phone number",
        otp: process.env.NODE_ENV === "development" ? otpData.otp : undefined,
      };
    } catch (error) {
      logger.error("Generate phone OTP error:", error);
      throw error;
    }
  }

  // Verify phone OTP
  async verifyPhoneOTP(userId, otp) {
    try {
      const user = await User.findById(userId);
      if (!user) {
        throw new AppError("User not found", 404);
      }

      const otpKey = `phone_otp:${userId}`;
      const storedData = await redisConnection.get(otpKey);

      if (!storedData) {
        throw new AppError("OTP not found or expired", 400);
      }

      const { otp: storedOTP, expires, phone } = JSON.parse(storedData);

      if (!passwordManager.verifyOTP(otp, storedOTP, new Date(expires))) {
        throw new AppError("Invalid or expired OTP", 400);
      }

      // Update user phone verification status
      user.isPhoneVerified = true;
      user.phone = phone; // Update phone if different
      await user.save();

      // Remove OTP from Redis
      await redisConnection.del(otpKey);

      logger.info(`Phone verified for user: ${user.email}`);

      return { message: "Phone number verified successfully" };
    } catch (error) {
      logger.error("Verify phone OTP error:", error);
      throw error;
    }
  }

  // Check password requirements
  async checkPasswordRequirements(password) {
    try {
      const validation = passwordManager.validatePasswordStrength(password);
      const breachCheck = await passwordManager.checkPasswordBreach(password);
      const entropy = passwordManager.calculatePasswordEntropy(password);

      return {
        isValid: validation.isValid && !breachCheck.isBreached,
        score: validation.score,
        strength: entropy.strength,
        entropy: entropy.entropy,
        requirements: validation.requirements,
        feedback: validation.feedback,
        isBreached: breachCheck.isBreached,
        breachMessage: breachCheck.message,
      };
    } catch (error) {
      logger.error("Check password requirements error:", error);
      throw error;
    }
  }

  // Get password policy
  getPasswordPolicy() {
    return passwordManager.getPasswordPolicy();
  }

  // Account lockout status
  async getAccountLockoutStatus(email) {
    try {
      const user = await User.findOne({ email }).select(
        "+loginAttempts +lockUntil"
      );

      if (!user) {
        return { locked: false };
      }

      if (user.isLocked) {
        const remainingTime = Math.ceil(
          (user.lockUntil - Date.now()) / 1000 / 60
        );
        return {
          locked: true,
          remainingTime,
          attempts: user.loginAttempts,
        };
      }

      return {
        locked: false,
        attempts: user.loginAttempts || 0,
        maxAttempts: 5,
      };
    } catch (error) {
      logger.error("Get account lockout status error:", error);
      return { locked: false };
    }
  }

  // Security audit log
  async logSecurityEvent(userId, event, details = {}) {
    try {
      const securityLog = {
        userId,
        event,
        details,
        timestamp: new Date(),
        ip: details.ip,
        userAgent: details.userAgent,
      };

      // Store in Redis for recent events
      const logKey = `security_log:${userId}`;
      const logs = (await redisConnection.get(logKey)) || [];
      logs.push(securityLog);

      // Keep only last 50 events
      if (logs.length > 50) {
        logs.splice(0, logs.length - 50);
      }

      await redisConnection.set(logKey, logs, 86400 * 7); // 7 days

      logger.info(
        `Security event logged: ${event} for user ${userId}`,
        securityLog
      );
    } catch (error) {
      logger.error("Log security event error:", error);
    }
  }

  // Get security events for user
  async getSecurityEvents(userId, limit = 20) {
    try {
      const logKey = `security_log:${userId}`;
      const logs = (await redisConnection.get(logKey)) || [];

      return logs.slice(-limit).reverse(); // Most recent first
    } catch (error) {
      logger.error("Get security events error:", error);
      return [];
    }
  }
}

// Create singleton instance
const authService = new AuthService();

export default authService;

import { User } from "../models/index.js";
import jwtManager from "../utils/jwt.js";
import passwordManager from "../utils/password.js";
import { createLogger } from "../utils/logger.js";
import { AppError } from "../middlewares/errorMiddleware.js";
import redisConnection from "../config/redis.js";

const logger = createLogger("AuthService");

class AuthService {
  // Register new user (updated for multi-role and email optional)
  async register(userData) {
    try {
      const {
        name,
        email,
        phone,
        password,
        currentRole = "individual",
        roles = [],
        ...otherData
      } = userData;

      // Check if email is provided and already exists
      if (email) {
        const existingUserByEmail = await User.findOne({ email });
        if (existingUserByEmail) {
          throw new AppError("errors.email_already_registered", 400);
        }
      }

      // Check if phone is used by different person (different email)
      let phoneQuery = { phone };
      if (email) {
        phoneQuery.email = { $ne: email };
      }

      const existingUserByPhone = await User.findOne(phoneQuery);
      if (existingUserByPhone) {
        throw new AppError("errors.phone_used_by_different_user", 400);
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

      // Generate email verification token only if email provided
      let verificationToken = null;
      if (email) {
        verificationToken = passwordManager.generateVerificationToken();
      }

      // Create user with multi-role structure
      const userData_final = {
        name,
        phone,
        password, // Will be hashed by User model middleware
        currentRole,
        roles:
          roles.length > 0
            ? roles
            : [
                {
                  role: currentRole,
                  isPrimary: true,
                  isActive: true,
                },
              ],
        ...otherData,
      };

      // Add email fields only if email is provided
      if (email) {
        userData_final.email = email;
        userData_final.emailVerificationToken = verificationToken.token;
        userData_final.emailVerificationExpires = verificationToken.expires;
      }

      const user = new User(userData_final);
      await user.save();

      // Generate JWT tokens with role information
      const { accessToken, refreshToken } = this.generateTokens(user);

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

      logger.info(
        `New user registered: ${email || phone} (current role: ${currentRole})`
      );

      return {
        user: userResponse,
        tokens: { accessToken, refreshToken },
        verificationRequired: email ? !user.isEmailVerified : false,
      };
    } catch (error) {
      logger.error("Registration error:", error);
      throw error;
    }
  }

  // Login user with role selection (updated for email optional)
  async loginWithRole(credentials, deviceInfo = {}) {
    try {
      const {
        email,
        phone,
        password,
        selectedRole,
        rememberMe = false,
      } = credentials;

      // Find user by email OR phone
      let user;
      if (email) {
        user = await User.findOne({ email }).select(
          "+password +loginAttempts +lockUntil"
        );
      } else if (phone) {
        user = await User.findOne({ phone }).select(
          "+password +loginAttempts +lockUntil"
        );
      } else {
        throw new AppError("errors.email_or_phone_required", 400);
      }

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

      // Handle role selection
      if (selectedRole) {
        const hasRole = user.roles.find(
          (r) => r.role === selectedRole && r.isActive
        );
        if (!hasRole) {
          throw new AppError("errors.role_not_available", 403, {
            role: selectedRole,
          });
        }
        user.currentRole = selectedRole;
      } else {
        // Use primary role if no role selected
        const primaryRole = user.roles.find((r) => r.isPrimary);
        user.currentRole = primaryRole?.role || user.roles[0]?.role;
      }

      // Reset login attempts on successful login
      if (user.loginAttempts > 0) {
        await user.resetLoginAttempts();
      }

      // Update last login
      user.lastLogin = new Date();
      await user.save({ validateBeforeSave: false });

      // Generate JWT tokens with role information
      const { accessToken, refreshToken } = this.generateTokens(
        user,
        rememberMe
      );

      // Store refresh token
      const refreshDecoded = jwtManager.verifyRefreshToken(refreshToken);
      await jwtManager.storeRefreshToken(
        user._id,
        refreshDecoded.tokenId,
        refreshToken
      );

      // Log successful login
      const loginIdentifier = email || phone;
      logger.info(
        `User logged in: ${loginIdentifier} (current role: ${user.currentRole})`,
        {
          userId: user._id,
          selectedRole: user.currentRole,
          availableRoles: user.roles
            .filter((r) => r.isActive)
            .map((r) => r.role),
          deviceInfo,
          ip: deviceInfo.ip,
        }
      );

      // Remove sensitive data
      const userResponse = user.toObject();
      delete userResponse.password;
      delete userResponse.loginAttempts;
      delete userResponse.lockUntil;

      return {
        user: userResponse,
        tokens: { accessToken, refreshToken },
        availableRoles: user.roles.filter((r) => r.isActive),
        currentRoleData: user.currentRoleData,
        requiresEmailVerification: user.email ? !user.isEmailVerified : false,
      };
    } catch (error) {
      logger.error("Login error:", error);
      throw error;
    }
  }

  // Switch user role (NEW)
  async switchUserRole(userId, roleName) {
    try {
      const user = await User.findById(userId);

      if (!user) {
        throw new AppError("errors.user_not_found", 404);
      }

      // Check if user has the role
      const role = user.roles.find((r) => r.role === roleName && r.isActive);
      if (!role) {
        throw new AppError("errors.role_not_available", 403, {
          role: roleName,
        });
      }

      // Switch role
      await user.switchRole(roleName);

      // Generate new tokens with updated role
      const { accessToken, refreshToken } = this.generateTokens(user);

      const userIdentifier = user.email || user.phone;
      logger.info(
        `Role switched: ${userIdentifier} from ${user.currentRole} to ${roleName}`
      );

      return {
        currentRole: roleName,
        currentRoleData: user.currentRoleData,
        tokens: { accessToken, refreshToken },
      };
    } catch (error) {
      logger.error("Switch role error:", error);
      throw error;
    }
  }

  // Generate JWT tokens with role information (updated for email optional)
  generateTokens(user, rememberMe = false) {
    const payload = {
      id: user._id, // Keep compatibility with existing JWT utils
      userId: user._id,
      email: user.email || null, // Can be null now
      phone: user.phone, // Add phone as fallback identifier
      currentRole: user.currentRole,
      roles: user.roles.filter((r) => r.isActive).map((r) => r.role),
      tokenVersion: Date.now(), // For token invalidation
    };

    const accessTokenExpiry = rememberMe ? "30d" : "1h";
    const refreshTokenExpiry = rememberMe ? "90d" : "7d";

    // Use existing jwtManager but with extended payload
    const accessToken = jwtManager.generateAccessToken(
      payload,
      accessTokenExpiry
    );
    const refreshToken = jwtManager.generateRefreshToken(user);

    return {
      accessToken,
      refreshToken,
      expiresIn: rememberMe ? 30 * 24 * 60 * 60 : 60 * 60, // in seconds
    };
  }

  // Legacy login method (keep for backward compatibility)
  async login(credentials, deviceInfo = {}) {
    return this.loginWithRole(credentials, deviceInfo);
  }

  // Refresh access token (updated for multi-role)
  async refreshToken(refreshToken) {
    try {
      // Verify refresh token
      const decoded = jwtManager.verifyRefreshToken(refreshToken);

      // Get user with current role info
      const user = await User.findById(decoded.id || decoded.userId);

      if (!user || !user.isActive) {
        throw new AppError("Invalid or expired refresh token", 401);
      }

      // Generate new access token with current role
      const { accessToken } = this.generateTokens(user);

      const userIdentifier = user.email || user.phone;
      logger.info(
        `Token refreshed for user: ${userIdentifier} (role: ${user.currentRole})`
      );

      return {
        accessToken,
        user: {
          id: user._id,
          email: user.email,
          phone: user.phone,
          currentRole: user.currentRole,
          roles: user.roles.filter((r) => r.isActive),
        },
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

  // Add points to specific role (NEW)
  async addPointsToRole(
    userId,
    points,
    roleName = null,
    reason = "Transaction"
  ) {
    try {
      const user = await User.findById(userId);

      if (!user) {
        throw new AppError("errors.user_not_found", 404);
      }

      await user.addPointsToRole(points, roleName, reason);

      return {
        success: true,
        pointsAdded: points,
        role: roleName || user.currentRole,
        reason,
      };
    } catch (error) {
      logger.error("Add points to role error:", error);
      throw error;
    }
  }

  // Deduct points from specific role (NEW)
  async deductPointsFromRole(userId, points, roleName = null) {
    try {
      const user = await User.findById(userId);

      if (!user) {
        throw new AppError("errors.user_not_found", 404);
      }

      await user.deductPointsFromRole(points, roleName);

      return {
        success: true,
        pointsDeducted: points,
        role: roleName || user.currentRole,
      };
    } catch (error) {
      logger.error("Deduct points from role error:", error);
      throw error;
    }
  }

  // Update rating for specific role (NEW)
  async updateRoleRating(userId, rating, roleName = null) {
    try {
      const user = await User.findById(userId);

      if (!user) {
        throw new AppError("errors.user_not_found", 404);
      }

      await user.updateRoleRating(rating, roleName);

      const targetRole = roleName || user.currentRole;
      const roleData = user.roles.find((r) => r.role === targetRole);

      return {
        success: true,
        role: targetRole,
        newRating: roleData.rating.average,
        totalReviews: roleData.rating.count,
      };
    } catch (error) {
      logger.error("Update role rating error:", error);
      throw error;
    }
  }

  // Get users by specific role (NEW)
  async getUsersByRole(role, options = {}) {
    try {
      const {
        limit = 10,
        skip = 0,
        coordinates = null,
        radiusInKm = 10,
        sortBy = "rating",
      } = options;

      let users;

      // Add geospatial filter if coordinates provided
      if (coordinates) {
        users = await User.findNearbyByRole(coordinates, role, radiusInKm);
      } else {
        users = await User.findByRole(role);
      }

      // Apply sorting and pagination
      if (sortBy === "rating") {
        users = users.sort((a, b) => {
          const aRole = a.roles.find((r) => r.role === role);
          const bRole = b.roles.find((r) => r.role === role);
          return (bRole.rating.average || 0) - (aRole.rating.average || 0);
        });
      } else if (sortBy === "newest") {
        users = users.sort(
          (a, b) => new Date(b.createdAt) - new Date(a.createdAt)
        );
      }

      const paginatedUsers = users.slice(skip, skip + limit);

      // Format response with role-specific data
      const formattedUsers = paginatedUsers.map((user) => {
        const userRole = user.roles.find((r) => r.role === role);
        return {
          _id: user._id,
          name: user.name,
          email: user.email,
          phone: user.phone,
          addresses: user.addresses,
          roleData: userRole,
          rating: userRole.rating,
          points: userRole.points,
          createdAt: user.createdAt,
        };
      });

      return formattedUsers;
    } catch (error) {
      logger.error("Get users by role error:", error);
      throw error;
    }
  }

  // Verify email (handle case where email is null)
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

      const userIdentifier = user.email || user.phone;
      logger.info(`Email verified for user: ${userIdentifier}`);

      return { message: "Email verified successfully" };
    } catch (error) {
      logger.error("Email verification error:", error);
      throw error;
    }
  }

  // Resend email verification (handle case where email is null)
  async resendEmailVerification(userId) {
    try {
      const user = await User.findById(userId);

      if (!user) {
        throw new AppError("User not found", 404);
      }

      if (!user.email) {
        throw new AppError("User has no email address", 400);
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

  // Forgot password (updated for email optional)
  async forgotPassword(identifier) {
    try {
      // Try to find user by email or phone
      let user;
      if (identifier.includes("@")) {
        // Looks like an email
        user = await User.findOne({ email: identifier });
      } else {
        // Assume it's a phone number
        user = await User.findOne({ phone: identifier });
      }

      if (!user) {
        // Don't reveal if identifier exists or not
        return { message: "If the account exists, a reset code has been sent" };
      }

      // For users with email, send email reset
      if (user.email && identifier.includes("@")) {
        const resetTokenData = passwordManager.generateResetToken();
        user.passwordResetToken = resetTokenData.hashedToken;
        user.passwordResetExpires = resetTokenData.expires;
        await user.save();

        logger.info(`Password reset requested for user: ${user.email}`);
        return {
          message: "If the email exists, a reset link has been sent",
          resetToken: resetTokenData.token, // For testing purposes
        };
      } else {
        // For phone-only users, generate OTP
        const otpData = passwordManager.generateOTP(6);
        const otpKey = `password_reset_otp:${user.phone}`;

        await redisConnection.set(
          otpKey,
          JSON.stringify({
            otp: otpData.otp,
            userId: user._id,
            expires: otpData.expires,
          }),
          300 // 5 minutes
        );

        logger.info(`Password reset OTP sent for user: ${user.phone}`);
        return {
          message: "If the phone number exists, a reset code has been sent",
          otp: process.env.NODE_ENV === "development" ? otpData.otp : undefined,
        };
      }
    } catch (error) {
      logger.error("Forgot password error:", error);
      throw error;
    }
  }

  // Reset password via OTP (NEW for phone-only users)
  async resetPasswordWithOTP(phone, otp, newPassword) {
    try {
      const otpKey = `password_reset_otp:${phone}`;
      const storedData = await redisConnection.get(otpKey);

      if (!storedData) {
        throw new AppError("OTP not found or expired", 400);
      }

      const { otp: storedOTP, userId, expires } = JSON.parse(storedData);

      if (!passwordManager.verifyOTP(otp, storedOTP, new Date(expires))) {
        throw new AppError("Invalid or expired OTP", 400);
      }

      const user = await User.findById(userId);
      if (!user) {
        throw new AppError("User not found", 404);
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

      // Update password
      user.password = newPassword;
      user.loginAttempts = undefined;
      user.lockUntil = undefined;
      await user.save();

      // Remove OTP and invalidate all tokens
      await redisConnection.del(otpKey);
      await jwtManager.removeAllRefreshTokens(user._id);

      logger.info(`Password reset completed via OTP for user: ${user.phone}`);
      return { message: "Password reset successfully" };
    } catch (error) {
      logger.error("Reset password with OTP error:", error);
      throw error;
    }
  }

  // Reset password (existing method, unchanged)
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

      const userIdentifier = user.email || user.phone;
      logger.info(`Password reset completed for user: ${userIdentifier}`);

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

      const userIdentifier = user.email || user.phone;
      logger.info(`Password changed for user: ${userIdentifier}`);

      return { message: "Password changed successfully" };
    } catch (error) {
      logger.error("Change password error:", error);
      throw error;
    }
  }

  // Check if user session is valid (updated for multi-role)
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

      // Verify token contains current role info
      const decoded = jwtManager.verifyAccessToken(token);
      if (decoded.currentRole !== user.currentRole) {
        return { valid: false, reason: "Role mismatch - please login again" };
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

      const userIdentifier = user.email || user.phone;
      logger.info(`Phone verified for user: ${userIdentifier}`);

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

  // Account lockout status (updated for email optional)
  async getAccountLockoutStatus(identifier) {
    try {
      let user;
      if (identifier.includes("@")) {
        user = await User.findOne({ email: identifier }).select(
          "+loginAttempts +lockUntil"
        );
      } else {
        user = await User.findOne({ phone: identifier }).select(
          "+loginAttempts +lockUntil"
        );
      }

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

  // Security audit log (updated with role info)
  async logSecurityEvent(userId, event, details = {}) {
    try {
      const securityLog = {
        userId,
        event,
        details,
        timestamp: new Date(),
        ip: details.ip,
        userAgent: details.userAgent,
        role: details.role || details.currentRole,
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

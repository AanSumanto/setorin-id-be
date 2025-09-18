import jwt from "jsonwebtoken";
import { createLogger } from "./logger.js";
import redisConnection from "../config/redis.js";

const logger = createLogger("JWT");

class JWTManager {
  constructor() {
    this.accessTokenSecret = process.env.JWT_SECRET;
    this.refreshTokenSecret = process.env.JWT_REFRESH_SECRET;
    this.accessTokenExpiry = process.env.JWT_EXPIRE || "7d";
    this.refreshTokenExpiry = process.env.JWT_REFRESH_EXPIRE || "30d";

    if (!this.accessTokenSecret || !this.refreshTokenSecret) {
      throw new Error("JWT secrets are not configured");
    }
  }

  // Generate access token
  generateAccessToken(payload) {
    try {
      const tokenPayload = {
        id: payload.id,
        email: payload.email,
        role: payload.role,
        isEmailVerified: payload.isEmailVerified,
        isActive: payload.isActive,
        tokenType: "access",
      };

      return jwt.sign(tokenPayload, this.accessTokenSecret, {
        expiresIn: this.accessTokenExpiry,
        issuer: "setorin-api",
        audience: "setorin-client",
      });
    } catch (error) {
      logger.error("Error generating access token:", error);
      throw new Error("Failed to generate access token");
    }
  }

  // Generate refresh token
  generateRefreshToken(payload) {
    try {
      const tokenPayload = {
        id: payload.id,
        email: payload.email,
        tokenType: "refresh",
        tokenId: this.generateTokenId(), // Unique token ID for revocation
      };

      return jwt.sign(tokenPayload, this.refreshTokenSecret, {
        expiresIn: this.refreshTokenExpiry,
        issuer: "setorin-api",
        audience: "setorin-client",
      });
    } catch (error) {
      logger.error("Error generating refresh token:", error);
      throw new Error("Failed to generate refresh token");
    }
  }

  // Generate both tokens
  generateTokenPair(user) {
    const payload = {
      id: user._id.toString(),
      email: user.email,
      role: user.role,
      isEmailVerified: user.isEmailVerified,
      isActive: user.isActive,
    };

    const accessToken = this.generateAccessToken(payload);
    const refreshToken = this.generateRefreshToken(payload);

    return { accessToken, refreshToken };
  }

  // Verify access token
  verifyAccessToken(token) {
    try {
      const decoded = jwt.verify(token, this.accessTokenSecret, {
        issuer: "setorin-api",
        audience: "setorin-client",
      });

      if (decoded.tokenType !== "access") {
        throw new Error("Invalid token type");
      }

      return decoded;
    } catch (error) {
      if (error.name === "JsonWebTokenError") {
        throw new Error("Invalid token");
      } else if (error.name === "TokenExpiredError") {
        throw new Error("Token expired");
      } else {
        logger.error("Error verifying access token:", error);
        throw new Error("Token verification failed");
      }
    }
  }

  // Verify refresh token
  verifyRefreshToken(token) {
    try {
      const decoded = jwt.verify(token, this.refreshTokenSecret, {
        issuer: "setorin-api",
        audience: "setorin-client",
      });

      if (decoded.tokenType !== "refresh") {
        throw new Error("Invalid token type");
      }

      return decoded;
    } catch (error) {
      if (error.name === "JsonWebTokenError") {
        throw new Error("Invalid refresh token");
      } else if (error.name === "TokenExpiredError") {
        throw new Error("Refresh token expired");
      } else {
        logger.error("Error verifying refresh token:", error);
        throw new Error("Refresh token verification failed");
      }
    }
  }

  // Decode token without verification (for expired token handling)
  decodeToken(token) {
    try {
      return jwt.decode(token, { complete: true });
    } catch (error) {
      logger.error("Error decoding token:", error);
      return null;
    }
  }

  // Generate unique token ID for refresh token tracking
  generateTokenId() {
    return Date.now().toString(36) + Math.random().toString(36).substr(2);
  }

  // Store refresh token in Redis with expiration
  async storeRefreshToken(userId, tokenId, token) {
    try {
      const key = `refresh_token:${userId}:${tokenId}`;
      const expiry = this.parseExpiry(this.refreshTokenExpiry);

      await redisConnection.set(key, token, expiry);

      // Also maintain a set of all refresh tokens for a user
      const userTokensKey = `user_refresh_tokens:${userId}`;
      await redisConnection.client?.sAdd(userTokensKey, tokenId);
      await redisConnection.client?.expire(userTokensKey, expiry);

      logger.info(`Refresh token stored for user ${userId}`);
      return true;
    } catch (error) {
      logger.error("Error storing refresh token:", error);
      return false;
    }
  }

  // Verify refresh token from Redis
  async verifyStoredRefreshToken(userId, tokenId, token) {
    try {
      const key = `refresh_token:${userId}:${tokenId}`;
      const storedToken = await redisConnection.get(key);

      if (!storedToken || storedToken !== token) {
        return false;
      }

      return true;
    } catch (error) {
      logger.error("Error verifying stored refresh token:", error);
      return false;
    }
  }

  // Remove refresh token from Redis
  async removeRefreshToken(userId, tokenId) {
    try {
      const key = `refresh_token:${userId}:${tokenId}`;
      await redisConnection.del(key);

      // Remove from user's token set
      const userTokensKey = `user_refresh_tokens:${userId}`;
      await redisConnection.client?.sRem(userTokensKey, tokenId);

      logger.info(`Refresh token removed for user ${userId}`);
      return true;
    } catch (error) {
      logger.error("Error removing refresh token:", error);
      return false;
    }
  }

  // Remove all refresh tokens for a user (logout all devices)
  async removeAllRefreshTokens(userId) {
    try {
      const userTokensKey = `user_refresh_tokens:${userId}`;
      const tokenIds =
        (await redisConnection.client?.sMembers(userTokensKey)) || [];

      // Remove all individual tokens
      for (const tokenId of tokenIds) {
        const key = `refresh_token:${userId}:${tokenId}`;
        await redisConnection.del(key);
      }

      // Remove the token set
      await redisConnection.del(userTokensKey);

      logger.info(`All refresh tokens removed for user ${userId}`);
      return true;
    } catch (error) {
      logger.error("Error removing all refresh tokens:", error);
      return false;
    }
  }

  // Check if token is blacklisted
  async isTokenBlacklisted(token) {
    try {
      const key = `blacklisted_token:${token}`;
      return await redisConnection.exists(key);
    } catch (error) {
      logger.error("Error checking token blacklist:", error);
      return false;
    }
  }

  // Blacklist a token (for immediate logout)
  async blacklistToken(token, expiry) {
    try {
      const key = `blacklisted_token:${token}`;
      const expirySeconds = expiry
        ? Math.max(0, Math.floor((expiry - Date.now()) / 1000))
        : 86400;

      if (expirySeconds > 0) {
        await redisConnection.set(key, "blacklisted", expirySeconds);
      }

      logger.info("Token blacklisted successfully");
      return true;
    } catch (error) {
      logger.error("Error blacklisting token:", error);
      return false;
    }
  }

  // Refresh access token using refresh token
  async refreshAccessToken(refreshToken) {
    try {
      // Verify refresh token
      const decoded = this.verifyRefreshToken(refreshToken);

      // Check if refresh token is stored and valid
      const isValid = await this.verifyStoredRefreshToken(
        decoded.id,
        decoded.tokenId,
        refreshToken
      );

      if (!isValid) {
        throw new Error("Invalid or expired refresh token");
      }

      // Get fresh user data
      const { User } = await import("../models/index.js");
      const user = await User.findById(decoded.id).select("+isActive");

      if (!user || !user.isActive) {
        throw new Error("User not found or inactive");
      }

      // Generate new access token
      const newAccessToken = this.generateAccessToken({
        id: user._id.toString(),
        email: user.email,
        role: user.role,
        isEmailVerified: user.isEmailVerified,
        isActive: user.isActive,
      });

      return { accessToken: newAccessToken, user };
    } catch (error) {
      logger.error("Error refreshing access token:", error);
      throw error;
    }
  }

  // Parse expiry string to seconds
  parseExpiry(expiryString) {
    const match = expiryString.match(/(\d+)([smhd])/);
    if (!match) return 3600; // Default 1 hour

    const [, value, unit] = match;
    const multipliers = { s: 1, m: 60, h: 3600, d: 86400 };

    return parseInt(value) * multipliers[unit];
  }

  // Extract token from Authorization header
  extractTokenFromHeader(authHeader) {
    if (!authHeader) {
      return null;
    }

    const parts = authHeader.split(" ");
    if (parts.length !== 2 || parts[0] !== "Bearer") {
      return null;
    }

    return parts[1];
  }

  // Get token expiry time
  getTokenExpiry(token) {
    try {
      const decoded = jwt.decode(token);
      return decoded?.exp ? new Date(decoded.exp * 1000) : null;
    } catch (error) {
      return null;
    }
  }

  // Check if token is about to expire (within next hour)
  isTokenExpiringSoon(token, thresholdMinutes = 60) {
    const expiry = this.getTokenExpiry(token);
    if (!expiry) return false;

    const now = new Date();
    const threshold = new Date(now.getTime() + thresholdMinutes * 60 * 1000);

    return expiry <= threshold;
  }
}

// Create singleton instance
const jwtManager = new JWTManager();

export default jwtManager;

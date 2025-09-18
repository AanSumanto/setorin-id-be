import bcrypt from "bcryptjs";
import crypto from "crypto";
import { createLogger } from "./logger.js";

const logger = createLogger("PasswordUtils");

class PasswordManager {
  constructor() {
    this.saltRounds = 12; // Higher for better security
    this.minLength = 8;
    this.maxLength = 128;
  }

  // Hash password
  async hashPassword(password) {
    try {
      if (!password) {
        throw new Error("Password is required");
      }

      if (password.length < this.minLength) {
        throw new Error(
          `Password must be at least ${this.minLength} characters long`
        );
      }

      if (password.length > this.maxLength) {
        throw new Error(
          `Password must not exceed ${this.maxLength} characters`
        );
      }

      const hashedPassword = await bcrypt.hash(password, this.saltRounds);
      return hashedPassword;
    } catch (error) {
      logger.error("Error hashing password:", error.message);
      throw error;
    }
  }

  // Compare password with hash
  async comparePassword(password, hash) {
    try {
      if (!password || !hash) {
        return false;
      }

      return await bcrypt.compare(password, hash);
    } catch (error) {
      logger.error("Error comparing password:", error.message);
      return false;
    }
  }

  // Validate password strength
  validatePasswordStrength(password) {
    const result = {
      isValid: false,
      score: 0,
      feedback: [],
      requirements: {
        length: false,
        lowercase: false,
        uppercase: false,
        numbers: false,
        symbols: false,
        noCommonPatterns: false,
      },
    };

    if (!password) {
      result.feedback.push("Password is required");
      return result;
    }

    // Check length
    if (password.length >= this.minLength) {
      result.requirements.length = true;
      result.score += 1;
    } else {
      result.feedback.push(
        `Password must be at least ${this.minLength} characters long`
      );
    }

    // Check for lowercase letters
    if (/[a-z]/.test(password)) {
      result.requirements.lowercase = true;
      result.score += 1;
    } else {
      result.feedback.push("Password must contain lowercase letters");
    }

    // Check for uppercase letters
    if (/[A-Z]/.test(password)) {
      result.requirements.uppercase = true;
      result.score += 1;
    } else {
      result.feedback.push("Password must contain uppercase letters");
    }

    // Check for numbers
    if (/\d/.test(password)) {
      result.requirements.numbers = true;
      result.score += 1;
    } else {
      result.feedback.push("Password must contain numbers");
    }

    // Check for symbols
    if (/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?~`]/.test(password)) {
      result.requirements.symbols = true;
      result.score += 1;
    } else {
      result.feedback.push("Password must contain special characters");
    }

    // Check for common patterns
    const commonPatterns = this.checkCommonPatterns(password);
    if (commonPatterns.length === 0) {
      result.requirements.noCommonPatterns = true;
      result.score += 1;
    } else {
      result.feedback.push(...commonPatterns);
    }

    // Determine if password is valid (all requirements met)
    result.isValid = Object.values(result.requirements).every(
      (req) => req === true
    );

    return result;
  }

  // Check for common weak patterns
  checkCommonPatterns(password) {
    const issues = [];
    const lowerPassword = password.toLowerCase();

    // Common weak passwords
    const commonPasswords = [
      "password",
      "12345678",
      "qwerty123",
      "abc123456",
      "password123",
      "admin123",
      "welcome123",
      "letmein123",
      "monkey123",
      "1234567890",
    ];

    if (commonPasswords.some((common) => lowerPassword.includes(common))) {
      issues.push("Password contains common weak patterns");
    }

    // Sequential numbers or letters
    if (/123456|987654|abcdef|fedcba/i.test(password)) {
      issues.push("Password contains sequential characters");
    }

    // Repeated characters
    if (/(.)\1{3,}/.test(password)) {
      issues.push("Password contains too many repeated characters");
    }

    // Keyboard patterns
    const keyboardPatterns = ["qwerty", "asdf", "zxcv", "1234", "qwer", "asdf"];
    if (keyboardPatterns.some((pattern) => lowerPassword.includes(pattern))) {
      issues.push("Password contains keyboard patterns");
    }

    return issues;
  }

  // Generate secure random password
  generateSecurePassword(length = 16) {
    const lowercase = "abcdefghijklmnopqrstuvwxyz";
    const uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const numbers = "0123456789";
    const symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?";

    const allChars = lowercase + uppercase + numbers + symbols;
    let password = "";

    // Ensure at least one character from each category
    password += this.getRandomChar(lowercase);
    password += this.getRandomChar(uppercase);
    password += this.getRandomChar(numbers);
    password += this.getRandomChar(symbols);

    // Fill the rest randomly
    for (let i = 4; i < length; i++) {
      password += this.getRandomChar(allChars);
    }

    // Shuffle the password
    return password
      .split("")
      .sort(() => Math.random() - 0.5)
      .join("");
  }

  // Get random character from string
  getRandomChar(str) {
    return str.charAt(Math.floor(Math.random() * str.length));
  }

  // Generate password reset token
  generateResetToken() {
    const token = crypto.randomBytes(32).toString("hex");
    const hashedToken = crypto.createHash("sha256").update(token).digest("hex");

    return {
      token, // Send this to user
      hashedToken, // Store this in database
      expires: new Date(Date.now() + 15 * 60 * 1000), // 15 minutes
    };
  }

  // Verify password reset token
  verifyResetToken(token) {
    if (!token) {
      return null;
    }

    return crypto.createHash("sha256").update(token).digest("hex");
  }

  // Generate email verification token
  generateVerificationToken() {
    const token = crypto.randomBytes(32).toString("hex");

    return {
      token,
      expires: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours
    };
  }

  // Generate OTP for 2FA or phone verification
  generateOTP(length = 6) {
    const digits = "0123456789";
    let otp = "";

    for (let i = 0; i < length; i++) {
      otp += digits.charAt(Math.floor(Math.random() * digits.length));
    }

    return {
      otp,
      expires: new Date(Date.now() + 5 * 60 * 1000), // 5 minutes
    };
  }

  // Verify OTP
  verifyOTP(inputOTP, storedOTP, expiryTime) {
    if (!inputOTP || !storedOTP || !expiryTime) {
      return false;
    }

    if (new Date() > expiryTime) {
      return false; // Expired
    }

    return inputOTP === storedOTP;
  }

  // Check if password has been breached (simplified check)
  async checkPasswordBreach(password) {
    try {
      // In production, you might want to integrate with HaveIBeenPwned API
      // For now, we'll do basic checks

      const commonBreachedPasswords = [
        "password",
        "123456",
        "123456789",
        "qwerty",
        "abc123",
        "monkey",
        "1234567",
        "letmein",
        "trustno1",
        "dragon",
      ];

      const isBreached = commonBreachedPasswords.includes(
        password.toLowerCase()
      );

      return {
        isBreached,
        message: isBreached
          ? "This password has been found in data breaches"
          : null,
      };
    } catch (error) {
      logger.error("Error checking password breach:", error);
      return { isBreached: false, message: null };
    }
  }

  // Calculate password entropy
  calculatePasswordEntropy(password) {
    if (!password) return 0;

    let charset = 0;

    if (/[a-z]/.test(password)) charset += 26; // lowercase
    if (/[A-Z]/.test(password)) charset += 26; // uppercase
    if (/\d/.test(password)) charset += 10; // numbers
    if (/[^a-zA-Z0-9]/.test(password)) charset += 32; // symbols (approximate)

    const entropy = Math.log2(Math.pow(charset, password.length));

    return {
      entropy: Math.round(entropy),
      strength: this.getStrengthFromEntropy(entropy),
    };
  }

  // Get strength level from entropy
  getStrengthFromEntropy(entropy) {
    if (entropy < 30) return "Very Weak";
    if (entropy < 40) return "Weak";
    if (entropy < 50) return "Fair";
    if (entropy < 60) return "Good";
    if (entropy < 70) return "Strong";
    return "Very Strong";
  }

  // Generate password policy message
  getPasswordPolicy() {
    return {
      minLength: this.minLength,
      maxLength: this.maxLength,
      requirements: [
        "At least 8 characters long",
        "Contains lowercase letters (a-z)",
        "Contains uppercase letters (A-Z)",
        "Contains numbers (0-9)",
        "Contains special characters (!@#$%^&*)",
        "No common weak patterns",
        "Not found in data breaches",
      ],
      recommendations: [
        "Use a unique password for this account",
        "Consider using a password manager",
        "Enable two-factor authentication when available",
        "Update your password regularly",
      ],
    };
  }

  // Rate limit password attempts
  checkPasswordAttempts(attempts, lockTime) {
    const maxAttempts = 5;
    const lockDuration = 30 * 60 * 1000; // 30 minutes

    if (lockTime && new Date() < lockTime) {
      const remainingTime = Math.ceil((lockTime - new Date()) / 1000 / 60);
      return {
        allowed: false,
        remainingAttempts: 0,
        lockTimeRemaining: remainingTime,
        message: `Account locked for ${remainingTime} minutes due to failed login attempts`,
      };
    }

    if (attempts >= maxAttempts) {
      return {
        allowed: false,
        remainingAttempts: 0,
        lockTimeRemaining: lockDuration / 1000 / 60,
        message: "Too many failed attempts. Account will be locked.",
      };
    }

    return {
      allowed: true,
      remainingAttempts: maxAttempts - attempts,
      lockTimeRemaining: 0,
      message: null,
    };
  }
}

// Create singleton instance
const passwordManager = new PasswordManager();

export default passwordManager;

import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import { createLogger } from "../utils/logger.js";

const logger = createLogger("UserModel");

const addressSchema = new mongoose.Schema(
  {
    street: {
      type: String,
      required: true,
      trim: true,
    },
    village: {
      type: String,
      required: true,
      trim: true,
    },
    district: {
      type: String,
      required: true,
      trim: true,
    },
    city: {
      type: String,
      required: true,
      trim: true,
    },
    province: {
      type: String,
      required: true,
      trim: true,
    },
    postalCode: {
      type: String,
      required: true,
      trim: true,
    },
    coordinates: {
      type: {
        type: String,
        enum: ["Point"],
        default: "Point",
      },
      coordinates: {
        type: [Number],
        required: true,
        validate: {
          validator: function (coords) {
            return (
              coords.length === 2 &&
              coords[0] >= -180 &&
              coords[0] <= 180 &&
              coords[1] >= -90 &&
              coords[1] <= 90
            );
          },
          message:
            "Coordinates must be [longitude, latitude] within valid bounds",
        },
      },
    },
    isDefault: {
      type: Boolean,
      default: false,
    },
  },
  { _id: false }
);

// RT/RW specific data
const rtRwDataSchema = new mongoose.Schema(
  {
    rtNumber: {
      type: String,
      required: true,
    },
    rwNumber: {
      type: String,
      required: function () {
        return this.role === "rw";
      },
    },
    area: {
      type: String,
      required: true,
    },
    memberCount: {
      type: Number,
      default: 0,
    },
    cashBalance: {
      type: Number,
      default: 0,
      min: 0,
    },
    incentiveBalance: {
      type: Number,
      default: 0,
      min: 0,
    },
  },
  { _id: false }
);

// Pengepul specific data
const collectorDataSchema = new mongoose.Schema(
  {
    businessName: {
      type: String,
      required: true,
    },
    businessLicense: {
      type: String,
      trim: true,
    },
    serviceRadius: {
      type: Number,
      default: 10,
      min: 1,
      max: 50,
    },
    vehicleType: {
      type: String,
      enum: ["cart", "bicycle", "motorcycle", "car", "truck", "pickup"],
      required: true,
    },
    operatingHours: {
      start: {
        type: String,
        default: "08:00",
      },
      end: {
        type: String,
        default: "17:00",
      },
    },
    isAvailable: {
      type: Boolean,
      default: true,
    },
  },
  { _id: false }
);

// Role configuration schema
const roleConfigSchema = new mongoose.Schema(
  {
    role: {
      type: String,
      enum: ["individual", "rt", "rw", "collector", "admin"],
      required: true,
    },
    isActive: {
      type: Boolean,
      default: true,
    },
    isPrimary: {
      type: Boolean,
      default: false,
    },
    // Role-specific data
    rtRwData: {
      type: rtRwDataSchema,
      required: function () {
        return ["rt", "rw"].includes(this.role);
      },
    },
    collectorData: {
      type: collectorDataSchema,
      required: function () {
        return this.role === "collector";
      },
    },
    // Points per role
    points: {
      current: {
        type: Number,
        default: 0,
        min: 0,
      },
      lifetime: {
        type: Number,
        default: 0,
        min: 0,
      },
      lastEarned: Date,
    },
    // Rating per role
    rating: {
      average: {
        type: Number,
        default: 0,
        min: 0,
        max: 5,
      },
      count: {
        type: Number,
        default: 0,
        min: 0,
      },
    },
  },
  { _id: false }
);

const userSchema = new mongoose.Schema(
  {
    // Basic Information
    name: {
      type: String,
      required: [true, "Name is required"],
      trim: true,
      minlength: [2, "Name must be at least 2 characters"],
      maxlength: [100, "Name cannot exceed 100 characters"],
    },
    email: {
      type: String,
      unique: true,
      sparse: true, // Allow null/undefined values to be unique
      lowercase: true,
      trim: true,
      match: [/^[^\s@]+@[^\s@]+\.[^\s@]+$/, "Please provide a valid email"],
    },
    phone: {
      type: String,
      required: [true, "Phone number is required"],
      trim: true,
      match: [
        /^(\+62|62|0)[0-9]{9,13}$/,
        "Please provide a valid Indonesian phone number",
      ],
    },
    password: {
      type: String,
      required: [true, "Password is required"],
      minlength: [8, "Password must be at least 8 characters"],
      select: false,
    },

    // Multiple Roles Configuration
    roles: {
      type: [roleConfigSchema],
      required: true,
      validate: {
        validator: function (roles) {
          // At least one role must exist
          if (roles.length === 0) return false;

          // Only one primary role allowed
          const primaryRoles = roles.filter((r) => r.isPrimary);
          if (primaryRoles.length !== 1) return false;

          // No duplicate roles
          const roleNames = roles.map((r) => r.role);
          return roleNames.length === new Set(roleNames).size;
        },
        message:
          "Must have at least one role, exactly one primary role, and no duplicates",
      },
    },

    // Current active role (for session management)
    currentRole: {
      type: String,
      enum: ["individual", "rt", "rw", "collector", "admin"],
      required: true,
    },

    // Profile Information
    avatar: {
      url: String,
      publicId: String,
    },
    dateOfBirth: {
      type: Date,
      validate: {
        validator: function (value) {
          return value < new Date();
        },
        message: "Date of birth must be in the past",
      },
    },
    gender: {
      type: String,
      enum: ["male", "female", "other"],
      lowercase: true,
    },

    // Address Information
    addresses: [addressSchema],

    // Account Status
    isActive: {
      type: Boolean,
      default: true,
    },
    isEmailVerified: {
      type: Boolean,
      default: false,
    },
    isPhoneVerified: {
      type: Boolean,
      default: false,
    },

    // Security
    lastLogin: Date,
    loginAttempts: {
      type: Number,
      default: 0,
    },
    lockUntil: Date,

    // Tokens
    emailVerificationToken: String,
    emailVerificationExpires: Date,
    passwordResetToken: String,
    passwordResetExpires: Date,

    // Metadata
    fcmToken: String,
    preferences: {
      notifications: {
        email: {
          type: Boolean,
          default: true,
        },
        push: {
          type: Boolean,
          default: true,
        },
        sms: {
          type: Boolean,
          default: false,
        },
      },
      language: {
        type: String,
        default: "id",
        enum: ["id", "en"],
      },
    },
  },
  {
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
  }
);

// Indexes
userSchema.index({ email: 1 }, { unique: true, sparse: true }); // sparse allows multiple null values
userSchema.index({ phone: 1 }); // Tidak unique lagi untuk multi-role
userSchema.index({ "roles.role": 1 });
userSchema.index({ currentRole: 1 });
userSchema.index({ "addresses.coordinates": "2dsphere" });
userSchema.index({ isActive: 1, "roles.role": 1 });
userSchema.index({ "roles.rating.average": -1, "roles.role": 1 }); // for top-rated by role

// Virtual for getting primary role
userSchema.virtual("primaryRole").get(function () {
  return this.roles.find((role) => role.isPrimary);
});

// Virtual for getting current role data
userSchema.virtual("currentRoleData").get(function () {
  return this.roles.find((role) => role.role === this.currentRole);
});

// Virtual for account lock status
userSchema.virtual("isLocked").get(function () {
  return !!(this.lockUntil && this.lockUntil > Date.now());
});

// Virtual for default address
userSchema.virtual("defaultAddress").get(function () {
  return this.addresses.find((addr) => addr.isDefault) || this.addresses[0];
});

// Pre-save middleware
userSchema.pre("save", async function (next) {
  try {
    // Hash password if modified
    if (this.isModified("password")) {
      this.password = await bcrypt.hash(this.password, 12);
    }

    // Ensure currentRole exists in roles array
    if (
      this.currentRole &&
      !this.roles.some((r) => r.role === this.currentRole)
    ) {
      this.currentRole =
        this.roles.find((r) => r.isPrimary)?.role || this.roles[0]?.role;
    }

    // Ensure only one default address
    if (this.addresses.length > 0) {
      const defaultAddresses = this.addresses.filter((addr) => addr.isDefault);
      if (defaultAddresses.length === 0) {
        this.addresses[0].isDefault = true;
      } else if (defaultAddresses.length > 1) {
        let firstDefault = true;
        this.addresses.forEach((addr) => {
          if (addr.isDefault && firstDefault) {
            firstDefault = false;
          } else if (addr.isDefault) {
            addr.isDefault = false;
          }
        });
      }
    }

    next();
  } catch (error) {
    next(error);
  }
});

// Instance methods
userSchema.methods.comparePassword = async function (candidatePassword) {
  try {
    return await bcrypt.compare(candidatePassword, this.password);
  } catch (error) {
    logger.error("Error comparing password:", error);
    return false;
  }
};

// Login attempt management
userSchema.methods.incrementLoginAttempts = function () {
  // If we have a previous lock that has expired, restart at 1
  if (this.lockUntil && this.lockUntil < Date.now()) {
    return this.updateOne({
      $unset: { lockUntil: 1 },
      $set: { loginAttempts: 1 },
    });
  }

  const updates = { $inc: { loginAttempts: 1 } };

  // Lock account after 5 failed attempts for 15 minutes
  if (this.loginAttempts + 1 >= 5 && !this.isLocked) {
    updates.$set = { lockUntil: Date.now() + 15 * 60 * 1000 }; // 15 minutes
  }

  return this.updateOne(updates);
};

userSchema.methods.resetLoginAttempts = function () {
  return this.updateOne({
    $unset: { loginAttempts: 1, lockUntil: 1 },
  });
};

// Role management methods
userSchema.methods.switchRole = function (roleName) {
  const role = this.roles.find((r) => r.role === roleName && r.isActive);
  if (!role) {
    throw new Error(`Role ${roleName} not found or inactive`);
  }

  this.currentRole = roleName;
  return this.save();
};

userSchema.methods.addRole = function (roleData) {
  // Check if role already exists
  if (this.roles.some((r) => r.role === roleData.role)) {
    throw new Error(`Role ${roleData.role} already exists`);
  }

  // If this is the first role, make it primary
  if (this.roles.length === 0) {
    roleData.isPrimary = true;
    this.currentRole = roleData.role;
  }

  this.roles.push(roleData);
  return this.save();
};

userSchema.methods.removeRole = function (roleName) {
  const roleIndex = this.roles.findIndex((r) => r.role === roleName);
  if (roleIndex === -1) {
    throw new Error(`Role ${roleName} not found`);
  }

  const roleToRemove = this.roles[roleIndex];

  // Cannot remove primary role if other roles exist
  if (roleToRemove.isPrimary && this.roles.length > 1) {
    throw new Error(
      "Cannot remove primary role. Set another role as primary first."
    );
  }

  this.roles.splice(roleIndex, 1);

  // If removing current role, switch to primary
  if (this.currentRole === roleName) {
    this.currentRole =
      this.roles.find((r) => r.isPrimary)?.role || this.roles[0]?.role;
  }

  return this.save();
};

// Set primary role
userSchema.methods.setPrimaryRole = function (roleName) {
  const role = this.roles.find((r) => r.role === roleName && r.isActive);
  if (!role) {
    throw new Error(`Role ${roleName} not found or inactive`);
  }

  // Remove primary flag from all roles
  this.roles.forEach((r) => {
    r.isPrimary = false;
  });

  // Set new primary role
  role.isPrimary = true;

  return this.save();
};

// Points management per role
userSchema.methods.addPointsToRole = function (
  points,
  roleName = null,
  reason = "Transaction"
) {
  const targetRole = roleName || this.currentRole;
  const role = this.roles.find((r) => r.role === targetRole);

  if (!role) {
    throw new Error(`Role ${targetRole} not found`);
  }

  role.points.current += points;
  role.points.lifetime += points;
  role.points.lastEarned = new Date();

  logger.info(
    `Points added to user ${this._id} role ${targetRole}: +${points} (${reason})`
  );
  return this.save();
};

userSchema.methods.deductPointsFromRole = function (points, roleName = null) {
  const targetRole = roleName || this.currentRole;
  const role = this.roles.find((r) => r.role === targetRole);

  if (!role) {
    throw new Error(`Role ${targetRole} not found`);
  }

  if (role.points.current < points) {
    throw new Error("Insufficient points");
  }

  role.points.current -= points;
  logger.info(
    `Points deducted from user ${this._id} role ${targetRole}: -${points}`
  );
  return this.save();
};

// Rating management per role
userSchema.methods.updateRoleRating = function (newRating, roleName = null) {
  const targetRole = roleName || this.currentRole;
  const role = this.roles.find((r) => r.role === targetRole);

  if (!role) {
    throw new Error(`Role ${targetRole} not found`);
  }

  const totalRating = role.rating.average * role.rating.count + newRating;
  role.rating.count += 1;
  role.rating.average = totalRating / role.rating.count;

  logger.info(
    `Rating updated for user ${this._id} role ${targetRole}: ${role.rating.average} (${role.rating.count} reviews)`
  );
  return this.save();
};

// Check if user has specific role
userSchema.methods.hasRole = function (roleName) {
  return this.roles.some((r) => r.role === roleName && r.isActive);
};

// Get role data
userSchema.methods.getRoleData = function (roleName) {
  return this.roles.find((r) => r.role === roleName);
};

// Legacy methods for backward compatibility
userSchema.methods.addPoints = function (points, reason = "Transaction") {
  return this.addPointsToRole(points, null, reason);
};

userSchema.methods.deductPoints = function (points) {
  return this.deductPointsFromRole(points, null);
};

userSchema.methods.updateRating = function (newRating) {
  return this.updateRoleRating(newRating, null);
};

// Static methods
userSchema.statics.findByEmail = function (email) {
  return this.findOne({ email: email.toLowerCase() });
};

userSchema.statics.findByPhone = function (phone) {
  return this.find({ phone: phone });
};

userSchema.statics.findByRole = function (role) {
  return this.find({
    "roles.role": role,
    "roles.isActive": true,
    isActive: true,
  });
};

userSchema.statics.findNearbyByRole = function (
  coordinates,
  role,
  radiusInKm = 10
) {
  const longitude = Array.isArray(coordinates)
    ? coordinates[0]
    : coordinates.longitude;
  const latitude = Array.isArray(coordinates)
    ? coordinates[1]
    : coordinates.latitude;

  return this.find({
    "addresses.coordinates": {
      $near: {
        $geometry: {
          type: "Point",
          coordinates: [longitude, latitude],
        },
        $maxDistance: radiusInKm * 1000,
      },
    },
    "roles.role": role,
    "roles.isActive": true,
    isActive: true,
  });
};

userSchema.statics.findTopRatedByRole = function (role, limit = 10) {
  return this.aggregate([
    {
      $match: {
        isActive: true,
        "roles.role": role,
        "roles.isActive": true,
      },
    },
    {
      $addFields: {
        roleData: {
          $filter: {
            input: "$roles",
            cond: { $eq: ["$$this.role", role] },
          },
        },
      },
    },
    {
      $addFields: {
        roleRating: { $arrayElemAt: ["$roleData.rating", 0] },
      },
    },
    {
      $match: {
        "roleRating.count": { $gte: 1 },
      },
    },
    {
      $sort: {
        "roleRating.average": -1,
        "roleRating.count": -1,
      },
    },
    {
      $limit: limit,
    },
  ]);
};

// Legacy method for backward compatibility
userSchema.statics.findNearby = function (
  coordinates,
  radiusInKm = 10,
  role = null
) {
  if (role) {
    return this.findNearbyByRole(coordinates, role, radiusInKm);
  }

  const longitude = Array.isArray(coordinates)
    ? coordinates[0]
    : coordinates.longitude;
  const latitude = Array.isArray(coordinates)
    ? coordinates[1]
    : coordinates.latitude;

  return this.find({
    "addresses.coordinates": {
      $near: {
        $geometry: {
          type: "Point",
          coordinates: [longitude, latitude],
        },
        $maxDistance: radiusInKm * 1000,
      },
    },
    isActive: true,
  });
};

// Update rating for specific role using external Rating model
userSchema.statics.updateUserRating = async function (userId, role = null) {
  try {
    const Rating = mongoose.model("Rating");

    // If role specified, update that role's rating
    if (role) {
      const ratingStats = await Rating.aggregate([
        {
          $match: {
            ratee: new mongoose.Types.ObjectId(userId),
            rateeRole: role,
            status: "active",
          },
        },
        {
          $group: {
            _id: null,
            averageRating: { $avg: "$rating" },
            ratingCount: { $sum: 1 },
          },
        },
      ]);

      const stats = ratingStats[0] || { averageRating: 0, ratingCount: 0 };

      await this.findOneAndUpdate(
        { _id: userId, "roles.role": role },
        {
          $set: {
            "roles.$.rating.average": Math.round(stats.averageRating * 10) / 10,
            "roles.$.rating.count": stats.ratingCount,
          },
        }
      );

      logger.info(
        `Updated rating for user ${userId} role ${role}: ${stats.averageRating} (${stats.ratingCount} reviews)`
      );
    } else {
      // Update all role ratings
      const user = await this.findById(userId);
      if (!user) return;

      for (const userRole of user.roles) {
        const ratingStats = await Rating.aggregate([
          {
            $match: {
              ratee: new mongoose.Types.ObjectId(userId),
              rateeRole: userRole.role,
              status: "active",
            },
          },
          {
            $group: {
              _id: null,
              averageRating: { $avg: "$rating" },
              ratingCount: { $sum: 1 },
            },
          },
        ]);

        const stats = ratingStats[0] || { averageRating: 0, ratingCount: 0 };
        userRole.rating.average = Math.round(stats.averageRating * 10) / 10;
        userRole.rating.count = stats.ratingCount;
      }

      await user.save();
    }
  } catch (error) {
    logger.error("Error updating user rating:", error);
  }
};

const User = mongoose.model("User", userSchema);

export default User;

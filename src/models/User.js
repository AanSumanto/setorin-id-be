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
        type: [Number], // [longitude, latitude] - MongoDB GeoJSON format
        required: true,
        validate: {
          validator: function (coords) {
            return (
              coords.length === 2 &&
              coords[0] >= -180 &&
              coords[0] <= 180 && // longitude
              coords[1] >= -90 &&
              coords[1] <= 90
            ); // latitude
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
      required: function () {
        return ["rt", "rw"].includes(this.role);
      },
    },
    rwNumber: {
      type: String,
      required: function () {
        return this.role === "rw";
      },
    },
    area: {
      type: String,
      required: function () {
        return ["rt", "rw"].includes(this.role);
      },
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
      required: function () {
        return this.role === "collector";
      },
    },
    businessLicense: {
      type: String,
      trim: true,
    },
    serviceRadius: {
      type: Number,
      default: 10, // km
      min: 1,
      max: 50,
    },
    vehicleType: {
      type: String,
      enum: ["cart", "bicycle", "motorcycle", "car", "truck", "pickup"],
      required: function () {
        return this.role === "collector";
      },
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
      required: [true, "Email is required"],
      unique: true,
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
      select: false, // Don't include in queries by default
    },

    // User Role
    role: {
      type: String,
      enum: {
        values: ["individual", "rt", "rw", "collector", "admin"],
        message: "Role must be one of: individual, rt, rw, collector, admin",
      },
      required: [true, "Role is required"],
      default: "individual",
    },

    // Profile Information
    avatar: {
      url: String,
      publicId: String, // for DO Spaces file management
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

    // Role-specific Data
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

    // Points and Rewards System
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

    // Rating System
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
    fcmToken: String, // for push notifications
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

// Indexes for performance
// userSchema.index({ email: 1 }, { unique: true });
// userSchema.index({ phone: 1 }, { unique: true });
userSchema.index({ role: 1 });
userSchema.index({ "addresses.coordinates": "2dsphere" }); // for geospatial queries
userSchema.index({ isActive: 1, role: 1 });
userSchema.index({ "rating.average": -1, role: 1 }); // for finding top-rated collectors

// Virtual for account lock status
userSchema.virtual("isLocked").get(function () {
  return !!(this.lockUntil && this.lockUntil > Date.now());
});

// Virtual for full address
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

    // Ensure only one default address
    if (this.addresses.length > 0) {
      const defaultAddresses = this.addresses.filter((addr) => addr.isDefault);
      if (defaultAddresses.length === 0) {
        this.addresses[0].isDefault = true;
      } else if (defaultAddresses.length > 1) {
        // Keep only the first default, set others to false
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

userSchema.methods.incrementLoginAttempts = function () {
  // If we have a previous lock that has expired, restart at 1
  if (this.lockUntil && this.lockUntil < Date.now()) {
    return this.updateOne({
      $unset: { lockUntil: 1 },
      $set: { loginAttempts: 1 },
    });
  }

  const updates = { $inc: { loginAttempts: 1 } };

  // Lock account after 5 failed attempts for 2 hours
  // if (this.loginAttempts + 1 >= 5 && !this.isLocked) {
  //   updates.$set = { lockUntil: Date.now() + 2 * 60 * 60 * 1000 }; // 2 hours
  // }

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

userSchema.methods.addPoints = function (points, reason = "Transaction") {
  this.points.current += points;
  this.points.lifetime += points;
  this.points.lastEarned = new Date();

  logger.info(`Points added to user ${this._id}: +${points} (${reason})`);
  return this.save();
};

userSchema.methods.deductPoints = function (points) {
  if (this.points.current < points) {
    throw new Error("Insufficient points");
  }

  this.points.current -= points;
  logger.info(`Points deducted from user ${this._id}: -${points}`);
  return this.save();
};

userSchema.methods.updateRating = function (newRating) {
  const totalRating = this.rating.average * this.rating.count + newRating;
  this.rating.count += 1;
  this.rating.average = totalRating / this.rating.count;

  logger.info(
    `Rating updated for user ${this._id}: ${this.rating.average} (${this.rating.count} reviews)`
  );
  return this.save();
};

// Static methods
userSchema.statics.findByEmail = function (email) {
  return this.findOne({ email: email.toLowerCase() });
};

userSchema.statics.findNearby = function (
  coordinates,
  radiusInKm = 10,
  role = null
) {
  // coordinates should be [longitude, latitude] for GeoJSON
  const longitude = Array.isArray(coordinates)
    ? coordinates[0]
    : coordinates.longitude;
  const latitude = Array.isArray(coordinates)
    ? coordinates[1]
    : coordinates.latitude;

  const query = {
    "addresses.coordinates": {
      $near: {
        $geometry: {
          type: "Point",
          coordinates: [longitude, latitude],
        },
        $maxDistance: radiusInKm * 1000, // Convert km to meters
      },
    },
    isActive: true,
  };

  if (role) {
    query.role = role;
  }

  return this.find(query);
};

userSchema.statics.findTopRatedCollectors = function (limit = 10) {
  return this.find({
    role: "collector",
    isActive: true,
    "rating.count": { $gte: 1 },
  })
    .sort({ "rating.average": -1, "rating.count": -1 })
    .limit(limit);
};

userSchema.statics.updateUserRating = async function (userId) {
  try {
    const Rating = mongoose.model("Rating");

    // Calculate new rating from all active ratings
    const ratingStats = await Rating.aggregate([
      {
        $match: {
          ratee: mongoose.Types.ObjectId(userId),
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

    // Update user rating
    await this.findByIdAndUpdate(userId, {
      "rating.average": Math.round(stats.averageRating * 10) / 10, // Round to 1 decimal
      "rating.count": stats.ratingCount,
    });

    logger.info(
      `Updated rating for user ${userId}: ${stats.averageRating} (${stats.ratingCount} reviews)`
    );
  } catch (error) {
    logger.error("Error updating user rating:", error);
  }
};

const User = mongoose.model("User", userSchema);

export default User;

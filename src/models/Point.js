import mongoose from "mongoose";

// Point transaction schema
const pointTransactionSchema = new mongoose.Schema(
  {
    // User who owns the points
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: [true, "User is required"],
    },

    // Transaction details
    type: {
      type: String,
      enum: {
        values: ["earned", "redeemed", "expired", "bonus", "penalty", "refund"],
        message: "Invalid transaction type",
      },
      required: [true, "Transaction type is required"],
    },

    amount: {
      type: Number,
      required: [true, "Point amount is required"],
      validate: {
        validator: function (value) {
          return value !== 0;
        },
        message: "Point amount cannot be zero",
      },
    },

    // Transaction source
    source: {
      type: String,
      enum: {
        values: [
          "order_completion", // Points earned from completing orders
          "first_order", // Bonus for first order
          "referral", // Points from referring new users
          "daily_bonus", // Daily login bonus
          "rating_given", // Points for giving ratings
          "quality_bonus", // Bonus for high-quality products
          "loyalty_bonus", // Long-term user bonus
          "reward_redemption", // Points spent on rewards
          "manual_adjustment", // Admin manual adjustment
          "promotion", // Special promotional points
          "penalty", // Points deducted for violations
          "expiration", // Points expired
        ],
        message: "Invalid point source",
      },
      required: [true, "Point source is required"],
    },

    // Reference to related entities
    relatedOrder: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Order",
    },
    relatedReward: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Reward",
    },
    relatedUser: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User", // For referrals
    },

    // Description
    description: {
      type: String,
      required: true,
      maxlength: [200, "Description cannot exceed 200 characters"],
    },

    // Point expiration
    expiresAt: {
      type: Date,
      validate: {
        validator: function (value) {
          return !value || value > new Date();
        },
        message: "Expiration date must be in the future",
      },
    },

    // Balance after transaction
    balanceAfter: {
      type: Number,
      required: true,
      min: 0,
    },

    // Status
    status: {
      type: String,
      enum: {
        values: ["pending", "completed", "cancelled", "expired"],
        message: "Invalid transaction status",
      },
      default: "completed",
    },

    // Metadata
    metadata: {
      adminUser: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User", // For manual adjustments
      },
      originalAmount: Number, // For refunds
      reason: String, // Additional reason for penalties/bonuses
    },
  },
  {
    timestamps: true,
  }
);

// Reward catalog schema
const rewardSchema = new mongoose.Schema(
  {
    // Reward details
    name: {
      type: String,
      required: [true, "Reward name is required"],
      trim: true,
      maxlength: [100, "Reward name cannot exceed 100 characters"],
    },
    description: {
      type: String,
      required: [true, "Reward description is required"],
      trim: true,
      maxlength: [500, "Description cannot exceed 500 characters"],
    },

    // Reward category
    category: {
      type: String,
      enum: {
        values: [
          "voucher", // Discount vouchers
          "cash", // Cash rewards
          "product", // Physical products
          "service", // Service credits
          "charity", // Donation to charity
          "digital", // Digital products/services
          "experience", // Experience rewards
        ],
        message: "Invalid reward category",
      },
      required: [true, "Reward category is required"],
    },

    // Pricing
    pointsCost: {
      type: Number,
      required: [true, "Points cost is required"],
      min: [1, "Points cost must be at least 1"],
    },
    cashValue: {
      type: Number,
      min: 0, // Cash equivalent value
    },

    // Stock management
    totalStock: {
      type: Number,
      min: 0,
      default: 0,
    },
    availableStock: {
      type: Number,
      min: 0,
      default: 0,
    },
    isUnlimitedStock: {
      type: Boolean,
      default: false,
    },

    // Images
    images: [
      {
        url: {
          type: String,
          required: true,
        },
        publicId: {
          type: String,
          required: true,
        },
        isPrimary: {
          type: Boolean,
          default: false,
        },
      },
    ],

    // Availability
    isActive: {
      type: Boolean,
      default: true,
    },
    validFrom: {
      type: Date,
      default: Date.now,
    },
    validUntil: {
      type: Date,
      validate: {
        validator: function (value) {
          return !value || value > this.validFrom;
        },
        message: "Valid until must be after valid from date",
      },
    },

    // Usage limits
    maxRedemptionsPerUser: {
      type: Number,
      min: 1,
      default: 1,
    },
    maxTotalRedemptions: {
      type: Number,
      min: 1,
    },
    currentRedemptions: {
      type: Number,
      default: 0,
      min: 0,
    },

    // Terms and conditions
    terms: {
      type: String,
      maxlength: [1000, "Terms cannot exceed 1000 characters"],
    },
    redemptionInstructions: {
      type: String,
      maxlength: [500, "Instructions cannot exceed 500 characters"],
    },

    // Partner information (for external rewards)
    partner: {
      name: String,
      logo: String,
      contact: {
        email: String,
        phone: String,
        website: String,
      },
    },

    // Statistics
    popularity: {
      views: {
        type: Number,
        default: 0,
      },
      redemptions: {
        type: Number,
        default: 0,
      },
      averageRating: {
        type: Number,
        min: 0,
        max: 5,
        default: 0,
      },
      ratingCount: {
        type: Number,
        default: 0,
        min: 0,
      },
    },

    // SEO and categorization
    tags: [
      {
        type: String,
        trim: true,
        lowercase: true,
      },
    ],
    featured: {
      type: Boolean,
      default: false,
    },
    priority: {
      type: Number,
      default: 0, // Higher number = higher priority
    },
  },
  {
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
  }
);

// Reward redemption schema
const redemptionSchema = new mongoose.Schema(
  {
    // User and reward
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: [true, "User is required"],
    },
    reward: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Reward",
      required: [true, "Reward is required"],
    },

    // Redemption details
    pointsSpent: {
      type: Number,
      required: [true, "Points spent is required"],
      min: 1,
    },
    quantity: {
      type: Number,
      default: 1,
      min: 1,
    },

    // Status
    status: {
      type: String,
      enum: {
        values: [
          "pending",
          "confirmed",
          "processing",
          "shipped",
          "delivered",
          "cancelled",
          "expired",
        ],
        message: "Invalid redemption status",
      },
      default: "pending",
    },

    // Delivery information
    deliveryAddress: {
      name: String,
      phone: String,
      street: String,
      village: String,
      district: String,
      city: String,
      province: String,
      postalCode: String,
      notes: String,
    },

    // Fulfillment
    fulfillment: {
      method: {
        type: String,
        enum: ["digital", "pickup", "delivery", "partner_pickup"],
        default: "digital",
      },
      trackingNumber: String,
      courierService: String,
      estimatedDelivery: Date,
      actualDelivery: Date,
      notes: String,
    },

    // Digital reward data (for vouchers, codes, etc.)
    digitalReward: {
      code: String,
      voucher: String,
      validUntil: Date,
      instructions: String,
      downloadLink: String,
    },

    // Rating for the reward
    rating: {
      score: {
        type: Number,
        min: 1,
        max: 5,
      },
      review: {
        type: String,
        maxlength: 300,
      },
      ratedAt: Date,
    },

    // Refund information
    refund: {
      reason: String,
      processedAt: Date,
      pointsRefunded: {
        type: Number,
        min: 0,
      },
    },

    // Admin notes
    adminNotes: [
      {
        note: String,
        admin: {
          type: mongoose.Schema.Types.ObjectId,
          ref: "User",
        },
        createdAt: {
          type: Date,
          default: Date.now,
        },
      },
    ],
  },
  {
    timestamps: true,
  }
);

// Indexes for Point Transactions
pointTransactionSchema.index({ user: 1, createdAt: -1 });
pointTransactionSchema.index({ type: 1, status: 1 });
pointTransactionSchema.index({ relatedOrder: 1 });
// pointTransactionSchema.index({ expiresAt: 1 }); // For TTL
pointTransactionSchema.index({ source: 1, createdAt: -1 });

// Indexes for Rewards
rewardSchema.index({ category: 1, isActive: 1 });
rewardSchema.index({ pointsCost: 1 });
rewardSchema.index({ featured: -1, priority: -1 });
rewardSchema.index({ tags: 1 });
rewardSchema.index({ validFrom: 1, validUntil: 1 });

// Indexes for Redemptions
redemptionSchema.index({ user: 1, createdAt: -1 });
redemptionSchema.index({ reward: 1, status: 1 });
redemptionSchema.index({ status: 1, createdAt: -1 });

// Virtual for reward availability
rewardSchema.virtual("isAvailable").get(function () {
  const now = new Date();
  const hasStock = this.isUnlimitedStock || this.availableStock > 0;
  const isInDateRange =
    (!this.validFrom || this.validFrom <= now) &&
    (!this.validUntil || this.validUntil > now);
  const underRedemptionLimit =
    !this.maxTotalRedemptions ||
    this.currentRedemptions < this.maxTotalRedemptions;

  return this.isActive && hasStock && isInDateRange && underRedemptionLimit;
});

// Virtual for primary image
rewardSchema.virtual("primaryImage").get(function () {
  const primaryImg = this.images.find((img) => img.isPrimary);
  return primaryImg || this.images[0] || null;
});

// Instance methods for Point Transactions
pointTransactionSchema.statics.createTransaction = async function (
  userId,
  amount,
  source,
  description,
  options = {}
) {
  const User = mongoose.model("User");
  const user = await User.findById(userId);

  if (!user) {
    throw new Error("User not found");
  }

  // Calculate new balance
  const newBalance = Math.max(0, user.points.current + amount);

  // Create transaction
  const transaction = new this({
    user: userId,
    type: amount > 0 ? "earned" : amount < 0 ? "redeemed" : "expired",
    amount,
    source,
    description,
    balanceAfter: newBalance,
    ...options,
  });

  // Update user points
  await User.findByIdAndUpdate(userId, {
    "points.current": newBalance,
    "points.lifetime":
      amount > 0 ? user.points.lifetime + amount : user.points.lifetime,
    "points.lastEarned": amount > 0 ? new Date() : user.points.lastEarned,
  });

  return transaction.save();
};

// Instance methods for Rewards
rewardSchema.methods.checkUserEligibility = async function (userId) {
  if (!this.isAvailable) {
    return { eligible: false, reason: "Reward not available" };
  }

  const Redemption = mongoose.model("Redemption");
  const userRedemptions = await Redemption.countDocuments({
    user: userId,
    reward: this._id,
    status: { $in: ["confirmed", "processing", "shipped", "delivered"] },
  });

  if (userRedemptions >= this.maxRedemptionsPerUser) {
    return { eligible: false, reason: "User redemption limit exceeded" };
  }

  const User = mongoose.model("User");
  const user = await User.findById(userId);

  if (!user || user.points.current < this.pointsCost) {
    return { eligible: false, reason: "Insufficient points" };
  }

  return { eligible: true };
};

rewardSchema.methods.incrementViews = function () {
  this.popularity.views += 1;
  return this.save({ validateBeforeSave: false });
};

// Instance methods for Redemptions
redemptionSchema.methods.confirm = async function () {
  const Reward = mongoose.model("Reward");
  const PointTransaction = mongoose.model("PointTransaction");

  // Update reward stock
  if (!this.reward.isUnlimitedStock) {
    await Reward.findByIdAndUpdate(this.reward, {
      $inc: {
        availableStock: -this.quantity,
        currentRedemptions: 1,
        "popularity.redemptions": 1,
      },
    });
  }

  // Create point transaction
  await PointTransaction.createTransaction(
    this.user,
    -this.pointsSpent,
    "reward_redemption",
    `Redeemed: ${this.reward.name}`,
    { relatedReward: this.reward }
  );

  this.status = "confirmed";
  return this.save();
};

redemptionSchema.methods.cancel = async function (reason) {
  const Reward = mongoose.model("Reward");
  const PointTransaction = mongoose.model("PointTransaction");

  // Refund points
  await PointTransaction.createTransaction(
    this.user,
    this.pointsSpent,
    "refund",
    `Refund for cancelled redemption: ${this.reward.name}`
  );

  // Restore reward stock
  if (!this.reward.isUnlimitedStock) {
    await Reward.findByIdAndUpdate(this.reward, {
      $inc: {
        availableStock: this.quantity,
        currentRedemptions: -1,
        "popularity.redemptions": -1,
      },
    });
  }

  this.status = "cancelled";
  this.refund = {
    reason,
    processedAt: new Date(),
    pointsRefunded: this.pointsSpent,
  };

  return this.save();
};

// Models
const PointTransaction = mongoose.model(
  "PointTransaction",
  pointTransactionSchema
);
const Reward = mongoose.model("Reward", rewardSchema);
const Redemption = mongoose.model("Redemption", redemptionSchema);

export { PointTransaction, Reward, Redemption };

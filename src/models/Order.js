import mongoose from "mongoose";

// Payment breakdown for minyak jelantah multi-level system
const paymentBreakdownSchema = new mongoose.Schema(
  {
    cashAmount: {
      type: Number,
      required: true,
      min: 0,
    },
    kasRtAmount: {
      type: Number,
      default: 0,
      min: 0,
    },
    incentiveAmount: {
      type: Number,
      default: 0,
      min: 0,
    },
    platformFee: {
      type: Number,
      default: 0,
      min: 0,
    },
    totalAmount: {
      type: Number,
      required: true,
      min: 0,
    },
  },
  { _id: false }
);

// Timeline tracking for order status changes
const timelineSchema = new mongoose.Schema(
  {
    status: {
      type: String,
      required: true,
    },
    timestamp: {
      type: Date,
      default: Date.now,
    },
    notes: String,
    updatedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
    },
  },
  { _id: false }
);

// Location for pickup/delivery
const locationSchema = new mongoose.Schema(
  {
    address: {
      street: String,
      village: String,
      district: String,
      city: String,
      province: String,
      postalCode: String,
    },
    coordinates: {
      latitude: {
        type: Number,
        required: true,
      },
      longitude: {
        type: Number,
        required: true,
      },
    },
    instructions: String, // Special pickup instructions
  },
  { _id: false }
);

const orderSchema = new mongoose.Schema(
  {
    // Order identification
    orderNumber: {
      type: String,
      unique: true,
      required: true,
    },

    // Order type based on business flow
    orderType: {
      type: String,
      enum: {
        values: [
          "scrap_pickup",
          "cooking_oil_warga_to_rt",
          "cooking_oil_rt_to_rw",
          "cooking_oil_rw_to_platform",
        ],
        message: "Invalid order type",
      },
      required: [true, "Order type is required"],
    },

    // Participants
    seller: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: [true, "Seller is required"],
    },
    buyer: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: [true, "Buyer is required"],
    },

    // For scrap orders - collector assignment
    assignedCollector: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
    },

    // Product information
    product: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Product",
      required: [true, "Product is required"],
    },

    // Quantity and pricing
    quantity: {
      weight: {
        type: Number, // for scrap items (kg)
        min: 0,
      },
      volume: {
        type: Number, // for cooking oil (liters)
        min: 0,
      },
    },

    pricing: {
      pricePerUnit: {
        type: Number,
        required: true,
        min: 0,
      },
      totalAmount: {
        type: Number,
        required: true,
        min: 0,
      },
      finalAmount: {
        type: Number, // actual amount after verification
        min: 0,
      },
    },

    // Payment breakdown (for cooking oil multi-level system)
    paymentBreakdown: paymentBreakdownSchema,

    // Order status
    status: {
      type: String,
      enum: {
        values: [
          "pending", // Order placed, waiting for collector
          "assigned", // Collector assigned
          "accepted", // Collector accepted the order
          "pickup_scheduled", // Pickup time scheduled
          "in_transit", // Collector on the way
          "arrived", // Collector arrived at location
          "verifying", // Verifying product quality/quantity
          "completed", // Transaction completed
          "cancelled", // Order cancelled
          "disputed", // Order in dispute
        ],
        message: "Invalid order status",
      },
      default: "pending",
    },

    // Location details
    pickupLocation: {
      type: locationSchema,
      required: true,
    },
    deliveryLocation: locationSchema, // for some order types

    // Scheduling
    scheduledPickupTime: {
      type: Date,
      validate: {
        validator: function (value) {
          return !value || value > new Date();
        },
        message: "Scheduled pickup time must be in the future",
      },
    },
    actualPickupTime: Date,
    completedAt: Date,

    // Quality verification
    verification: {
      actualWeight: {
        type: Number,
        min: 0,
      },
      actualVolume: {
        type: Number,
        min: 0,
      },
      qualityGrade: {
        type: String,
        enum: ["grade_a", "grade_b", "grade_c", "rejected"],
      },
      photos: [
        {
          url: String,
          publicId: String,
          caption: String,
          takenBy: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "User",
          },
          timestamp: {
            type: Date,
            default: Date.now,
          },
        },
      ],
      notes: String,
      verifiedBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
      },
      verifiedAt: Date,
    },

    // Communication
    messages: [
      {
        sender: {
          type: mongoose.Schema.Types.ObjectId,
          ref: "User",
          required: true,
        },
        message: {
          type: String,
          required: true,
          maxlength: 500,
        },
        timestamp: {
          type: Date,
          default: Date.now,
        },
        isSystemMessage: {
          type: Boolean,
          default: false,
        },
      },
    ],

    // Timeline tracking
    timeline: {
      type: [timelineSchema],
      default: function () {
        return [
          {
            status: "pending",
            timestamp: new Date(),
            notes: "Order created",
            updatedBy: this.seller,
          },
        ];
      },
    },

    // Cancellation details
    cancellation: {
      reason: {
        type: String,
        enum: [
          "seller_request",
          "buyer_request",
          "no_collector",
          "quality_issue",
          "other",
        ],
      },
      description: String,
      cancelledBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
      },
      cancelledAt: Date,
    },

    // Dispute handling
    dispute: {
      reason: String,
      description: String,
      initiatedBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
      },
      status: {
        type: String,
        enum: ["open", "investigating", "resolved", "escalated"],
        default: "open",
      },
      resolution: String,
      resolvedBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
      },
      resolvedAt: Date,
    },

    // Ratings (filled after completion)
    ratings: {
      sellerRating: {
        rating: {
          type: Number,
          min: 1,
          max: 5,
        },
        review: {
          type: String,
          maxlength: 500,
        },
        ratedBy: {
          type: mongoose.Schema.Types.ObjectId,
          ref: "User",
        },
        ratedAt: Date,
      },
      buyerRating: {
        rating: {
          type: Number,
          min: 1,
          max: 5,
        },
        review: {
          type: String,
          maxlength: 500,
        },
        ratedBy: {
          type: mongoose.Schema.Types.ObjectId,
          ref: "User",
        },
        ratedAt: Date,
      },
      collectorRating: {
        rating: {
          type: Number,
          min: 1,
          max: 5,
        },
        review: {
          type: String,
          maxlength: 500,
        },
        ratedBy: {
          type: mongoose.Schema.Types.ObjectId,
          ref: "User",
        },
        ratedAt: Date,
      },
    },

    // Points awarded
    pointsAwarded: {
      seller: {
        type: Number,
        default: 0,
        min: 0,
      },
      buyer: {
        type: Number,
        default: 0,
        min: 0,
      },
      collector: {
        type: Number,
        default: 0,
        min: 0,
      },
    },

    // Special flags
    isUrgent: {
      type: Boolean,
      default: false,
    },
    requiresSpecialHandling: {
      type: Boolean,
      default: false,
    },
    specialInstructions: String,

    // Auto-cancellation
    expiresAt: {
      type: Date,
      default: function () {
        // Auto cancel if no collector assigned within 24 hours
        return new Date(Date.now() + 24 * 60 * 60 * 1000);
      },
    },

    // Metadata
    deviceInfo: {
      platform: String,
      version: String,
      userAgent: String,
    },
    source: {
      type: String,
      enum: ["mobile_app", "web_app", "system"],
      default: "mobile_app",
    },
  },
  {
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
  }
);

// Indexes for performance
orderSchema.index({ orderNumber: 1 }, { unique: true });
orderSchema.index({ seller: 1, status: 1 });
orderSchema.index({ buyer: 1, status: 1 });
orderSchema.index({ assignedCollector: 1, status: 1 });
orderSchema.index({ status: 1, createdAt: -1 });
orderSchema.index({ orderType: 1, status: 1 });
orderSchema.index({ "pickupLocation.coordinates": "2dsphere" });
orderSchema.index({ expiresAt: 1 }); // for TTL functionality
orderSchema.index({ scheduledPickupTime: 1 });

// Virtual for distance calculation (will be populated by aggregation)
orderSchema.virtual("distance").get(function () {
  return this._distance;
});

// Virtual for order duration
orderSchema.virtual("duration").get(function () {
  if (this.completedAt) {
    return this.completedAt - this.createdAt;
  }
  return Date.now() - this.createdAt;
});

// Virtual for can be cancelled
orderSchema.virtual("canBeCancelled").get(function () {
  return ["pending", "assigned", "accepted", "pickup_scheduled"].includes(
    this.status
  );
});

// Virtual for can be rated
orderSchema.virtual("canBeRated").get(function () {
  return this.status === "completed";
});

// Pre-save middleware
orderSchema.pre("save", function (next) {
  // Generate order number if not exists
  if (!this.orderNumber) {
    const prefix = this.orderType === "scrap_pickup" ? "SP" : "CO";
    const timestamp = Date.now().toString().slice(-8);
    const random = Math.random().toString(36).substr(2, 4).toUpperCase();
    this.orderNumber = `${prefix}-${timestamp}-${random}`;
  }

  // Calculate payment breakdown for cooking oil orders
  if (this.orderType !== "scrap_pickup" && this.quantity.volume) {
    const volume = this.quantity.volume;
    const pricePerLiter = this.pricing.pricePerUnit;

    if (this.orderType === "cooking_oil_warga_to_rt") {
      // Warga → RT: Rp 4.000/liter breakdown
      this.paymentBreakdown = {
        cashAmount: 2500 * volume, // Rp 2.500 cash to warga
        kasRtAmount: 1000 * volume, // Rp 1.000 kas RT
        incentiveAmount: 500 * volume, // Rp 500 insentif RT
        totalAmount: 4000 * volume,
      };
    } else if (this.orderType === "cooking_oil_rt_to_rw") {
      // RT → RW: Rp 4.000/liter cash
      this.paymentBreakdown = {
        cashAmount: 4000 * volume,
        totalAmount: 4000 * volume,
      };
    } else if (this.orderType === "cooking_oil_rw_to_platform") {
      // RW → Platform: Rp 4.500/liter
      this.paymentBreakdown = {
        cashAmount: 4500 * volume,
        totalAmount: 4500 * volume,
      };
    }
  }

  next();
});

// Instance methods
orderSchema.methods.updateStatus = function (newStatus, updatedBy, notes) {
  this.status = newStatus;
  this.timeline.push({
    status: newStatus,
    timestamp: new Date(),
    notes: notes,
    updatedBy: updatedBy,
  });

  // Set specific timestamps
  switch (newStatus) {
    case "completed":
      this.completedAt = new Date();
      break;
    case "cancelled":
      this.cancellation.cancelledAt = new Date();
      break;
  }

  return this.save();
};

orderSchema.methods.assignCollector = function (collectorId) {
  this.assignedCollector = collectorId;
  this.status = "assigned";
  this.timeline.push({
    status: "assigned",
    timestamp: new Date(),
    notes: "Collector assigned",
    updatedBy: collectorId,
  });
  return this.save();
};

orderSchema.methods.schedulePickup = function (scheduledTime) {
  this.scheduledPickupTime = scheduledTime;
  this.status = "pickup_scheduled";
  this.timeline.push({
    status: "pickup_scheduled",
    timestamp: new Date(),
    notes: `Pickup scheduled for ${scheduledTime}`,
    updatedBy: this.assignedCollector,
  });
  return this.save();
};

orderSchema.methods.addMessage = function (
  sender,
  message,
  isSystemMessage = false
) {
  this.messages.push({
    sender,
    message,
    timestamp: new Date(),
    isSystemMessage,
  });
  return this.save({ validateBeforeSave: false });
};

orderSchema.methods.rateParticipant = function (
  ratedBy,
  rating,
  review,
  participantType
) {
  const ratingData = {
    rating,
    review,
    ratedBy,
    ratedAt: new Date(),
  };

  switch (participantType) {
    case "seller":
      this.ratings.sellerRating = ratingData;
      break;
    case "buyer":
      this.ratings.buyerRating = ratingData;
      break;
    case "collector":
      this.ratings.collectorRating = ratingData;
      break;
  }

  return this.save();
};

orderSchema.methods.cancelOrder = function (reason, description, cancelledBy) {
  this.status = "cancelled";
  this.cancellation = {
    reason,
    description,
    cancelledBy,
    cancelledAt: new Date(),
  };
  this.timeline.push({
    status: "cancelled",
    timestamp: new Date(),
    notes: `Order cancelled: ${reason}`,
    updatedBy: cancelledBy,
  });
  return this.save();
};

// Static methods
orderSchema.statics.findNearbyOrders = function (
  coordinates,
  radiusInKm = 10,
  collectorId
) {
  return this.aggregate([
    {
      $geoNear: {
        near: {
          type: "Point",
          coordinates: [coordinates.longitude, coordinates.latitude],
        },
        distanceField: "distance",
        maxDistance: radiusInKm * 1000,
        spherical: true,
        query: {
          status: "pending",
          orderType: "scrap_pickup",
          assignedCollector: { $exists: false },
        },
      },
    },
    {
      $lookup: {
        from: "users",
        localField: "seller",
        foreignField: "_id",
        as: "seller",
      },
    },
    {
      $lookup: {
        from: "products",
        localField: "product",
        foreignField: "_id",
        as: "product",
      },
    },
    {
      $unwind: "$seller",
    },
    {
      $unwind: "$product",
    },
    {
      $sort: { distance: 1, createdAt: -1 },
    },
  ]);
};

orderSchema.statics.getOrderStatistics = function (userId, role) {
  const matchCondition = {};

  if (role === "collector") {
    matchCondition.assignedCollector = mongoose.Types.ObjectId(userId);
  } else {
    matchCondition.$or = [
      { seller: mongoose.Types.ObjectId(userId) },
      { buyer: mongoose.Types.ObjectId(userId) },
    ];
  }

  return this.aggregate([
    { $match: matchCondition },
    {
      $group: {
        _id: "$status",
        count: { $sum: 1 },
        totalValue: { $sum: "$pricing.totalAmount" },
      },
    },
  ]);
};

// TTL index for auto-cancellation
orderSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

const Order = mongoose.model("Order", orderSchema);

export default Order;

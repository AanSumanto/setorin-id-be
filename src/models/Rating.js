import mongoose from "mongoose";

const ratingSchema = new mongoose.Schema(
  {
    // Order reference
    order: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Order",
      required: [true, "Order reference is required"],
    },

    // Rating participants
    rater: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: [true, "Rater is required"],
    },
    ratee: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: [true, "Ratee is required"],
    },

    // Rating type based on participant role
    ratingType: {
      type: String,
      enum: {
        values: [
          "seller_to_buyer",
          "buyer_to_seller",
          "seller_to_collector",
          "collector_to_seller",
          "buyer_to_collector",
          "collector_to_buyer",
        ],
        message: "Invalid rating type",
      },
      required: [true, "Rating type is required"],
    },

    // Rating score
    rating: {
      type: Number,
      required: [true, "Rating score is required"],
      min: [1, "Rating must be at least 1"],
      max: [5, "Rating must be at most 5"],
      validate: {
        validator: Number.isInteger,
        message: "Rating must be an integer",
      },
    },

    // Detailed ratings breakdown
    detailedRatings: {
      communication: {
        type: Number,
        min: 1,
        max: 5,
      },
      punctuality: {
        type: Number,
        min: 1,
        max: 5,
      },
      quality: {
        type: Number,
        min: 1,
        max: 5,
      },
      professionalism: {
        type: Number,
        min: 1,
        max: 5,
      },
      // For collectors specifically
      reliability: {
        type: Number,
        min: 1,
        max: 5,
      },
      fairness: {
        type: Number,
        min: 1,
        max: 5,
      },
    },

    // Review text
    review: {
      type: String,
      maxlength: [500, "Review cannot exceed 500 characters"],
      trim: true,
    },

    // Review tags (predefined positive/negative aspects)
    tags: [
      {
        type: String,
        enum: [
          // Positive tags
          "excellent_communication",
          "on_time",
          "fair_pricing",
          "professional",
          "reliable",
          "friendly",
          "accurate_description",
          "fast_response",
          "good_quality",
          "clean_packaging",
          "flexible_schedule",

          // Negative tags
          "poor_communication",
          "late",
          "unfair_pricing",
          "unprofessional",
          "unreliable",
          "rude",
          "misleading_description",
          "slow_response",
          "poor_quality",
          "dirty_packaging",
          "inflexible",
        ],
      },
    ],

    // Photos attached to review
    photos: [
      {
        url: {
          type: String,
          required: true,
        },
        publicId: {
          type: String,
          required: true,
        },
        caption: String,
      },
    ],

    // Review status
    status: {
      type: String,
      enum: {
        values: ["active", "hidden", "reported", "deleted"],
        message: "Invalid review status",
      },
      default: "active",
    },

    // Helpful votes from other users
    helpfulVotes: {
      helpful: [
        {
          user: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "User",
          },
          votedAt: {
            type: Date,
            default: Date.now,
          },
        },
      ],
      notHelpful: [
        {
          user: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "User",
          },
          votedAt: {
            type: Date,
            default: Date.now,
          },
        },
      ],
    },

    // Response from the ratee
    response: {
      text: {
        type: String,
        maxlength: [300, "Response cannot exceed 300 characters"],
        trim: true,
      },
      respondedAt: Date,
    },

    // Report information (if review is reported)
    reports: [
      {
        reporter: {
          type: mongoose.Schema.Types.ObjectId,
          ref: "User",
          required: true,
        },
        reason: {
          type: String,
          enum: [
            "inappropriate_content",
            "fake_review",
            "spam",
            "harassment",
            "other",
          ],
          required: true,
        },
        description: String,
        reportedAt: {
          type: Date,
          default: Date.now,
        },
      },
    ],

    // Admin moderation
    moderation: {
      isReviewed: {
        type: Boolean,
        default: false,
      },
      reviewedBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
      },
      reviewedAt: Date,
      moderationNotes: String,
      action: {
        type: String,
        enum: ["approved", "hidden", "edited", "deleted"],
      },
    },

    // Metadata
    isEdited: {
      type: Boolean,
      default: false,
    },
    editHistory: [
      {
        originalReview: String,
        editedAt: {
          type: Date,
          default: Date.now,
        },
        reason: String,
      },
    ],
  },
  {
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
  }
);

// Indexes for performance
ratingSchema.index({ order: 1, rater: 1, ratee: 1 }, { unique: true }); // One rating per participant pair per order
ratingSchema.index({ ratee: 1, status: 1 });
ratingSchema.index({ rater: 1 });
ratingSchema.index({ rating: -1, createdAt: -1 });
ratingSchema.index({ ratingType: 1 });
ratingSchema.index({ tags: 1 });
ratingSchema.index({ status: 1, createdAt: -1 });

// Virtual for helpful score
ratingSchema.virtual("helpfulScore").get(function () {
  const helpful = this.helpfulVotes.helpful.length;
  const notHelpful = this.helpfulVotes.notHelpful.length;
  return helpful - notHelpful;
});

// Virtual for overall detailed rating average
ratingSchema.virtual("detailedAverage").get(function () {
  if (!this.detailedRatings) return this.rating;

  const ratings = Object.values(this.detailedRatings).filter(
    (r) => r !== undefined && r !== null
  );
  if (ratings.length === 0) return this.rating;

  const sum = ratings.reduce((acc, rating) => acc + rating, 0);
  return Math.round((sum / ratings.length) * 10) / 10;
});

// Pre-save middleware
ratingSchema.pre("save", function (next) {
  // Calculate overall rating from detailed ratings if provided
  if (this.detailedRatings && Object.keys(this.detailedRatings).length > 0) {
    const validRatings = Object.values(this.detailedRatings).filter(
      (r) => r && r >= 1 && r <= 5
    );
    if (validRatings.length > 0) {
      const average =
        validRatings.reduce((sum, rating) => sum + rating, 0) /
        validRatings.length;
      this.rating = Math.round(average);
    }
  }

  // Auto-generate tags based on rating score
  if (this.rating >= 4 && !this.tags.some((tag) => tag.includes("excellent"))) {
    if (this.rating === 5) {
      this.tags.push("excellent_communication", "professional");
    }
  } else if (
    this.rating <= 2 &&
    !this.tags.some((tag) => tag.includes("poor"))
  ) {
    this.tags.push("poor_communication");
  }

  next();
});

// Post-save middleware to update user ratings
ratingSchema.post("save", async function (doc) {
  try {
    const User = mongoose.model("User");
    await User.updateUserRating(doc.ratee);
  } catch (error) {
    console.error("Error updating user rating:", error);
  }
});

// Instance methods
ratingSchema.methods.addHelpfulVote = function (userId, isHelpful) {
  // Remove any existing vote from this user
  this.helpfulVotes.helpful = this.helpfulVotes.helpful.filter(
    (vote) => vote.user.toString() !== userId.toString()
  );
  this.helpfulVotes.notHelpful = this.helpfulVotes.notHelpful.filter(
    (vote) => vote.user.toString() !== userId.toString()
  );

  // Add new vote
  if (isHelpful) {
    this.helpfulVotes.helpful.push({ user: userId });
  } else {
    this.helpfulVotes.notHelpful.push({ user: userId });
  }

  return this.save({ validateBeforeSave: false });
};

ratingSchema.methods.addResponse = function (responseText) {
  this.response = {
    text: responseText,
    respondedAt: new Date(),
  };
  return this.save();
};

ratingSchema.methods.reportReview = function (reporterId, reason, description) {
  this.reports.push({
    reporter: reporterId,
    reason,
    description,
  });

  // Auto-hide if multiple reports
  if (this.reports.length >= 3) {
    this.status = "reported";
  }

  return this.save();
};

ratingSchema.methods.editReview = function (newReview, reason) {
  // Store original in edit history
  this.editHistory.push({
    originalReview: this.review,
    reason,
  });

  this.review = newReview;
  this.isEdited = true;

  return this.save();
};

// Static methods
ratingSchema.statics.getUserRatingStats = async function (userId) {
  const stats = await this.aggregate([
    { $match: { ratee: mongoose.Types.ObjectId(userId), status: "active" } },
    {
      $group: {
        _id: null,
        averageRating: { $avg: "$rating" },
        totalRatings: { $sum: 1 },
        ratingDistribution: {
          $push: "$rating",
        },
        recentRatings: {
          $push: {
            $cond: [
              {
                $gte: [
                  "$createdAt",
                  new Date(Date.now() - 30 * 24 * 60 * 60 * 1000),
                ],
              },
              "$rating",
              null,
            ],
          },
        },
      },
    },
    {
      $project: {
        averageRating: { $round: ["$averageRating", 1] },
        totalRatings: 1,
        fiveStars: {
          $size: {
            $filter: {
              input: "$ratingDistribution",
              as: "rating",
              cond: { $eq: ["$$rating", 5] },
            },
          },
        },
        fourStars: {
          $size: {
            $filter: {
              input: "$ratingDistribution",
              as: "rating",
              cond: { $eq: ["$$rating", 4] },
            },
          },
        },
        threeStars: {
          $size: {
            $filter: {
              input: "$ratingDistribution",
              as: "rating",
              cond: { $eq: ["$$rating", 3] },
            },
          },
        },
        twoStars: {
          $size: {
            $filter: {
              input: "$ratingDistribution",
              as: "rating",
              cond: { $eq: ["$$rating", 2] },
            },
          },
        },
        oneStar: {
          $size: {
            $filter: {
              input: "$ratingDistribution",
              as: "rating",
              cond: { $eq: ["$$rating", 1] },
            },
          },
        },
        recentAverageRating: {
          $avg: {
            $filter: {
              input: "$recentRatings",
              as: "rating",
              cond: { $ne: ["$$rating", null] },
            },
          },
        },
      },
    },
  ]);

  return (
    stats[0] || {
      averageRating: 0,
      totalRatings: 0,
      fiveStars: 0,
      fourStars: 0,
      threeStars: 0,
      twoStars: 0,
      oneStar: 0,
      recentAverageRating: 0,
    }
  );
};

ratingSchema.statics.getTopRatedUsers = function (role = null, limit = 10) {
  const matchCondition = { status: "active" };

  const pipeline = [
    { $match: matchCondition },
    {
      $group: {
        _id: "$ratee",
        averageRating: { $avg: "$rating" },
        totalRatings: { $sum: 1 },
      },
    },
    {
      $lookup: {
        from: "users",
        localField: "_id",
        foreignField: "_id",
        as: "user",
      },
    },
    { $unwind: "$user" },
    {
      $match: role ? { "user.role": role } : {},
    },
    {
      $project: {
        user: {
          _id: 1,
          name: 1,
          avatar: 1,
          role: 1,
        },
        averageRating: { $round: ["$averageRating", 1] },
        totalRatings: 1,
      },
    },
    { $sort: { averageRating: -1, totalRatings: -1 } },
    { $limit: limit },
  ];

  return this.aggregate(pipeline);
};

ratingSchema.statics.getRatingTrends = function (userId, days = 30) {
  const startDate = new Date(Date.now() - days * 24 * 60 * 60 * 1000);

  return this.aggregate([
    {
      $match: {
        ratee: mongoose.Types.ObjectId(userId),
        status: "active",
        createdAt: { $gte: startDate },
      },
    },
    {
      $group: {
        _id: {
          $dateToString: {
            format: "%Y-%m-%d",
            date: "$createdAt",
          },
        },
        averageRating: { $avg: "$rating" },
        count: { $sum: 1 },
      },
    },
    { $sort: { _id: 1 } },
  ]);
};

const Rating = mongoose.model("Rating", ratingSchema);

export default Rating;

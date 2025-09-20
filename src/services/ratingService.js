import { Rating, Order, User } from "../models/index.js";
import { createLogger } from "../utils/logger.js";
import { AppError } from "../middlewares/errorMiddleware.js";

const logger = createLogger("RatingService");

class RatingService {
  // Create new rating/review
  async createRating(ratingData, currentUser) {
    try {
      const {
        orderId,
        rateeId,
        rating,
        review,
        detailedRatings,
        tags,
        photos,
      } = ratingData;

      // Validate order exists and is completed
      const order = await Order.findById(orderId).populate(
        "seller buyer assignedCollector"
      );

      if (!order) {
        throw new AppError("errors.order_not_found", 404);
      }

      if (order.status !== "completed") {
        throw new AppError("business.can_only_rate_completed_orders", 400);
      }

      // Validate user can rate in this order
      const canRate = this.canUserRateInOrder(order, currentUser._id, rateeId);
      if (!canRate.allowed) {
        throw new AppError("errors.insufficient_permissions", 403);
      }

      // Check if rating already exists
      const existingRating = await Rating.findOne({
        order: orderId,
        rater: currentUser._id,
        ratee: rateeId,
      });

      if (existingRating) {
        throw new AppError("business.rating_already_exists", 400);
      }

      // Validate ratee exists
      const ratee = await User.findById(rateeId);
      if (!ratee) {
        throw new AppError("errors.user_not_found", 404);
      }

      // Determine rating type based on roles
      const ratingType = this.determineRatingType(
        currentUser.role,
        ratee.role,
        order.orderType,
        order.assignedCollector
      );

      // Create rating
      const newRating = new Rating({
        order: orderId,
        rater: currentUser._id,
        ratee: rateeId,
        ratingType,
        rating,
        review: review || "",
        detailedRatings: detailedRatings || {},
        tags: tags || [],
        photos: photos || [],
        status: "active",
      });

      await newRating.save();

      // Update user's overall rating (handled by post-save middleware)
      // But we'll also update the order's rating record
      await this.updateOrderRating(order, newRating);

      // Award points for giving rating
      await this.awardRatingPoints(currentUser._id, "rating_given");

      // Populate rating details
      await newRating.populate([
        { path: "rater", select: "name avatar role" },
        { path: "ratee", select: "name avatar role" },
        { path: "order", select: "orderNumber orderType" },
      ]);

      logger.info(
        `Rating created: ${newRating._id} by ${currentUser._id} for ${rateeId}`
      );

      return newRating;
    } catch (error) {
      logger.error("Error creating rating:", error);
      throw error;
    }
  }

  // Get ratings for a user
  async getUserRatings(userId, filters = {}, pagination = {}) {
    try {
      const {
        role,
        ratingType,
        minRating,
        maxRating,
        dateFrom,
        dateTo,
        withPhotos,
      } = filters;
      const {
        page = 1,
        limit = 20,
        sort = "createdAt",
        order = "desc",
      } = pagination;

      // Build query
      let query = {
        ratee: userId,
        status: "active",
      };

      // Apply filters
      if (ratingType) {
        query.ratingType = ratingType;
      }

      if (minRating || maxRating) {
        query.rating = {};
        if (minRating) query.rating.$gte = parseInt(minRating);
        if (maxRating) query.rating.$lte = parseInt(maxRating);
      }

      if (dateFrom || dateTo) {
        query.createdAt = {};
        if (dateFrom) query.createdAt.$gte = new Date(dateFrom);
        if (dateTo) query.createdAt.$lte = new Date(dateTo);
      }

      if (withPhotos) {
        query["photos.0"] = { $exists: true };
      }

      // Filter by rater role if specified
      if (role) {
        const raters = await User.find({ role }).select("_id");
        const raterIds = raters.map((r) => r._id);
        query.rater = { $in: raterIds };
      }

      // Execute query
      const totalItems = await Rating.countDocuments(query);
      const totalPages = Math.ceil(totalItems / limit);
      const skip = (page - 1) * limit;

      const sortObj = {};
      sortObj[sort] = order === "desc" ? -1 : 1;

      const ratings = await Rating.find(query)
        .populate([
          { path: "rater", select: "name avatar role" },
          { path: "order", select: "orderNumber orderType createdAt" },
        ])
        .sort(sortObj)
        .skip(skip)
        .limit(limit)
        .exec();

      return {
        ratings,
        pagination: {
          page,
          totalPages,
          totalItems,
          limit,
          hasNext: page < totalPages,
          hasPrev: page > 1,
        },
      };
    } catch (error) {
      logger.error("Error getting user ratings:", error);
      throw error;
    }
  }

  // Get ratings given by a user
  async getRatingsGivenByUser(userId, filters = {}, pagination = {}) {
    try {
      const { dateFrom, dateTo } = filters;
      const { page = 1, limit = 20 } = pagination;

      let query = {
        rater: userId,
        status: "active",
      };

      if (dateFrom || dateTo) {
        query.createdAt = {};
        if (dateFrom) query.createdAt.$gte = new Date(dateFrom);
        if (dateTo) query.createdAt.$lte = new Date(dateTo);
      }

      const totalItems = await Rating.countDocuments(query);
      const totalPages = Math.ceil(totalItems / limit);
      const skip = (page - 1) * limit;

      const ratings = await Rating.find(query)
        .populate([
          { path: "ratee", select: "name avatar role" },
          { path: "order", select: "orderNumber orderType" },
        ])
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .exec();

      return {
        ratings,
        pagination: {
          page,
          totalPages,
          totalItems,
          limit,
          hasNext: page < totalPages,
          hasPrev: page > 1,
        },
      };
    } catch (error) {
      logger.error("Error getting ratings given by user:", error);
      throw error;
    }
  }

  // Get rating statistics for a user
  async getUserRatingStats(userId) {
    try {
      const stats = await Rating.getUserRatingStats(userId);

      // Get additional breakdown by rating type
      const ratingTypeStats = await Rating.aggregate([
        {
          $match: {
            ratee: userId,
            status: "active",
          },
        },
        {
          $group: {
            _id: "$ratingType",
            averageRating: { $avg: "$rating" },
            count: { $sum: 1 },
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
            count: 1,
            recentAverageRating: {
              $round: [
                {
                  $avg: {
                    $filter: {
                      input: "$recentRatings",
                      as: "rating",
                      cond: { $ne: ["$$rating", null] },
                    },
                  },
                },
                1,
              ],
            },
          },
        },
      ]);

      // Get most common tags
      const commonTags = await Rating.aggregate([
        {
          $match: {
            ratee: userId,
            status: "active",
            tags: { $not: { $size: 0 } },
          },
        },
        { $unwind: "$tags" },
        {
          $group: {
            _id: "$tags",
            count: { $sum: 1 },
          },
        },
        { $sort: { count: -1 } },
        { $limit: 10 },
      ]);

      return {
        ...stats,
        byRatingType: ratingTypeStats,
        commonTags: commonTags.map((tag) => ({
          tag: tag._id,
          count: tag.count,
        })),
      };
    } catch (error) {
      logger.error("Error getting user rating stats:", error);
      throw error;
    }
  }

  // Update rating (edit)
  async updateRating(ratingId, updateData, currentUser) {
    try {
      const rating = await Rating.findById(ratingId);

      if (!rating) {
        throw new AppError("errors.rating_not_found", 404);
      }

      // Check if user can edit this rating
      if (
        rating.rater.toString() !== currentUser._id.toString() &&
        currentUser.role !== "admin"
      ) {
        throw new AppError("errors.insufficient_permissions", 403);
      }

      // Check if rating can still be edited (within 24 hours)
      const editDeadline = new Date(
        rating.createdAt.getTime() + 24 * 60 * 60 * 1000
      );
      if (new Date() > editDeadline && currentUser.role !== "admin") {
        throw new AppError("business.rating_edit_deadline_passed", 400);
      }

      // Store original for edit history
      const originalReview = rating.review;

      // Update rating
      const allowedFields = ["rating", "review", "detailedRatings", "tags"];
      const updates = {};

      allowedFields.forEach((field) => {
        if (updateData[field] !== undefined) {
          updates[field] = updateData[field];
        }
      });

      const updatedRating = await Rating.findByIdAndUpdate(
        ratingId,
        {
          ...updates,
          isEdited: true,
          $push: {
            editHistory: {
              originalReview,
              reason: updateData.editReason || "Updated by user",
            },
          },
        },
        { new: true, runValidators: true }
      ).populate([
        { path: "rater", select: "name avatar role" },
        { path: "ratee", select: "name avatar role" },
      ]);

      logger.info(`Rating updated: ${ratingId} by ${currentUser._id}`);

      return updatedRating;
    } catch (error) {
      logger.error("Error updating rating:", error);
      throw error;
    }
  }

  // Add helpful vote to rating
  async addHelpfulVote(ratingId, currentUser, isHelpful) {
    try {
      const rating = await Rating.findById(ratingId);

      if (!rating) {
        throw new AppError("errors.rating_not_found", 404);
      }

      // Can't vote on own rating
      if (rating.rater.toString() === currentUser._id.toString()) {
        throw new AppError("business.cannot_vote_on_own_rating", 400);
      }

      await rating.addHelpfulVote(currentUser._id, isHelpful);

      logger.info(
        `Helpful vote added to rating: ${ratingId} by ${currentUser._id}`
      );

      return { message: "Vote recorded successfully" };
    } catch (error) {
      logger.error("Error adding helpful vote:", error);
      throw error;
    }
  }

  // Add response to rating (ratee responds)
  async addRatingResponse(ratingId, responseText, currentUser) {
    try {
      const rating = await Rating.findById(ratingId);

      if (!rating) {
        throw new AppError("errors.rating_not_found", 404);
      }

      // Check if user can respond (must be the ratee)
      if (
        rating.ratee.toString() !== currentUser._id.toString() &&
        currentUser.role !== "admin"
      ) {
        throw new AppError("errors.insufficient_permissions", 403);
      }

      // Check if response already exists
      if (rating.response && rating.response.text) {
        throw new AppError("business.rating_response_already_exists", 400);
      }

      await rating.addResponse(responseText);

      logger.info(
        `Response added to rating: ${ratingId} by ${currentUser._id}`
      );

      return { message: "Response added successfully" };
    } catch (error) {
      logger.error("Error adding rating response:", error);
      throw error;
    }
  }

  // Report rating
  async reportRating(ratingId, reportData, currentUser) {
    try {
      const { reason, description } = reportData;

      const rating = await Rating.findById(ratingId);

      if (!rating) {
        throw new AppError("errors.rating_not_found", 404);
      }

      // Can't report own rating
      if (rating.rater.toString() === currentUser._id.toString()) {
        throw new AppError("business.cannot_report_own_rating", 400);
      }

      await rating.reportReview(currentUser._id, reason, description);

      logger.info(`Rating reported: ${ratingId} by ${currentUser._id}`);

      return { message: "Rating reported successfully" };
    } catch (error) {
      logger.error("Error reporting rating:", error);
      throw error;
    }
  }

  // Get top rated users
  async getTopRatedUsers(role = null, timeframe = "all", limit = 10) {
    try {
      let dateFilter = {};

      if (timeframe !== "all") {
        const days =
          timeframe === "week" ? 7 : timeframe === "month" ? 30 : 365;
        dateFilter.createdAt = {
          $gte: new Date(Date.now() - days * 24 * 60 * 60 * 1000),
        };
      }

      const topRated = await Rating.aggregate([
        {
          $match: {
            status: "active",
            ...dateFilter,
          },
        },
        {
          $group: {
            _id: "$ratee",
            averageRating: { $avg: "$rating" },
            totalRatings: { $sum: 1 },
          },
        },
        {
          $match: {
            totalRatings: { $gte: 3 }, // Minimum 3 ratings
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
        {
          $sort: {
            averageRating: -1,
            totalRatings: -1,
          },
        },
        { $limit: limit },
      ]);

      return topRated;
    } catch (error) {
      logger.error("Error getting top rated users:", error);
      throw error;
    }
  }

  // Get rating trends
  async getRatingTrends(userId, days = 30) {
    try {
      const trends = await Rating.getRatingTrends(userId, days);
      return trends;
    } catch (error) {
      logger.error("Error getting rating trends:", error);
      throw error;
    }
  }

  // Get ratings that need moderation
  async getRatingsForModeration(filters = {}, pagination = {}) {
    try {
      const { status = "reported" } = filters;
      const { page = 1, limit = 20 } = pagination;

      let query = {
        $or: [{ status: "reported" }, { "reports.0": { $exists: true } }],
      };

      if (status !== "all") {
        query.status = status;
      }

      const totalItems = await Rating.countDocuments(query);
      const totalPages = Math.ceil(totalItems / limit);
      const skip = (page - 1) * limit;

      const ratings = await Rating.find(query)
        .populate([
          { path: "rater", select: "name avatar role" },
          { path: "ratee", select: "name avatar role" },
          { path: "reports.reporter", select: "name role" },
        ])
        .sort({ "reports.reportedAt": -1 })
        .skip(skip)
        .limit(limit)
        .exec();

      return {
        ratings,
        pagination: {
          page,
          totalPages,
          totalItems,
          limit,
          hasNext: page < totalPages,
          hasPrev: page > 1,
        },
      };
    } catch (error) {
      logger.error("Error getting ratings for moderation:", error);
      throw error;
    }
  }

  // Moderate rating (admin action)
  async moderateRating(ratingId, moderationData, currentUser) {
    try {
      if (currentUser.role !== "admin") {
        throw new AppError("errors.insufficient_permissions", 403);
      }

      const { action, notes } = moderationData;

      const rating = await Rating.findById(ratingId);

      if (!rating) {
        throw new AppError("errors.rating_not_found", 404);
      }

      // Update moderation status
      rating.moderation = {
        isReviewed: true,
        reviewedBy: currentUser._id,
        reviewedAt: new Date(),
        moderationNotes: notes,
        action,
      };

      // Apply moderation action
      switch (action) {
        case "approved":
          rating.status = "active";
          break;
        case "hidden":
          rating.status = "hidden";
          break;
        case "deleted":
          rating.status = "deleted";
          break;
      }

      await rating.save();

      logger.info(
        `Rating moderated: ${ratingId} - ${action} by ${currentUser._id}`
      );

      return { message: `Rating ${action} successfully` };
    } catch (error) {
      logger.error("Error moderating rating:", error);
      throw error;
    }
  }

  // Get pending ratings for completed orders
  async getPendingRatings(userId) {
    try {
      // Get completed orders where user participated but hasn't rated yet
      const completedOrders = await Order.find({
        $or: [
          { seller: userId },
          { buyer: userId },
          { assignedCollector: userId },
        ],
        status: "completed",
        completedAt: {
          $gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000), // Last 30 days
        },
      }).populate("seller buyer assignedCollector product");

      const pendingRatings = [];

      for (const order of completedOrders) {
        const participants = this.getOrderParticipants(order, userId);

        for (const participant of participants) {
          // Check if rating already exists
          const existingRating = await Rating.findOne({
            order: order._id,
            rater: userId,
            ratee: participant._id,
          });

          if (!existingRating) {
            pendingRatings.push({
              order: {
                _id: order._id,
                orderNumber: order.orderNumber,
                orderType: order.orderType,
                completedAt: order.completedAt,
              },
              ratee: {
                _id: participant._id,
                name: participant.name,
                avatar: participant.avatar,
                role: participant.role,
              },
              canRate: true,
            });
          }
        }
      }

      return pendingRatings;
    } catch (error) {
      logger.error("Error getting pending ratings:", error);
      throw error;
    }
  }

  // Helper methods
  canUserRateInOrder(order, raterId, rateeId) {
    const raterStr = raterId.toString();
    const rateeStr = rateeId.toString();
    const sellerStr = order.seller._id.toString();
    const buyerStr = order.buyer._id.toString();
    const collectorStr = order.assignedCollector?._id.toString();

    // Define valid rating relationships
    const validRatings = [];

    // Seller can rate buyer and collector
    if (raterStr === sellerStr) {
      validRatings.push(buyerStr);
      if (collectorStr) validRatings.push(collectorStr);
    }

    // Buyer can rate seller and collector
    if (raterStr === buyerStr) {
      validRatings.push(sellerStr);
      if (collectorStr) validRatings.push(collectorStr);
    }

    // Collector can rate seller and buyer
    if (collectorStr && raterStr === collectorStr) {
      validRatings.push(sellerStr);
      validRatings.push(buyerStr);
    }

    return {
      allowed: validRatings.includes(rateeStr),
      validTargets: validRatings,
    };
  }

  determineRatingType(raterRole, rateeRole, orderType, collectorId) {
    if (raterRole === "individual" && rateeRole === "individual") {
      return "buyer_to_seller";
    }
    if (raterRole === "individual" && rateeRole === "collector") {
      return "seller_to_collector";
    }
    if (raterRole === "collector" && rateeRole === "individual") {
      return "collector_to_seller";
    }
    if (raterRole === "rt" && rateeRole === "individual") {
      return "buyer_to_seller";
    }
    if (raterRole === "individual" && rateeRole === "rt") {
      return "seller_to_buyer";
    }
    if (raterRole === "rw" && rateeRole === "rt") {
      return "buyer_to_seller";
    }
    if (raterRole === "rt" && rateeRole === "rw") {
      return "seller_to_buyer";
    }

    // Default fallback
    return "seller_to_buyer";
  }

  getOrderParticipants(order, currentUserId) {
    const participants = [];
    const currentUserStr = currentUserId.toString();

    if (order.seller._id.toString() !== currentUserStr) {
      participants.push(order.seller);
    }
    if (order.buyer._id.toString() !== currentUserStr) {
      participants.push(order.buyer);
    }
    if (
      order.assignedCollector &&
      order.assignedCollector._id.toString() !== currentUserStr
    ) {
      participants.push(order.assignedCollector);
    }

    return participants;
  }

  async updateOrderRating(order, rating) {
    try {
      const ratingType = rating.ratingType;
      const ratingValue = rating.rating;

      // Update order's rating records
      if (ratingType.includes("seller")) {
        if (!order.ratings.sellerRating.rating) {
          order.ratings.sellerRating = {
            rating: ratingValue,
            review: rating.review,
            ratedBy: rating.rater,
            ratedAt: new Date(),
          };
        }
      } else if (ratingType.includes("buyer")) {
        if (!order.ratings.buyerRating.rating) {
          order.ratings.buyerRating = {
            rating: ratingValue,
            review: rating.review,
            ratedBy: rating.rater,
            ratedAt: new Date(),
          };
        }
      } else if (ratingType.includes("collector")) {
        if (!order.ratings.collectorRating.rating) {
          order.ratings.collectorRating = {
            rating: ratingValue,
            review: rating.review,
            ratedBy: rating.rater,
            ratedAt: new Date(),
          };
        }
      }

      await order.save();
    } catch (error) {
      logger.error("Error updating order rating:", error);
    }
  }

  async awardRatingPoints(userId, reason) {
    try {
      const user = await User.findById(userId);
      if (user) {
        await user.addPoints(5, reason); // 5 points for giving a rating
      }
    } catch (error) {
      logger.error("Error awarding rating points:", error);
    }
  }
}

// Create singleton instance
const ratingService = new RatingService();

export default ratingService;

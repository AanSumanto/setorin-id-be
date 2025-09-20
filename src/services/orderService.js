import { Order, Product, User, ServiceCoverage } from "../models/index.js";
import { createLogger } from "../utils/logger.js";
import { AppError } from "../middlewares/errorMiddleware.js";
import productService from "./productService.js";

const logger = createLogger("OrderService");

class OrderService {
  // Create new order (scrap pickup)
  async createScrapOrder(orderData, currentUser) {
    try {
      const { productId, scheduledPickupTime, specialInstructions } = orderData;

      // Validate product
      const product = await Product.findById(productId).populate("owner");

      if (!product) {
        throw new AppError("errors.product_not_found", 404);
      }

      if (!product.isAvailable || product.status !== "active") {
        throw new AppError("business.product_not_available", 400);
      }

      // Can't order own products (for individuals)
      if (
        currentUser.role === "individual" &&
        product.owner._id.toString() === currentUser._id.toString()
      ) {
        throw new AppError("business.cannot_order_own_product", 400);
      }

      // For RT/RW, they can order from their area members or sell to collectors
      if (["rt", "rw"].includes(currentUser.role)) {
        // This will be implemented based on specific business rules
        // For now, allow RT/RW to create orders
      }

      // Calculate pricing
      const quantity = {
        weight: product.scrapData?.estimatedWeight || 0,
      };

      const pricing = {
        pricePerUnit: product.scrapData?.pricePerKg || 0,
        totalAmount: quantity.weight * (product.scrapData?.pricePerKg || 0),
      };

      // Set pickup location (product location)
      const pickupLocation = {
        address: product.location.address,
        coordinates: {
          latitude: product.location.coordinates.latitude,
          longitude: product.location.coordinates.longitude,
        },
        instructions: specialInstructions,
      };

      // Create order
      const order = new Order({
        orderType: "scrap_pickup",
        seller: product.owner._id,
        buyer: currentUser._id,
        product: productId,
        quantity,
        pricing,
        pickupLocation,
        scheduledPickupTime: scheduledPickupTime
          ? new Date(scheduledPickupTime)
          : undefined,
        specialInstructions,
        isUrgent: orderData.isUrgent || false,
      });

      await order.save();

      // Reserve the product
      await productService.markAsReserved(productId, currentUser._id);

      // Find and assign nearby collectors
      await this.findAndNotifyCollectors(order);

      // Populate order details
      await order.populate([
        { path: "seller", select: "name avatar rating addresses" },
        { path: "buyer", select: "name avatar rating" },
        { path: "product", select: "title images category type" },
      ]);

      logger.info(
        `Scrap order created: ${order._id} by user ${currentUser._id}`
      );

      return order;
    } catch (error) {
      logger.error("Error creating scrap order:", error);
      throw error;
    }
  }

  // Get order by ID
  async getOrderById(orderId, currentUser) {
    try {
      const order = await Order.findById(orderId)
        .populate([
          { path: "seller", select: "name avatar rating addresses role" },
          { path: "buyer", select: "name avatar rating role" },
          {
            path: "assignedCollector",
            select: "name avatar rating collectorData",
          },
          { path: "product", select: "title images category type location" },
        ])
        .exec();

      if (!order) {
        throw new AppError("errors.order_not_found", 404);
      }

      // Check if user can view this order
      const canView = this.canUserAccessOrder(order, currentUser);
      if (!canView) {
        throw new AppError("errors.insufficient_permissions", 403);
      }

      return order;
    } catch (error) {
      logger.error("Error getting order by ID:", error);
      throw error;
    }
  }

  // Get orders for a user
  async getUserOrders(userId, filters = {}, pagination = {}) {
    try {
      const { role, status, orderType, dateFrom, dateTo } = filters;

      const {
        page = 1,
        limit = 20,
        sort = "createdAt",
        order = "desc",
      } = pagination;

      // Build query based on user role
      let query = {};

      if (role === "collector") {
        query.assignedCollector = userId;
      } else {
        query.$or = [{ seller: userId }, { buyer: userId }];
      }

      // Apply filters
      if (status) {
        query.status = status;
      }

      if (orderType) {
        query.orderType = orderType;
      }

      if (dateFrom || dateTo) {
        query.createdAt = {};
        if (dateFrom) query.createdAt.$gte = new Date(dateFrom);
        if (dateTo) query.createdAt.$lte = new Date(dateTo);
      }

      // Execute query
      const totalItems = await Order.countDocuments(query);
      const totalPages = Math.ceil(totalItems / limit);
      const skip = (page - 1) * limit;

      const sortObj = {};
      sortObj[sort] = order === "desc" ? -1 : 1;

      const orders = await Order.find(query)
        .populate([
          { path: "seller", select: "name avatar rating role" },
          { path: "buyer", select: "name avatar rating role" },
          { path: "assignedCollector", select: "name avatar rating" },
          { path: "product", select: "title images category type" },
        ])
        .sort(sortObj)
        .skip(skip)
        .limit(limit)
        .exec();

      return {
        orders,
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
      logger.error("Error getting user orders:", error);
      throw error;
    }
  }

  // Get available orders for collectors
  async getAvailableOrdersForCollector(collectorId, coordinates, radius = 15) {
    try {
      const collector = await User.findById(collectorId);

      if (!collector || collector.role !== "collector") {
        throw new AppError("errors.invalid_collector", 400);
      }

      // Check if collector is available
      if (!collector.collectorData?.isAvailable) {
        throw new AppError("business.collector_not_available", 400);
      }

      // Use collector's service area if coordinates not provided
      let searchCoords = coordinates;
      let searchRadius = radius;

      if (!searchCoords && collector.collectorData?.serviceRadius) {
        const defaultAddress = collector.defaultAddress;
        if (defaultAddress) {
          searchCoords = [
            defaultAddress.coordinates.coordinates[0],
            defaultAddress.coordinates.coordinates[1],
          ];
          searchRadius = collector.collectorData.serviceRadius;
        }
      }

      if (!searchCoords) {
        throw new AppError("errors.coordinates_required", 400);
      }

      // Find nearby orders
      const orders = await Order.findNearbyOrders(
        searchCoords,
        searchRadius,
        collectorId
      );

      // Filter by collector's operating hours
      const now = new Date();
      const currentDay = now.toLocaleDateString("en-US", {
        weekday: "lowercase",
      });
      const currentTime = now.toTimeString().substring(0, 5);

      const operatingHours = collector.collectorData?.operatingHours;
      if (operatingHours && operatingHours[currentDay]) {
        const daySchedule = operatingHours[currentDay];
        if (
          !daySchedule.isActive ||
          currentTime < daySchedule.start ||
          currentTime > daySchedule.end
        ) {
          // Return empty if outside operating hours, but don't throw error
          return { orders: [], message: "Outside operating hours" };
        }
      }

      return { orders };
    } catch (error) {
      logger.error("Error getting available orders for collector:", error);
      throw error;
    }
  }

  // Accept order (collector accepts)
  async acceptOrder(orderId, collectorId, estimatedArrival) {
    try {
      const order = await Order.findById(orderId);

      if (!order) {
        throw new AppError("errors.order_not_found", 404);
      }

      if (order.status !== "pending" && order.status !== "assigned") {
        throw new AppError("business.order_cannot_be_accepted", 400, {
          status: order.status,
        });
      }

      if (
        order.assignedCollector &&
        order.assignedCollector.toString() !== collectorId
      ) {
        throw new AppError("business.order_already_assigned", 400);
      }

      // Assign collector if not already assigned
      if (!order.assignedCollector) {
        await order.assignCollector(collectorId);
      }

      // Update status to accepted
      await order.updateStatus(
        "accepted",
        collectorId,
        "Order accepted by collector"
      );

      // Set estimated arrival
      if (estimatedArrival) {
        order.scheduledPickupTime = new Date(estimatedArrival);
        await order.save();
      }

      // Notify seller
      await this.sendOrderNotification(order, "order_accepted");

      logger.info(`Order accepted: ${orderId} by collector ${collectorId}`);

      return order;
    } catch (error) {
      logger.error("Error accepting order:", error);
      throw error;
    }
  }

  // Update order status
  async updateOrderStatus(orderId, newStatus, currentUser, notes = "") {
    try {
      const order = await Order.findById(orderId);

      if (!order) {
        throw new AppError("errors.order_not_found", 404);
      }

      // Check permissions
      const canUpdate = this.canUserUpdateOrderStatus(
        order,
        currentUser,
        newStatus
      );
      if (!canUpdate) {
        throw new AppError("errors.insufficient_permissions", 403);
      }

      // Validate status transition
      const validTransitions = this.getValidStatusTransitions(order.status);
      if (!validTransitions.includes(newStatus)) {
        throw new AppError("business.invalid_status_transition", 400, {
          from: order.status,
          to: newStatus,
        });
      }

      await order.updateStatus(newStatus, currentUser._id, notes);

      // Handle specific status updates
      await this.handleStatusUpdate(order, newStatus, currentUser);

      logger.info(
        `Order status updated: ${orderId} to ${newStatus} by ${currentUser._id}`
      );

      return order;
    } catch (error) {
      logger.error("Error updating order status:", error);
      throw error;
    }
  }

  // Cancel order
  async cancelOrder(orderId, currentUser, reason, description) {
    try {
      const order = await Order.findById(orderId);

      if (!order) {
        throw new AppError("errors.order_not_found", 404);
      }

      // Check if order can be cancelled
      if (!order.canBeCancelled) {
        throw new AppError("business.order_cannot_be_cancelled", 400, {
          status: order.status,
        });
      }

      // Check permissions
      const canCancel = this.canUserCancelOrder(order, currentUser);
      if (!canCancel) {
        throw new AppError("errors.insufficient_permissions", 403);
      }

      await order.cancelOrder(reason, description, currentUser._id);

      // Release product reservation
      if (order.product) {
        const product = await Product.findById(order.product);
        if (product && product.status === "reserved") {
          product.status = "active";
          product.isAvailable = true;
          await product.save();
        }
      }

      // Notify participants
      await this.sendOrderNotification(order, "order_cancelled");

      logger.info(`Order cancelled: ${orderId} by ${currentUser._id}`);

      return order;
    } catch (error) {
      logger.error("Error cancelling order:", error);
      throw error;
    }
  }

  // Complete order
  async completeOrder(orderId, completionData, currentUser) {
    try {
      const {
        actualWeight,
        actualVolume,
        qualityGrade,
        finalAmount,
        verificationPhotos,
        notes,
      } = completionData;

      const order = await Order.findById(orderId).populate("product");

      if (!order) {
        throw new AppError("errors.order_not_found", 404);
      }

      if (order.status !== "verifying" && order.status !== "arrived") {
        throw new AppError("business.order_cannot_be_completed", 400, {
          status: order.status,
        });
      }

      // Update verification data
      order.verification = {
        actualWeight,
        actualVolume,
        qualityGrade,
        photos: verificationPhotos || [],
        notes,
        verifiedBy: currentUser._id,
        verifiedAt: new Date(),
      };

      // Set final amount
      if (finalAmount) {
        order.pricing.finalAmount = finalAmount;
      } else {
        // Calculate based on actual quantity
        if (actualWeight && order.product.category === "scrap") {
          order.pricing.finalAmount = actualWeight * order.pricing.pricePerUnit;
        } else if (actualVolume && order.product.category === "cooking_oil") {
          order.pricing.finalAmount = actualVolume * order.pricing.pricePerUnit;
        }
      }

      await order.updateStatus("completed", currentUser._id, "Order completed");

      // Mark product as sold
      if (order.product) {
        await productService.markAsSold(
          order.product._id,
          order.pricing.finalAmount,
          order.buyer
        );
      }

      // Award points to participants
      await this.awardCompletionPoints(order);

      logger.info(`Order completed: ${orderId} by ${currentUser._id}`);

      return order;
    } catch (error) {
      logger.error("Error completing order:", error);
      throw error;
    }
  }

  // Add message to order
  async addOrderMessage(orderId, message, currentUser) {
    try {
      const order = await Order.findById(orderId);

      if (!order) {
        throw new AppError("errors.order_not_found", 404);
      }

      // Check if user can message in this order
      const canMessage = this.canUserAccessOrder(order, currentUser);
      if (!canMessage) {
        throw new AppError("errors.insufficient_permissions", 403);
      }

      await order.addMessage(currentUser._id, message);

      // Send notification to other participants
      await this.sendMessageNotification(order, currentUser, message);

      logger.info(`Message added to order: ${orderId} by ${currentUser._id}`);

      return { message: "Message sent successfully" };
    } catch (error) {
      logger.error("Error adding order message:", error);
      throw error;
    }
  }

  // Get order statistics
  async getOrderStatistics(filters = {}) {
    try {
      const { userId, role, dateFrom, dateTo, orderType } = filters;

      let matchQuery = {};

      // Filter by user role
      if (userId) {
        if (role === "collector") {
          matchQuery.assignedCollector = userId;
        } else {
          matchQuery.$or = [{ seller: userId }, { buyer: userId }];
        }
      }

      if (orderType) {
        matchQuery.orderType = orderType;
      }

      if (dateFrom || dateTo) {
        matchQuery.createdAt = {};
        if (dateFrom) matchQuery.createdAt.$gte = new Date(dateFrom);
        if (dateTo) matchQuery.createdAt.$lte = new Date(dateTo);
      }

      const stats = await Order.aggregate([
        { $match: matchQuery },
        {
          $group: {
            _id: null,
            totalOrders: { $sum: 1 },
            completedOrders: {
              $sum: { $cond: [{ $eq: ["$status", "completed"] }, 1, 0] },
            },
            cancelledOrders: {
              $sum: { $cond: [{ $eq: ["$status", "cancelled"] }, 1, 0] },
            },
            totalValue: { $sum: "$pricing.finalAmount" },
            averageValue: { $avg: "$pricing.finalAmount" },
            averageDuration: {
              $avg: {
                $subtract: ["$completedAt", "$createdAt"],
              },
            },
          },
        },
      ]);

      // Status breakdown
      const statusStats = await Order.aggregate([
        { $match: matchQuery },
        {
          $group: {
            _id: "$status",
            count: { $sum: 1 },
            totalValue: { $sum: "$pricing.finalAmount" },
          },
        },
      ]);

      return {
        summary: stats[0] || {
          totalOrders: 0,
          completedOrders: 0,
          cancelledOrders: 0,
          totalValue: 0,
          averageValue: 0,
          averageDuration: 0,
        },
        byStatus: statusStats,
      };
    } catch (error) {
      logger.error("Error getting order statistics:", error);
      throw error;
    }
  }

  // Helper method: Find and notify collectors
  async findAndNotifyCollectors(order) {
    try {
      const pickupCoords = [
        order.pickupLocation.coordinates.longitude,
        order.pickupLocation.coordinates.latitude,
      ];

      // Find available collectors within service area
      const availableCollectors = await User.findNearby(
        { longitude: pickupCoords[0], latitude: pickupCoords[1] },
        15, // 15km radius
        "collector"
      );

      // Filter by availability and operating hours
      const suitableCollectors = availableCollectors.filter((collector) => {
        return (
          collector.collectorData?.isAvailable &&
          this.isCollectorOperating(collector)
        );
      });

      if (suitableCollectors.length === 0) {
        logger.warn(`No suitable collectors found for order: ${order._id}`);
        return;
      }

      // Sort by rating and distance
      suitableCollectors.sort((a, b) => {
        // Primary: rating (higher is better)
        if (b.rating.average !== a.rating.average) {
          return b.rating.average - a.rating.average;
        }
        // Secondary: distance (closer is better)
        return a.distance - b.distance;
      });

      // Assign to best collector or mark as available for multiple
      const bestCollector = suitableCollectors[0];

      if (order.isUrgent) {
        // Auto-assign urgent orders to best collector
        await order.assignCollector(bestCollector._id);
      }

      // Send notifications to top 3 collectors
      const notifyCollectors = suitableCollectors.slice(0, 3);
      await this.sendOrderNotifications(order, notifyCollectors);

      logger.info(
        `Order notifications sent to ${notifyCollectors.length} collectors for order: ${order._id}`
      );
    } catch (error) {
      logger.error("Error finding and notifying collectors:", error);
    }
  }

  // Helper method: Check if collector is operating
  isCollectorOperating(collector) {
    const now = new Date();
    const currentDay = now.toLocaleDateString("en-US", {
      weekday: "lowercase",
    });
    const currentTime = now.toTimeString().substring(0, 5);

    const operatingHours = collector.collectorData?.operatingHours;
    if (!operatingHours || !operatingHours[currentDay]) {
      return true; // Assume available if no schedule set
    }

    const daySchedule = operatingHours[currentDay];
    return (
      daySchedule.isActive &&
      currentTime >= daySchedule.start &&
      currentTime <= daySchedule.end
    );
  }

  // Helper method: Check if user can access order
  canUserAccessOrder(order, user) {
    if (user.role === "admin") return true;

    const userId = user._id.toString();
    return (
      order.seller.toString() === userId ||
      order.buyer.toString() === userId ||
      (order.assignedCollector && order.assignedCollector.toString() === userId)
    );
  }

  // Helper method: Check if user can update order status
  canUserUpdateOrderStatus(order, user, newStatus) {
    if (user.role === "admin") return true;

    const userId = user._id.toString();

    // Seller can update certain statuses
    if (order.seller.toString() === userId) {
      return ["cancelled"].includes(newStatus);
    }

    // Buyer can update certain statuses
    if (order.buyer.toString() === userId) {
      return ["cancelled"].includes(newStatus);
    }

    // Collector can update most statuses
    if (
      order.assignedCollector &&
      order.assignedCollector.toString() === userId
    ) {
      return [
        "accepted",
        "pickup_scheduled",
        "in_transit",
        "arrived",
        "verifying",
        "completed",
      ].includes(newStatus);
    }

    return false;
  }

  // Helper method: Check if user can cancel order
  canUserCancelOrder(order, user) {
    if (user.role === "admin") return true;

    const userId = user._id.toString();
    return (
      order.seller.toString() === userId ||
      order.buyer.toString() === userId ||
      (order.assignedCollector && order.assignedCollector.toString() === userId)
    );
  }

  // Helper method: Get valid status transitions
  getValidStatusTransitions(currentStatus) {
    const transitions = {
      pending: ["assigned", "accepted", "cancelled"],
      assigned: ["accepted", "cancelled"],
      accepted: ["pickup_scheduled", "in_transit", "cancelled"],
      pickup_scheduled: ["in_transit", "cancelled"],
      in_transit: ["arrived", "cancelled"],
      arrived: ["verifying", "cancelled"],
      verifying: ["completed", "cancelled"],
      completed: [], // Terminal state
      cancelled: [], // Terminal state
      disputed: ["completed", "cancelled"],
    };

    return transitions[currentStatus] || [];
  }

  // Helper method: Handle status-specific updates
  async handleStatusUpdate(order, newStatus, currentUser) {
    try {
      switch (newStatus) {
        case "completed":
          await this.awardCompletionPoints(order);
          break;
        case "cancelled":
          // Release product reservation
          if (order.product) {
            const product = await Product.findById(order.product);
            if (product && product.status === "reserved") {
              product.status = "active";
              product.isAvailable = true;
              await product.save();
            }
          }
          break;
      }

      // Send notifications
      await this.sendOrderNotification(order, `order_${newStatus}`);
    } catch (error) {
      logger.error("Error handling status update:", error);
    }
  }

  // Helper method: Award points upon completion
  async awardCompletionPoints(order) {
    try {
      const basePoints = 10;
      const bonusPoints = {
        seller: order.orderType === "scrap_pickup" ? 5 : 0,
        buyer: 0,
        collector: 15,
      };

      // Award points to seller
      if (order.seller) {
        const sellerPoints = basePoints + bonusPoints.seller;
        const seller = await User.findById(order.seller);
        if (seller) {
          await seller.addPoints(sellerPoints, "Order completion");
          order.pointsAwarded.seller = sellerPoints;
        }
      }

      // Award points to collector
      if (order.assignedCollector) {
        const collectorPoints = basePoints + bonusPoints.collector;
        const collector = await User.findById(order.assignedCollector);
        if (collector) {
          await collector.addPoints(collectorPoints, "Order completion");
          order.pointsAwarded.collector = collectorPoints;
        }
      }

      await order.save();
      logger.info(`Points awarded for completed order: ${order._id}`);
    } catch (error) {
      logger.error("Error awarding completion points:", error);
    }
  }

  // Helper method: Send order notification (placeholder)
  async sendOrderNotification(order, event) {
    try {
      // This will be implemented with notification service
      logger.info(`Order notification sent: ${event} for order ${order._id}`);
    } catch (error) {
      logger.error("Error sending order notification:", error);
    }
  }

  // Helper method: Send order notifications to multiple collectors
  async sendOrderNotifications(order, collectors) {
    try {
      // This will be implemented with notification service
      logger.info(
        `Order notifications sent to ${collectors.length} collectors for order ${order._id}`
      );
    } catch (error) {
      logger.error("Error sending order notifications:", error);
    }
  }

  // Helper method: Send message notification
  async sendMessageNotification(order, sender, message) {
    try {
      // This will be implemented with notification service
      logger.info(`Message notification sent for order ${order._id}`);
    } catch (error) {
      logger.error("Error sending message notification:", error);
    }
  }
}

// Create singleton instance
const orderService = new OrderService();

export default orderService;

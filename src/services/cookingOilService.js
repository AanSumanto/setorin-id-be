import { Order, Product, User } from '../models/index.js';
import { createLogger } from '../utils/logger.js';
import { AppError } from '../middlewares/errorMiddleware.js';
import productService from './productService.js';

const logger = createLogger('CookingOilService');

class CookingOilService {
  constructor() {
    // Business logic constants from env or defaults
    this.PRICE_PER_LITER = parseFloat(process.env.COOKING_OIL_PRICE_PER_LITER) || 4000;
    this.WARGA_CASH = 2500;        // Cash to warga
    this.KAS_RT = 1000;            // Kas RT (paid by platform)
    this.INCENTIVE_RT = 500;       // Incentive RT (paid by platform)
    this.RT_TO_RW_PRICE = 4000;    // RT sells to RW
    this.RW_TO_PLATFORM_PRICE = 4500; // RW sells to platform
    this.PLATFORM_SELLING_PRICE = 8000; // Platform sells to buyer
  }

  // Create cooking oil transaction: Warga → RT
  async createWargaToRtTransaction(transactionData, currentUser) {
    try {
      const { productId, volume, rtId, deliveryMethod = 'pickup' } = transactionData;

      // Validate user role
      if (currentUser.role !== 'individual') {
        throw new AppError('business.only_individuals_can_sell_to_rt', 403);
      }

      // Validate product
      const product = await Product.findById(productId).populate('owner');
      
      if (!product) {
        throw new AppError('errors.product_not_found', 404);
      }

      if (product.category !== 'cooking_oil') {
        throw new AppError('business.invalid_product_category', 400, { expected: 'cooking_oil' });
      }

      if (product.owner._id.toString() !== currentUser._id.toString()) {
        throw new AppError('errors.insufficient_permissions', 403);
      }

      // Validate RT
      const rt = await User.findById(rtId);
      if (!rt || rt.role !== 'rt') {
        throw new AppError('business.invalid_rt', 400);
      }

      // Validate minimum volume
      const minVolume = parseFloat(process.env.MIN_COOKING_OIL_VOLUME) || 1;
      if (volume < minVolume) {
        throw new AppError('business.minimum_volume_not_met', 400, { 
          required: minVolume, 
          provided: volume 
        });
      }

      // Calculate payment breakdown for Warga → RT
      const paymentBreakdown = {
        cashAmount: this.WARGA_CASH * volume,     // RT pays cash to warga
        kasRtAmount: this.KAS_RT * volume,        // Platform credits kas RT
        incentiveAmount: this.INCENTIVE_RT * volume, // Platform pays incentive to RT
        totalAmount: this.PRICE_PER_LITER * volume
      };

      // Set locations
      const pickupLocation = {
        address: product.location.address,
        coordinates: {
          latitude: product.location.coordinates.latitude,
          longitude: product.location.coordinates.longitude
        }
      };

      // Create order
      const order = new Order({
        orderNumber: this.generateOrderNumber('WR'), // Warga → RT
        orderType: 'cooking_oil_warga_to_rt',
        seller: currentUser._id,
        buyer: rtId,
        product: productId,
        quantity: { volume },
        pricing: {
          pricePerUnit: this.PRICE_PER_LITER,
          totalAmount: this.PRICE_PER_LITER * volume
        },
        paymentBreakdown,
        pickupLocation,
        status: 'pending',
        specialInstructions: transactionData.notes
      });

      await order.save();

      // Reserve product
      await productService.markAsReserved(productId, rtId);

      // Update RT balance (kas + incentive will be handled by platform)
      await this.updateRtBalance(rtId, volume);

      // Populate order details
      await order.populate([
        { path: 'seller', select: 'name avatar rating' },
        { path: 'buyer', select: 'name avatar rating rtRwData' },
        { path: 'product', select: 'title images cookingOilData' }
      ]);

      logger.info(`Warga → RT transaction created: ${order._id}`);

      return order;
    } catch (error) {
      logger.error('Error creating Warga → RT transaction:', error);
      throw error;
    }
  }

  // Create cooking oil transaction: RT → RW
  async createRtToRwTransaction(transactionData, currentUser) {
    try {
      const { volume, rwId, sourceOrders } = transactionData;

      // Validate user role
      if (currentUser.role !== 'rt') {
        throw new AppError('business.only_rt_can_sell_to_rw', 403);
      }

      // Validate RW
      const rw = await User.findById(rwId);
      if (!rw || rw.role !== 'rw') {
        throw new AppError('business.invalid_rw', 400);
      }

      // Validate RT has enough collected oil
      const rtBalance = await this.getRtCookingOilBalance(currentUser._id);
      if (rtBalance.availableVolume < volume) {
        throw new AppError('business.insufficient_cooking_oil_balance', 400, {
          available: rtBalance.availableVolume,
          requested: volume
        });
      }

      // Calculate payment - RT → RW: RT gets cash, margin = Rp 1.500/liter
      const paymentBreakdown = {
        cashAmount: this.RT_TO_RW_PRICE * volume, // RW pays cash to RT
        totalAmount: this.RT_TO_RW_PRICE * volume
      };

      // Use RT's location for pickup
      const rtAddress = currentUser.defaultAddress;
      const pickupLocation = {
        address: {
          street: rtAddress.street,
          village: rtAddress.village,
          district: rtAddress.district,
          city: rtAddress.city,
          province: rtAddress.province,
          postalCode: rtAddress.postalCode
        },
        coordinates: {
          latitude: rtAddress.coordinates.coordinates[1],
          longitude: rtAddress.coordinates.coordinates[0]
        }
      };

      // Create order
      const order = new Order({
        orderNumber: this.generateOrderNumber('RR'), // RT → RW
        orderType: 'cooking_oil_rt_to_rw',
        seller: currentUser._id,
        buyer: rwId,
        quantity: { volume },
        pricing: {
          pricePerUnit: this.RT_TO_RW_PRICE,
          totalAmount: this.RT_TO_RW_PRICE * volume
        },
        paymentBreakdown,
        pickupLocation,
        status: 'pending',
        sourceOrders: sourceOrders || [] // Reference to Warga → RT orders
      });

      await order.save();

      // Update RT balance (deduct volume)
      await this.deductRtCookingOilBalance(currentUser._id, volume);

      // Populate order details
      await order.populate([
        { path: 'seller', select: 'name avatar rating rtRwData' },
        { path: 'buyer', select: 'name avatar rating rtRwData' }
      ]);

      logger.info(`RT → RW transaction created: ${order._id}`);

      return order;
    } catch (error) {
      logger.error('Error creating RT → RW transaction:', error);
      throw error;
    }
  }

  // Create cooking oil transaction: RW → Platform
  async createRwToPlatformTransaction(transactionData, currentUser) {
    try {
      const { volume, deliveryLocation } = transactionData;

      // Validate user role
      if (currentUser.role !== 'rw') {
        throw new AppError('business.only_rw_can_sell_to_platform', 403);
      }

      // Validate RW has enough collected oil
      const rwBalance = await this.getRwCookingOilBalance(currentUser._id);
      if (rwBalance.availableVolume < volume) {
        throw new AppError('business.insufficient_cooking_oil_balance', 400, {
          available: rwBalance.availableVolume,
          requested: volume
        });
      }

      // Calculate payment - RW → Platform: RW gets Rp 4.500/liter, margin = Rp 500/liter
      const paymentBreakdown = {
        cashAmount: this.RW_TO_PLATFORM_PRICE * volume, // Platform pays to RW
        totalAmount: this.RW_TO_PLATFORM_PRICE * volume
      };

      // Use RW's location for pickup
      const rwAddress = currentUser.defaultAddress;
      const pickupLocation = {
        address: {
          street: rwAddress.street,
          village: rwAddress.village,
          district: rwAddress.district,
          city: rwAddress.city,
          province: rwAddress.province,
          postalCode: rwAddress.postalCode
        },
        coordinates: {
          latitude: rwAddress.coordinates.coordinates[1],
          longitude: rwAddress.coordinates.coordinates[0]
        }
      };

      // Create order
      const order = new Order({
        orderNumber: this.generateOrderNumber('RP'), // RW → Platform
        orderType: 'cooking_oil_rw_to_platform',
        seller: currentUser._id,
        buyer: null, // Platform buyer will be assigned later
        quantity: { volume },
        pricing: {
          pricePerUnit: this.RW_TO_PLATFORM_PRICE,
          totalAmount: this.RW_TO_PLATFORM_PRICE * volume
        },
        paymentBreakdown,
        pickupLocation,
        deliveryLocation,
        status: 'pending'
      });

      await order.save();

      // Update RW balance (deduct volume)
      await this.deductRwCookingOilBalance(currentUser._id, volume);

      logger.info(`RW → Platform transaction created: ${order._id}`);

      return order;
    } catch (error) {
      logger.error('Error creating RW → Platform transaction:', error);
      throw error;
    }
  }

  // Get cooking oil balance for RT
  async getRtCookingOilBalance(rtId) {
    try {
      // Get all completed Warga → RT orders
      const receivedOrders = await Order.find({
        buyer: rtId,
        orderType: 'cooking_oil_warga_to_rt',
        status: 'completed'
      });

      // Get all completed RT → RW orders
      const soldOrders = await Order.find({
        seller: rtId,
        orderType: 'cooking_oil_rt_to_rw',
        status: 'completed'
      });

      const totalReceived = receivedOrders.reduce((sum, order) => sum + (order.quantity.volume || 0), 0);
      const totalSold = soldOrders.reduce((sum, order) => sum + (order.quantity.volume || 0), 0);
      const availableVolume = totalReceived - totalSold;

      return {
        totalReceived,
        totalSold,
        availableVolume,
        pendingReceived: await this.getPendingVolume(rtId, 'cooking_oil_warga_to_rt', 'buyer'),
        pendingSold: await this.getPendingVolume(rtId, 'cooking_oil_rt_to_rw', 'seller')
      };
    } catch (error) {
      logger.error('Error getting RT cooking oil balance:', error);
      throw error;
    }
  }

  // Get cooking oil balance for RW
  async getRwCookingOilBalance(rwId) {
    try {
      // Get all completed RT → RW orders
      const receivedOrders = await Order.find({
        buyer: rwId,
        orderType: 'cooking_oil_rt_to_rw',
        status: 'completed'
      });

      // Get all completed RW → Platform orders
      const soldOrders = await Order.find({
        seller: rwId,
        orderType: 'cooking_oil_rw_to_platform',
        status: 'completed'
      });

      const totalReceived = receivedOrders.reduce((sum, order) => sum + (order.quantity.volume || 0), 0);
      const totalSold = soldOrders.reduce((sum, order) => sum + (order.quantity.volume || 0), 0);
      const availableVolume = totalReceived - totalSold;

      return {
        totalReceived,
        totalSold,
        availableVolume,
        pendingReceived: await this.getPendingVolume(rwId, 'cooking_oil_rt_to_rw', 'buyer'),
        pendingSold: await this.getPendingVolume(rwId, 'cooking_oil_rw_to_platform', 'seller')
      };
    } catch (error) {
      logger.error('Error getting RW cooking oil balance:', error);
      throw error;
    }
  }

  // Get pending volume for user
  async getPendingVolume(userId, orderType, userRole) {
    try {
      const query = {
        orderType,
        status: { $in: ['pending', 'accepted', 'pickup_scheduled', 'in_transit', 'arrived', 'verifying'] }
      };
      query[userRole] = userId;

      const pendingOrders = await Order.find(query);
      return pendingOrders.reduce((sum, order) => sum + (order.quantity.volume || 0), 0);
    } catch (error) {
      logger.error('Error getting pending volume:', error);
      return 0;
    }
  }

  // Update RT balance (add kas and incentive)
  async updateRtBalance(rtId, volume) {
    try {
      const rt = await User.findById(rtId);
      if (!rt || rt.role !== 'rt') return;

      const kasAmount = this.KAS_RT * volume;
      const incentiveAmount = this.INCENTIVE_RT * volume;

      // Update RT data
      if (!rt.rtRwData) {
        rt.rtRwData = { cashBalance: 0, incentiveBalance: 0 };
      }

      rt.rtRwData.cashBalance = (rt.rtRwData.cashBalance || 0) + kasAmount;
      rt.rtRwData.incentiveBalance = (rt.rtRwData.incentiveBalance || 0) + incentiveAmount;

      await rt.save();

      logger.info(`RT balance updated: ${rtId}, kas: +${kasAmount}, incentive: +${incentiveAmount}`);
    } catch (error) {
      logger.error('Error updating RT balance:', error);
    }
  }

  // Deduct cooking oil volume from RT balance
  async deductRtCookingOilBalance(rtId, volume) {
    try {
      // This is tracked through orders, no direct balance to update
      logger.info(`RT cooking oil balance deducted: ${rtId}, volume: -${volume}`);
    } catch (error) {
      logger.error('Error deducting RT cooking oil balance:', error);
    }
  }

  // Deduct cooking oil volume from RW balance
  async deductRwCookingOilBalance(rwId, volume) {
    try {
      // This is tracked through orders, no direct balance to update
      logger.info(`RW cooking oil balance deducted: ${rwId}, volume: -${volume}`);
    } catch (error) {
      logger.error('Error deducting RW cooking oil balance:', error);
    }
  }

  // Generate order number with prefix
  generateOrderNumber(prefix) {
    const timestamp = Date.now().toString().slice(-8);
    const random = Math.random().toString(36).substr(2, 4).toUpperCase();
    return `${prefix}-${timestamp}-${random}`;
  }

  // Calculate distance between coordinates
  calculateDistance(coord1, coord2) {
    const R = 6371; // Earth's radius in km
    const dLat = (coord2[1] - coord1[1]) * Math.PI / 180;
    const dLon = (coord2[0] - coord1[0]) * Math.PI / 180;
    const a = 
      Math.sin(dLat/2) * Math.sin(dLat/2) +
      Math.cos(coord1[1] * Math.PI / 180) * Math.cos(coord2[1] * Math.PI / 180) * 
      Math.sin(dLon/2) * Math.sin(dLon/2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
    return R * c;
  }

  // Get cooking oil transaction history
  async getCookingOilTransactionHistory(userId, role, filters = {}, pagination = {}) {
    try {
      const { dateFrom, dateTo, orderType } = filters;
      const { page = 1, limit = 20 } = pagination;

      let query = {
        orderType: { $in: ['cooking_oil_warga_to_rt', 'cooking_oil_rt_to_rw', 'cooking_oil_rw_to_platform'] }
      };

      // Filter by user role
      if (role === 'individual') {
        query.seller = userId;
        query.orderType = 'cooking_oil_warga_to_rt';
      } else if (role === 'rt') {
        query.$or = [
          { buyer: userId, orderType: 'cooking_oil_warga_to_rt' },
          { seller: userId, orderType: 'cooking_oil_rt_to_rw' }
        ];
      } else if (role === 'rw') {
        query.$or = [
          { buyer: userId, orderType: 'cooking_oil_rt_to_rw' },
          { seller: userId, orderType: 'cooking_oil_rw_to_platform' }
        ];
      }

      // Apply filters
      if (orderType) {
        query.orderType = orderType;
      }

      if (dateFrom || dateTo) {
        query.createdAt = {};
        if (dateFrom) query.createdAt.$gte = new Date(dateFrom);
        if (dateTo) query.createdAt.$lte = new Date(dateTo);
      }

      const totalItems = await Order.countDocuments(query);
      const totalPages = Math.ceil(totalItems / limit);
      const skip = (page - 1) * limit;

      const transactions = await Order.find(query)
        .populate([
          { path: 'seller', select: 'name avatar rating role rtRwData' },
          { path: 'buyer', select: 'name avatar rating role rtRwData' },
          { path: 'product', select: 'title images cookingOilData' }
        ])
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .exec();

      return {
        transactions,
        pagination: {
          page,
          totalPages,
          totalItems,
          limit,
          hasNext: page < totalPages,
          hasPrev: page > 1
        }
      };
    } catch (error) {
      logger.error('Error getting cooking oil transaction history:', error);
      throw error;
    }
  }

  // Get cooking oil statistics
  async getCookingOilStatistics(filters = {}) {
    try {
      const { userId, role, dateFrom, dateTo } = filters;

      let matchQuery = {
        orderType: { $in: ['cooking_oil_warga_to_rt', 'cooking_oil_rt_to_rw', 'cooking_oil_rw_to_platform'] }
      };

      if (userId && role) {
        if (role === 'rt') {
          matchQuery.$or = [
            { buyer: userId, orderType: 'cooking_oil_warga_to_rt' },
            { seller: userId, orderType: 'cooking_oil_rt_to_rw' }
          ];
        } else if (role === 'rw') {
          matchQuery.$or = [
            { buyer: userId, orderType: 'cooking_oil_rt_to_rw' },
            { seller: userId, orderType: 'cooking_oil_rw_to_platform' }
          ];
        }
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
            _id: '$orderType',
            totalTransactions: { $sum: 1 },
            totalVolume: { $sum: '$quantity.volume' },
            totalValue: { $sum: '$pricing.totalAmount' },
            averageVolume: { $avg: '$quantity.volume' }
          }
        }
      ]);

      // Calculate platform margins
      const platformStats = await this.calculatePlatformMargins(matchQuery);

      return {
        byOrderType: stats,
        platformMargins: platformStats
      };
    } catch (error) {
      logger.error('Error getting cooking oil statistics:', error);
      throw error;
    }
  }

  // Calculate platform margins
  async calculatePlatformMargins(matchQuery) {
    try {
      const completedOrders = await Order.find({
        ...matchQuery,
        status: 'completed'
      });

      let totalCost = 0;
      let totalRevenue = 0;
      let totalVolume = 0;

      completedOrders.forEach(order => {
        const volume = order.quantity.volume || 0;
        totalVolume += volume;

        if (order.orderType === 'cooking_oil_warga_to_rt') {
          // Platform pays kas RT (Rp 1.000) + incentive RT (Rp 500)
          totalCost += (this.KAS_RT + this.INCENTIVE_RT) * volume;
        } else if (order.orderType === 'cooking_oil_rw_to_platform') {
          // Platform pays RW (Rp 4.500)
          totalCost += this.RW_TO_PLATFORM_PRICE * volume;
          // Platform sells to buyer (Rp 8.000)
          totalRevenue += this.PLATFORM_SELLING_PRICE * volume;
        }
      });

      const totalMargin = totalRevenue - totalCost;
      const marginPerLiter = totalVolume > 0 ? totalMargin / totalVolume : 0;

      return {
        totalCost,
        totalRevenue,
        totalMargin,
        marginPerLiter,
        totalVolume
      };
    } catch (error) {
      logger.error('Error calculating platform margins:', error);
      return {
        totalCost: 0,
        totalRevenue: 0,
        totalMargin: 0,
        marginPerLiter: 0,
        totalVolume: 0
      };
    }
  }

  // Get available RT/RW for cooking oil transactions
  async getAvailableRtRw(coordinates, role, radius = 5) {
    try {
      const [lng, lat] = coordinates;

      const availableUsers = await User.find({
        role: role,
        isActive: true,
        'addresses.coordinates': {
          $near: {
            $geometry: {
              type: 'Point',
              coordinates: [lng, lat]
            },
            $maxDistance: radius * 1000
          }
        }
      })
        .select('name avatar rating addresses rtRwData')
        .limit(20)
        .exec();

      // Add distance calculation
      return availableUsers.map(user => {
        const userCoords = user.defaultAddress?.coordinates?.coordinates;
        if (userCoords) {
          const distance = this.calculateDistance([lng, lat], userCoords);
          user.distance = Math.round(distance * 100) / 100;
        }
        return user;
      });
    } catch (error) {
      logger.error(`Error getting available ${role}:`, error);
      throw error;
    }
  }

  // Complete cooking oil transaction
  async completeCookingOilTransaction(orderId, completionData, currentUser) {
    try {
      const { actualVolume, qualityGrade, verificationPhotos, notes } = completionData;

      const order = await Order.findById(orderId);

      if (!order) {
        throw new AppError('errors.order_not_found', 404);
      }

      if (!order.orderType.includes('cooking_oil')) {
        throw new AppError('business.invalid_order_type', 400);
      }

      if (order.status !== 'verifying' && order.status !== 'arrived') {
        throw new AppError('business.order_cannot_be_completed', 400, { status: order.status });
      }

      // Update verification data
      order.verification = {
        actualVolume,
        qualityGrade,
        photos: verificationPhotos || [],
        notes,
        verifiedBy: currentUser._id,
        verifiedAt: new Date()
      };

      // Recalculate final amount based on actual volume
      if (actualVolume && actualVolume !== order.quantity.volume) {
        order.pricing.finalAmount = actualVolume * order.pricing.pricePerUnit;
        order.quantity.volume = actualVolume; // Update actual volume

        // Recalculate payment breakdown
        if (order.orderType === 'cooking_oil_warga_to_rt') {
          order.paymentBreakdown = {
            cashAmount: this.WARGA_CASH * actualVolume,
            kasRtAmount: this.KAS_RT * actualVolume,
            incentiveAmount: this.INCENTIVE_RT * actualVolume,
            totalAmount: this.PRICE_PER_LITER * actualVolume
          };
        }
      }

      await order.updateStatus('completed', currentUser._id, 'Cooking oil transaction completed');

      // Update balances based on order type
      await this.processCompletedCookingOilOrder(order);

      // Award points
      await this.awardCookingOilPoints(order);

      logger.info(`Cooking oil transaction completed: ${orderId}`);

      return order;
    } catch (error) {
      logger.error('Error completing cooking oil transaction:', error);
      throw error;
    }
  }

  // Process completed cooking oil order
  async processCompletedCookingOilOrder(order) {
    try {
      const volume = order.quantity.volume;

      switch (order.orderType) {
        case 'cooking_oil_warga_to_rt':
          // Update RT balance with kas and incentive
          await this.updateRtBalance(order.buyer, volume);
          // Mark product as sold if applicable
          if (order.product) {
            await productService.markAsSold(order.product, order.pricing.finalAmount, order.buyer);
          }
          break;

        case 'cooking_oil_rt_to_rw':
          // No additional balance updates needed (tracked through orders)
          break;

        case 'cooking_oil_rw_to_platform':
          // Platform processing - no additional updates needed
          break;
      }

      logger.info(`Processed completed cooking oil order: ${order._id}`);
    } catch (error) {
      logger.error('Error processing completed cooking oil order:', error);
    }
  }

  // Award points for cooking oil transactions
  async awardCookingOilPoints(order) {
    try {
      const basePoints = 5;
      let sellerPoints = basePoints;
      let buyerPoints = 0;

      // Different points based on order type
      switch (order.orderType) {
        case 'cooking_oil_warga_to_rt':
          sellerPoints = 10; // Warga gets more points for participating
          buyerPoints = 5;   // RT gets points for collecting
          break;
        case 'cooking_oil_rt_to_rw':
          sellerPoints = 8;  // RT gets points for selling
          buyerPoints = 3;   // RW gets fewer points
          break;
        case 'cooking_oil_rw_to_platform':
          sellerPoints = 15; // RW gets most points for completing chain
          break;
      }

      // Award points to seller
      if (order.seller && sellerPoints > 0) {
        const seller = await User.findById(order.seller);
        if (seller) {
          await seller.addPoints(sellerPoints, `Cooking oil ${order.orderType}`);
          order.pointsAwarded.seller = sellerPoints;
        }
      }

      // Award points to buyer
      if (order.buyer && buyerPoints > 0) {
        const buyer = await User.findById(order.buyer);
        if (buyer) {
          await buyer.addPoints(buyerPoints, `Cooking oil ${order.orderType}`);
          order.pointsAwarded.buyer = buyerPoints;
        }
      }

      await order.save();
      logger.info(`Points awarded for cooking oil transaction: ${order._id}`);
    } catch (error) {
      logger.error('Error awarding cooking oil points:', error);
    }
  }

  // Get cooking oil flow summary
  async getCookingOilFlowSummary(filters = {}) {
    try {
      const { dateFrom, dateTo } = filters;

      let matchQuery = {
        orderType: { $in: ['cooking_oil_warga_to_rt', 'cooking_oil_rt_to_rw', 'cooking_oil_rw_to_platform'] },
        status: 'completed'
      };

      if (dateFrom || dateTo) {
        matchQuery.createdAt = {};
        if (dateFrom) matchQuery.createdAt.$gte = new Date(dateFrom);
        if (dateTo) matchQuery.createdAt.$lte = new Date(dateTo);
      }

      const flowData = await Order.aggregate([
        { $match: matchQuery },
        {
          $group: {
            _id: '$orderType',
            totalVolume: { $sum: '$quantity.volume' },
            totalTransactions: { $sum: 1 },
            averageVolume: { $avg: '$quantity.volume' }
          }
        }
      ]);

      // Calculate flow efficiency
      const wargaToRt = flowData.find(f => f._id === 'cooking_oil_warga_to_rt');
      const rtToRw = flowData.find(f => f._id === 'cooking_oil_rt_to_rw');
      const rwToPlatform = flowData.find(f => f._id === 'cooking_oil_rw_to_platform');

      const efficiency = {
        wargaToRtVolume: wargaToRt?.totalVolume || 0,
        rtToRwVolume: rtToRw?.totalVolume || 0,
        rwToPlatformVolume: rwToPlatform?.totalVolume || 0,
        rtEfficiency: wargaToRt?.totalVolume ? (rtToRw?.totalVolume || 0) / wargaToRt.totalVolume : 0,
        rwEfficiency: rtToRw?.totalVolume ? (rwToPlatform?.totalVolume || 0) / rtToRw.totalVolume : 0,
        overallEfficiency: wargaToRt?.totalVolume ? (rwToPlatform?.totalVolume || 0) / wargaToRt.totalVolume : 0
      };

      return {
        flowData,
        efficiency
      };
    } catch (error) {
      logger.error('Error getting cooking oil flow summary:', error);
      throw error;
    }
  }

  // Get price breakdown for different levels
  getPriceBreakdown() {
    return {
      wargaToRt: {
        totalPrice: this.PRICE_PER_LITER,
        breakdown: {
          wargaCash: this.WARGA_CASH,
          kasRt: this.KAS_RT,
          incentiveRt: this.INCENTIVE_RT
        },
        description: {
          id: 'Warga mendapat Rp 2.500 cash, RT mendapat Rp 1.000 kas + Rp 500 insentif',
          en: 'Warga gets Rp 2,500 cash, RT gets Rp 1,000 cash fund + Rp 500 incentive'
        }
      },
      rtToRw: {
        totalPrice: this.RT_TO_RW_PRICE,
        rtMargin: this.RT_TO_RW_PRICE - this.WARGA_CASH, // Rp 1.500
        description: {
          id: 'RT jual ke RW Rp 4.000, margin RT = Rp 1.500',
          en: 'RT sells to RW for Rp 4,000, RT margin = Rp 1,500'
        }
      },
      rwToPlatform: {
        totalPrice: this.RW_TO_PLATFORM_PRICE,
        rwMargin: this.RW_TO_PLATFORM_PRICE - this.RT_TO_RW_PRICE, // Rp 500
        description: {
          id: 'RW jual ke Platform Rp 4.500, margin RW = Rp 500',
          en: 'RW sells to Platform for Rp 4,500, RW margin = Rp 500'
        }
      },
      platformToBuyer: {
        totalPrice: this.PLATFORM_SELLING_PRICE,
        platformMargin: this.PLATFORM_SELLING_PRICE - this.RW_TO_PLATFORM_PRICE - (this.KAS_RT + this.INCENTIVE_RT), // Rp 2.000
        description: {
          id: 'Platform jual ke Buyer Rp 8.000, margin Platform = Rp 2.000',
          en: 'Platform sells to Buyer for Rp 8,000, Platform margin = Rp 2,000'
        }
      }
    };
  }

  // Validate cooking oil transaction eligibility
  async validateTransactionEligibility(userId, role, transactionType, additionalData = {}) {
    try {
      const user = await User.findById(userId);
      
      if (!user || user.role !== role) {
        throw new AppError('business.invalid_user_role', 400, { expected: role, actual: user?.role });
      }

      if (!user.isActive) {
        throw new AppError('errors.account_deactivated', 403);
      }

      // Role-specific validations
      switch (transactionType) {
        case 'warga_to_rt':
          if (role !== 'individual') {
            throw new AppError('business.only_individuals_can_sell_to_rt', 403);
          }
          break;

        case 'rt_to_rw':
          if (role !== 'rt') {
            throw new AppError('business.only_rt_can_sell_to_rw', 403);
          }
          
          // Check if RT has sufficient balance
          const rtBalance = await this.getRtCookingOilBalance(userId);
          if (additionalData.volume && rtBalance.availableVolume < additionalData.volume) {
            throw new AppError('business.insufficient_cooking_oil_balance', 400, {
              available: rtBalance.availableVolume,
              requested: additionalData.volume
            });
          }
          break;

        case 'rw_to_platform':
          if (role !== 'rw') {
            throw new AppError('business.only_rw_can_sell_to_platform', 403);
          }
          
          // Check if RW has sufficient balance
          const rwBalance = await this.getRwCookingOilBalance(userId);
          if (additionalData.volume && rwBalance.availableVolume < additionalData.volume) {
            throw new AppError('business.insufficient_cooking_oil_balance', 400, {
              available: rwBalance.availableVolume,
              requested: additionalData.volume
            });
          }
          break;

        default:
          throw new AppError('business.invalid_transaction_type', 400, { type: transactionType });
      }

      return { eligible: true, user };
    } catch (error) {
      logger.error('Error validating transaction eligibility:', error);
      throw error;
    }
  }

  // Get cooking oil inventory summary
  async getCookingOilInventory(filters = {}) {
    try {
      const { role, userId, dateFrom, dateTo } = filters;

      let inventoryData = {};

      if (role === 'rt' || !role) {
        // Get all RT inventories
        const rtUsers = userId ? [userId] : await User.find({ role: 'rt', isActive: true }).select('_id');
        const rtIds = Array.isArray(rtUsers) ? rtUsers.map(u => u._id || u) : [rtUsers];

        inventoryData.rtInventories = await Promise.all(
          rtIds.map(async (rtId) => {
            const balance = await this.getRtCookingOilBalance(rtId);
            const user = await User.findById(rtId).select('name rtRwData addresses');
            return {
              rtId,
              rtName: user?.name,
              rtData: user?.rtRwData,
              location: user?.defaultAddress,
              ...balance
            };
          })
        );
      }

      if (role === 'rw' || !role) {
        // Get all RW inventories
        const rwUsers = userId ? [userId] : await User.find({ role: 'rw', isActive: true }).select('_id');
        const rwIds = Array.isArray(rwUsers) ? rwUsers.map(u => u._id || u) : [rwUsers];

        inventoryData.rwInventories = await Promise.all(
          rwIds.map(async (rwId) => {
            const balance = await this.getRwCookingOilBalance(rwId);
            const user = await User.findById(rwId).select('name rtRwData addresses');
            return {
              rwId,
              rwName: user?.name,
              rwData: user?.rtRwData,
              location: user?.defaultAddress,
              ...balance
            };
          })
        );
      }

      return inventoryData;
    } catch (error) {
      logger.error('Error getting cooking oil inventory:', error);
      throw error;
    }
  }

  // Generate cooking oil report
  async generateCookingOilReport(reportType, filters = {}) {
    try {
      const { dateFrom, dateTo, userId, role } = filters;

      let report = {};

      switch (reportType) {
        case 'flow_summary':
          report = await this.getCookingOilFlowSummary(filters);
          break;

        case 'financial_summary':
          report = await this.getCookingOilFinancialSummary(filters);
          break;

        case 'performance_summary':
          report = await this.getCookingOilPerformanceSummary(filters);
          break;

        case 'inventory_summary':
          report = await this.getCookingOilInventory(filters);
          break;

        default:
          // Comprehensive report
          report = {
            flow: await this.getCookingOilFlowSummary(filters),
            financial: await this.getCookingOilFinancialSummary(filters),
            performance: await this.getCookingOilPerformanceSummary(filters),
            inventory: await this.getCookingOilInventory(filters)
          };
          break;
      }

      return {
        reportType,
        generatedAt: new Date(),
        filters,
        data: report
      };
    } catch (error) {
      logger.error('Error generating cooking oil report:', error);
      throw error;
    }
  }

  // Get cooking oil financial summary
  async getCookingOilFinancialSummary(filters = {}) {
    try {
      const { dateFrom, dateTo, userId, role } = filters;

      let matchQuery = {
        orderType: { $in: ['cooking_oil_warga_to_rt', 'cooking_oil_rt_to_rw', 'cooking_oil_rw_to_platform'] },
        status: 'completed'
      };

      if (dateFrom || dateTo) {
        matchQuery.createdAt = {};
        if (dateFrom) matchQuery.createdAt.$gte = new Date(dateFrom);
        if (dateTo) matchQuery.createdAt.$lte = new Date(dateTo);
      }

      if (userId && role) {
        if (role === 'rt') {
          matchQuery.$or = [
            { buyer: userId, orderType: 'cooking_oil_warga_to_rt' },
            { seller: userId, orderType: 'cooking_oil_rt_to_rw' }
          ];
        } else if (role === 'rw') {
          matchQuery.$or = [
            { buyer: userId, orderType: 'cooking_oil_rt_to_rw' },
            { seller: userId, orderType: 'cooking_oil_rw_to_platform' }
          ];
        }
      }

      const financialData = await Order.aggregate([
        { $match: matchQuery },
        {
          $group: {
            _id: '$orderType',
            totalRevenue: { $sum: '$paymentBreakdown.totalAmount' },
            totalCashPaid: { $sum: '$paymentBreakdown.cashAmount' },
            totalKasRt: { $sum: '$paymentBreakdown.kasRtAmount' },
            totalIncentive: { $sum: '$paymentBreakdown.incentiveAmount' },
            totalVolume: { $sum: '$quantity.volume' },
            transactionCount: { $sum: 1 }
          }
        }
      ]);

      // Calculate totals and margins
      let totalRevenue = 0;
      let totalCashPaid = 0;
      let totalKasRt = 0;
      let totalIncentive = 0;
      let totalVolume = 0;

      financialData.forEach(item => {
        totalRevenue += item.totalRevenue || 0;
        totalCashPaid += item.totalCashPaid || 0;
        totalKasRt += item.totalKasRt || 0;
        totalIncentive += item.totalIncentive || 0;
        totalVolume += item.totalVolume || 0;
      });

      const platformCost = totalKasRt + totalIncentive;
      const platformRevenue = totalVolume * this.PLATFORM_SELLING_PRICE; // Theoretical revenue
      const platformMargin = platformRevenue - platformCost - (totalVolume * this.RW_TO_PLATFORM_PRICE);

      return {
        byOrderType: financialData,
        summary: {
          totalRevenue,
          totalCashPaid,
          totalKasRt,
          totalIncentive,
          totalVolume,
          platformCost,
          platformRevenue,
          platformMargin,
          averageRevenuePerLiter: totalVolume > 0 ? totalRevenue / totalVolume : 0
        }
      };
    } catch (error) {
      logger.error('Error getting cooking oil financial summary:', error);
      throw error;
    }
  }

  // Get cooking oil performance summary
  async getCookingOilPerformanceSummary(filters = {}) {
    try {
      const { dateFrom, dateTo } = filters;

      let matchQuery = {
        orderType: { $in: ['cooking_oil_warga_to_rt', 'cooking_oil_rt_to_rw', 'cooking_oil_rw_to_platform'] }
      };

      if (dateFrom || dateTo) {
        matchQuery.createdAt = {};
        if (dateFrom) matchQuery.createdAt.$gte = new Date(dateFrom);
        if (dateTo) matchQuery.createdAt.$lte = new Date(dateTo);
      }

      // Performance metrics
      const performanceData = await Order.aggregate([
        { $match: matchQuery },
        {
          $group: {
            _id: {
              orderType: '$orderType',
              status: '$status'
            },
            count: { $sum: 1 },
            avgDuration: {
              $avg: {
                $cond: [
                  { $eq: ['$status', 'completed'] },
                  { $subtract: ['$completedAt', '$createdAt'] },
                  null
                ]
              }
            }
          }
        }
      ]);

      // Calculate success rates
      const successRates = {};
      const orderTypes = ['cooking_oil_warga_to_rt', 'cooking_oil_rt_to_rw', 'cooking_oil_rw_to_platform'];

      orderTypes.forEach(orderType => {
        const typeData = performanceData.filter(item => item._id.orderType === orderType);
        const completed = typeData.find(item => item._id.status === 'completed')?.count || 0;
        const cancelled = typeData.find(item => item._id.status === 'cancelled')?.count || 0;
        const total = typeData.reduce((sum, item) => sum + item.count, 0);

        successRates[orderType] = {
          completed,
          cancelled,
          total,
          successRate: total > 0 ? (completed / total) * 100 : 0,
          cancellationRate: total > 0 ? (cancelled / total) * 100 : 0
        };
      });

      return {
        performanceData,
        successRates,
        overallMetrics: {
          totalTransactions: performanceData.reduce((sum, item) => sum + item.count, 0),
          avgCompletionTime: performanceData
            .filter(item => item.avgDuration)
            .reduce((sum, item) => sum + item.avgDuration, 0) / performanceData.length
        }
      };
    } catch (error) {
      logger.error('Error getting cooking oil performance summary:', error);
      throw error;
    }
  }

  // Cancel cooking oil transaction
  async cancelCookingOilTransaction(orderId, currentUser, reason) {
    try {
      const order = await Order.findById(orderId);

      if (!order) {
        throw new AppError('errors.order_not_found', 404);
      }

      if (!order.orderType.includes('cooking_oil')) {
        throw new AppError('business.invalid_order_type', 400);
      }

      if (!order.canBeCancelled) {
        throw new AppError('business.order_cannot_be_cancelled', 400, { status: order.status });
      }

      // Check permissions
      const userId = currentUser._id.toString();
      const canCancel = order.seller.toString() === userId || 
                       order.buyer.toString() === userId || 
                       currentUser.role === 'admin';

      if (!canCancel) {
        throw new AppError('errors.insufficient_permissions', 403);
      }

      await order.cancelOrder(reason, '', currentUser._id);

      // Restore product if applicable
      if (order.product) {
        const product = await Product.findById(order.product);
        if (product && product.status === 'reserved') {
          product.status = 'active';
          product.isAvailable = true;
          await product.save();
        }
      }

      // Reverse any balance updates if order was already processed
      await this.reverseCookingOilTransaction(order);

      logger.info(`Cooking oil transaction cancelled: ${orderId} by ${currentUser._id}`);

      return order;
    } catch (error) {
      logger.error('Error cancelling cooking oil transaction:', error);
      throw error;
    }
  }

  // Reverse cooking oil transaction (for cancellations)
  async reverseCookingOilTransaction(order) {
    try {
      if (order.status !== 'completed') {
        return; // Nothing to reverse if not completed
      }

      const volume = order.quantity.volume;

      switch (order.orderType) {
        case 'cooking_oil_warga_to_rt':
          // Reverse RT balance update
          const rt = await User.findById(order.buyer);
          if (rt && rt.rtRwData) {
            const kasAmount = this.KAS_RT * volume;
            const incentiveAmount = this.INCENTIVE_RT * volume;
            
            rt.rtRwData.cashBalance = Math.max(0, (rt.rtRwData.cashBalance || 0) - kasAmount);
            rt.rtRwData.incentiveBalance = Math.max(0, (rt.rtRwData.incentiveBalance || 0) - incentiveAmount);
            await rt.save();
          }
          break;

        case 'cooking_oil_rt_to_rw':
        case 'cooking_oil_rw_to_platform':
          // These are tracked through orders, no direct balance to reverse
          break;
      }

      logger.info(`Reversed cooking oil transaction: ${order._id}`);
    } catch (error) {
      logger.error('Error reversing cooking oil transaction:', error);
    }
  }
}

// Create singleton instance
const cookingOilService = new CookingOilService();

export default cookingOilService;

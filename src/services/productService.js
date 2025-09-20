import { Product, User, LocationUtils } from "../models/index.js";
import { createLogger } from "../utils/logger.js";
import { AppError } from "../middlewares/errorMiddleware.js";

const logger = createLogger("ProductService");

class ProductService {
  // Create new product
  async createProduct(productData, currentUser) {
    try {
      // Validate user can create products
      if (!["individual", "rt", "rw"].includes(currentUser.role)) {
        throw new AppError("errors.insufficient_permissions", 403);
      }

      // Validate minimum requirements
      if (productData.category === "scrap" && productData.scrapData) {
        const minWeight = parseFloat(process.env.MIN_SCRAP_WEIGHT) || 5;
        if (productData.scrapData.estimatedWeight < minWeight) {
          throw new AppError("business.minimum_weight_not_met", 400, {
            required: minWeight,
            provided: productData.scrapData.estimatedWeight,
          });
        }
      }

      if (
        productData.category === "cooking_oil" &&
        productData.cookingOilData
      ) {
        const minVolume = parseFloat(process.env.MIN_COOKING_OIL_VOLUME) || 1;
        if (productData.cookingOilData.volume < minVolume) {
          throw new AppError("business.minimum_volume_not_met", 400, {
            required: minVolume,
            provided: productData.cookingOilData.volume,
          });
        }
      }

      // Set owner and default location
      productData.owner = currentUser._id;

      // Use user's default address if no location provided
      if (!productData.location && currentUser.defaultAddress) {
        const defaultAddr = currentUser.defaultAddress;
        productData.location = {
          address: {
            street: defaultAddr.street,
            village: defaultAddr.village,
            district: defaultAddr.district,
            city: defaultAddr.city,
            province: defaultAddr.province,
            postalCode: defaultAddr.postalCode,
          },
          coordinates: {
            latitude: defaultAddr.coordinates.coordinates[1],
            longitude: defaultAddr.coordinates.coordinates[0],
          },
        };
      }

      // Validate coordinates if provided
      if (productData.location?.coordinates) {
        const { longitude, latitude } = productData.location.coordinates;
        if (!LocationUtils.isValidIndonesianCoordinates(longitude, latitude)) {
          throw new AppError("errors.invalid_coordinates", 400);
        }
      }

      // Create product
      const product = new Product(productData);
      await product.save();

      // Populate owner info
      await product.populate("owner", "name avatar rating");

      logger.info(`Product created: ${product._id} by user ${currentUser._id}`);

      return product;
    } catch (error) {
      logger.error("Error creating product:", error);
      throw error;
    }
  }

  // Get product by ID
  async getProductById(productId, currentUser = null) {
    try {
      const product = await Product.findById(productId)
        .populate("owner", "name avatar rating addresses role")
        .exec();

      if (!product) {
        throw new AppError("errors.product_not_found", 404);
      }

      // Check if product is accessible to current user
      if (!product.isAvailable && product.status !== "active") {
        if (
          !currentUser ||
          (currentUser._id.toString() !== product.owner._id.toString() &&
            currentUser.role !== "admin")
        ) {
          throw new AppError("errors.product_not_available", 403);
        }
      }

      // Increment views (only if not owner viewing their own product)
      if (
        currentUser &&
        currentUser._id.toString() !== product.owner._id.toString()
      ) {
        await product.incrementViews();
      }

      return product;
    } catch (error) {
      logger.error("Error getting product by ID:", error);
      throw error;
    }
  }

  // Search products with filters
  async searchProducts(filters = {}, pagination = {}, currentUser = null) {
    try {
      const {
        q, // search query
        category,
        type,
        city,
        province,
        minPrice,
        maxPrice,
        nearCoordinates,
        radius = 10,
        ownerId,
        status = "active",
        sortBy = "createdAt",
      } = filters;

      const { page = 1, limit = 20, order = "desc" } = pagination;

      // Build query
      let query = {
        isAvailable: true,
        status: status,
        meetMinimumRequirement: true,
      };

      // Text search
      if (q) {
        query.$or = [
          { title: { $regex: q, $options: "i" } },
          { description: { $regex: q, $options: "i" } },
          { tags: { $in: [new RegExp(q, "i")] } },
        ];
      }

      // Category filter
      if (category) {
        query.category = category;
      }

      // Type filter
      if (type) {
        query.type = type;
      }

      // Location filters
      if (city) {
        query["location.address.city"] = { $regex: city, $options: "i" };
      }
      if (province) {
        query["location.address.province"] = {
          $regex: province,
          $options: "i",
        };
      }

      // Price range filter
      if (minPrice || maxPrice) {
        query.estimatedPrice = {};
        if (minPrice) query.estimatedPrice.$gte = parseFloat(minPrice);
        if (maxPrice) query.estimatedPrice.$lte = parseFloat(maxPrice);
      }

      // Owner filter
      if (ownerId) {
        query.owner = ownerId;
      }

      // Geospatial search
      if (nearCoordinates) {
        const [lng, lat] = nearCoordinates;
        query["location.coordinates"] = {
          $near: {
            $geometry: {
              type: "Point",
              coordinates: [lng, lat],
            },
            $maxDistance: radius * 1000,
          },
        };
      }

      // Admin can see all products
      if (currentUser?.role === "admin") {
        delete query.isAvailable;
        delete query.status;
      }

      // Build sort
      const sortObj = {};
      if (sortBy === "price") {
        sortObj.estimatedPrice = order === "desc" ? -1 : 1;
      } else if (sortBy === "views") {
        sortObj.views = -1;
      } else {
        sortObj[sortBy] = order === "desc" ? -1 : 1;
      }

      // Execute query
      const totalItems = await Product.countDocuments(query);
      const totalPages = Math.ceil(totalItems / limit);
      const skip = (page - 1) * limit;

      const products = await Product.find(query)
        .populate("owner", "name avatar rating role")
        .sort(sortObj)
        .skip(skip)
        .limit(limit)
        .exec();

      return {
        products,
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
      logger.error("Error searching products:", error);
      throw error;
    }
  }

  // Get products by category
  async getProductsByCategory(
    category,
    filters = {},
    pagination = {},
    currentUser = null
  ) {
    try {
      const categoryFilters = { ...filters, category };
      return await this.searchProducts(
        categoryFilters,
        pagination,
        currentUser
      );
    } catch (error) {
      logger.error(`Error getting products by category ${category}:`, error);
      throw error;
    }
  }

  // Get nearby products
  async getNearbyProducts(
    coordinates,
    radius = 10,
    filters = {},
    currentUser = null
  ) {
    try {
      const [lng, lat] = coordinates;

      if (!LocationUtils.isValidIndonesianCoordinates(lng, lat)) {
        throw new AppError("errors.invalid_coordinates", 400);
      }

      const nearbyFilters = {
        ...filters,
        nearCoordinates: [lng, lat],
        radius,
      };

      const result = await this.searchProducts(nearbyFilters, {}, currentUser);

      // Add distance calculation to products
      result.products = result.products.map((product) => {
        if (product.location?.coordinates) {
          const productCoords = [
            product.location.coordinates.longitude,
            product.location.coordinates.latitude,
          ];
          const distance = this.calculateDistance([lng, lat], productCoords);
          product.distance = Math.round(distance * 100) / 100;
        }
        return product;
      });

      return result;
    } catch (error) {
      logger.error("Error getting nearby products:", error);
      throw error;
    }
  }

  // Update product
  async updateProduct(productId, updateData, currentUser) {
    try {
      const product = await Product.findById(productId);

      if (!product) {
        throw new AppError("errors.product_not_found", 404);
      }

      // Check ownership or admin
      if (
        product.owner.toString() !== currentUser._id.toString() &&
        currentUser.role !== "admin"
      ) {
        throw new AppError("errors.insufficient_permissions", 403);
      }

      // Check if product can be updated
      if (["sold", "cancelled"].includes(product.status)) {
        throw new AppError("business.product_cannot_be_updated", 400, {
          status: product.status,
        });
      }

      // Validate minimum requirements if quantity changed
      if (updateData.scrapData?.estimatedWeight) {
        const minWeight = parseFloat(process.env.MIN_SCRAP_WEIGHT) || 5;
        if (updateData.scrapData.estimatedWeight < minWeight) {
          throw new AppError("business.minimum_weight_not_met", 400, {
            required: minWeight,
            provided: updateData.scrapData.estimatedWeight,
          });
        }
      }

      if (updateData.cookingOilData?.volume) {
        const minVolume = parseFloat(process.env.MIN_COOKING_OIL_VOLUME) || 1;
        if (updateData.cookingOilData.volume < minVolume) {
          throw new AppError("business.minimum_volume_not_met", 400, {
            required: minVolume,
            provided: updateData.cookingOilData.volume,
          });
        }
      }

      // Validate coordinates if location is being updated
      if (updateData.location?.coordinates) {
        const { longitude, latitude } = updateData.location.coordinates;
        if (!LocationUtils.isValidIndonesianCoordinates(longitude, latitude)) {
          throw new AppError("errors.invalid_coordinates", 400);
        }
      }

      // Update product
      const updatedProduct = await Product.findByIdAndUpdate(
        productId,
        {
          ...updateData,
          updatedAt: new Date(),
        },
        {
          new: true,
          runValidators: true,
        }
      ).populate("owner", "name avatar rating");

      logger.info(`Product updated: ${productId} by user ${currentUser._id}`);

      return updatedProduct;
    } catch (error) {
      logger.error("Error updating product:", error);
      throw error;
    }
  }

  // Delete product (soft delete)
  async deleteProduct(productId, currentUser) {
    try {
      const product = await Product.findById(productId);

      if (!product) {
        throw new AppError("errors.product_not_found", 404);
      }

      // Check ownership or admin
      if (
        product.owner.toString() !== currentUser._id.toString() &&
        currentUser.role !== "admin"
      ) {
        throw new AppError("errors.insufficient_permissions", 403);
      }

      // Check if product can be deleted
      if (["reserved", "sold"].includes(product.status)) {
        throw new AppError("business.product_cannot_be_deleted", 400, {
          status: product.status,
        });
      }

      // Soft delete
      product.status = "cancelled";
      product.isAvailable = false;
      await product.save();

      logger.info(`Product deleted: ${productId} by user ${currentUser._id}`);

      return { message: "Product deleted successfully" };
    } catch (error) {
      logger.error("Error deleting product:", error);
      throw error;
    }
  }

  // Add product to favorites
  async addToFavorites(productId, currentUser) {
    try {
      const product = await Product.findById(productId);

      if (!product) {
        throw new AppError("errors.product_not_found", 404);
      }

      // Can't favorite own products
      if (product.owner.toString() === currentUser._id.toString()) {
        throw new AppError("business.cannot_favorite_own_product", 400);
      }

      await product.addToFavorites(currentUser._id);

      logger.info(
        `Product added to favorites: ${productId} by user ${currentUser._id}`
      );

      return { message: "Product added to favorites" };
    } catch (error) {
      logger.error("Error adding to favorites:", error);
      throw error;
    }
  }

  // Remove product from favorites
  async removeFromFavorites(productId, currentUser) {
    try {
      const product = await Product.findById(productId);

      if (!product) {
        throw new AppError("errors.product_not_found", 404);
      }

      await product.removeFromFavorites(currentUser._id);

      logger.info(
        `Product removed from favorites: ${productId} by user ${currentUser._id}`
      );

      return { message: "Product removed from favorites" };
    } catch (error) {
      logger.error("Error removing from favorites:", error);
      throw error;
    }
  }

  // Get user's favorite products
  async getUserFavorites(userId, pagination = {}) {
    try {
      const { page = 1, limit = 20 } = pagination;

      const skip = (page - 1) * limit;

      const products = await Product.find({
        "favorites.user": userId,
        isAvailable: true,
        status: "active",
      })
        .populate("owner", "name avatar rating")
        .sort({ "favorites.createdAt": -1 })
        .skip(skip)
        .limit(limit)
        .exec();

      const totalItems = await Product.countDocuments({
        "favorites.user": userId,
        isAvailable: true,
        status: "active",
      });

      return {
        products,
        pagination: {
          page,
          totalPages: Math.ceil(totalItems / limit),
          totalItems,
          limit,
          hasNext: page < Math.ceil(totalItems / limit),
          hasPrev: page > 1,
        },
      };
    } catch (error) {
      logger.error("Error getting user favorites:", error);
      throw error;
    }
  }

  // Mark product as reserved (when order is created)
  async markAsReserved(productId, buyerId) {
    try {
      const product = await Product.findById(productId);

      if (!product) {
        throw new AppError("errors.product_not_found", 404);
      }

      if (!product.isAvailable || product.status !== "active") {
        throw new AppError("business.product_not_available", 400);
      }

      await product.markAsReserved(buyerId);

      logger.info(
        `Product marked as reserved: ${productId} for buyer ${buyerId}`
      );

      return product;
    } catch (error) {
      logger.error("Error marking product as reserved:", error);
      throw error;
    }
  }

  // Mark product as sold
  async markAsSold(productId, finalPrice, buyerId) {
    try {
      const product = await Product.findById(productId);

      if (!product) {
        throw new AppError("errors.product_not_found", 404);
      }

      await product.markAsSold(finalPrice, buyerId);

      logger.info(
        `Product marked as sold: ${productId} to buyer ${buyerId} for ${finalPrice}`
      );

      return product;
    } catch (error) {
      logger.error("Error marking product as sold:", error);
      throw error;
    }
  }

  // Get product statistics
  async getProductStatistics(filters = {}) {
    try {
      const { category, city, province, dateFrom, dateTo, ownerId } = filters;

      // Build match query
      let matchQuery = {};

      if (category) matchQuery.category = category;
      if (city) matchQuery["location.address.city"] = city;
      if (province) matchQuery["location.address.province"] = province;
      if (ownerId) matchQuery.owner = ownerId;

      if (dateFrom || dateTo) {
        matchQuery.createdAt = {};
        if (dateFrom) matchQuery.createdAt.$gte = new Date(dateFrom);
        if (dateTo) matchQuery.createdAt.$lte = new Date(dateTo);
      }

      const stats = await Product.aggregate([
        { $match: matchQuery },
        {
          $group: {
            _id: null,
            totalProducts: { $sum: 1 },
            activeProducts: {
              $sum: { $cond: [{ $eq: ["$status", "active"] }, 1, 0] },
            },
            soldProducts: {
              $sum: { $cond: [{ $eq: ["$status", "sold"] }, 1, 0] },
            },
            averagePrice: { $avg: "$estimatedPrice" },
            totalViews: { $sum: "$views" },
            byCategory: {
              $push: {
                category: "$category",
                type: "$type",
                price: "$estimatedPrice",
              },
            },
          },
        },
      ]);

      // Category breakdown
      const categoryStats = await Product.aggregate([
        { $match: matchQuery },
        {
          $group: {
            _id: "$category",
            count: { $sum: 1 },
            averagePrice: { $avg: "$estimatedPrice" },
            totalViews: { $sum: "$views" },
          },
        },
      ]);

      // Type breakdown
      const typeStats = await Product.aggregate([
        { $match: matchQuery },
        {
          $group: {
            _id: "$type",
            count: { $sum: 1 },
            averagePrice: { $avg: "$estimatedPrice" },
          },
        },
      ]);

      return {
        summary: stats[0] || {
          totalProducts: 0,
          activeProducts: 0,
          soldProducts: 0,
          averagePrice: 0,
          totalViews: 0,
        },
        byCategory: categoryStats,
        byType: typeStats,
      };
    } catch (error) {
      logger.error("Error getting product statistics:", error);
      throw error;
    }
  }

  // Get trending products (most viewed, most favorited)
  async getTrendingProducts(limit = 10, timeframe = "7d") {
    try {
      // Calculate date based on timeframe
      let dateFrom = new Date();
      if (timeframe === "7d") {
        dateFrom.setDate(dateFrom.getDate() - 7);
      } else if (timeframe === "30d") {
        dateFrom.setDate(dateFrom.getDate() - 30);
      } else if (timeframe === "1d") {
        dateFrom.setDate(dateFrom.getDate() - 1);
      }

      const trendingProducts = await Product.find({
        isAvailable: true,
        status: "active",
        createdAt: { $gte: dateFrom },
      })
        .populate("owner", "name avatar rating")
        .sort({ views: -1, favoriteCount: -1 })
        .limit(limit)
        .exec();

      return trendingProducts;
    } catch (error) {
      logger.error("Error getting trending products:", error);
      throw error;
    }
  }

  // Calculate distance between two coordinates
  calculateDistance(coord1, coord2) {
    const R = 6371; // Earth's radius in km
    const dLat = ((coord2[1] - coord1[1]) * Math.PI) / 180;
    const dLon = ((coord2[0] - coord1[0]) * Math.PI) / 180;
    const a =
      Math.sin(dLat / 2) * Math.sin(dLat / 2) +
      Math.cos((coord1[1] * Math.PI) / 180) *
        Math.cos((coord2[1] * Math.PI) / 180) *
        Math.sin(dLon / 2) *
        Math.sin(dLon / 2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
    return R * c;
  }

  // Validate product ownership
  async validateProductOwnership(productId, userId) {
    try {
      const product = await Product.findById(productId).select("owner");

      if (!product) {
        return false;
      }

      return product.owner.toString() === userId.toString();
    } catch (error) {
      logger.error("Error validating product ownership:", error);
      return false;
    }
  }

  // Get products that need attention (expired, low quality, etc.)
  async getProductsNeedingAttention(userId, role) {
    try {
      let query = {};

      if (role !== "admin") {
        query.owner = userId;
      }

      // Find products that need attention
      const now = new Date();
      const products = await Product.find({
        ...query,
        $or: [
          // Expiring soon (within 3 days)
          {
            expiresAt: {
              $lte: new Date(now.getTime() + 3 * 24 * 60 * 60 * 1000),
              $gte: now,
            },
            status: "active",
          },
          // Low views after 7 days
          {
            views: { $lt: 5 },
            createdAt: {
              $lte: new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000),
            },
            status: "active",
          },
          // No images
          {
            $or: [{ images: { $size: 0 } }, { images: { $exists: false } }],
            status: "active",
          },
        ],
      })
        .populate("owner", "name email")
        .sort({ expiresAt: 1 })
        .limit(20)
        .exec();

      // Categorize issues
      const categorized = {
        expiringSoon: [],
        lowViews: [],
        noImages: [],
      };

      products.forEach((product) => {
        if (
          product.expiresAt &&
          product.expiresAt <= new Date(now.getTime() + 3 * 24 * 60 * 60 * 1000)
        ) {
          categorized.expiringSoon.push(product);
        }
        if (
          product.views < 5 &&
          product.createdAt <= new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000)
        ) {
          categorized.lowViews.push(product);
        }
        if (!product.images || product.images.length === 0) {
          categorized.noImages.push(product);
        }
      });

      return categorized;
    } catch (error) {
      logger.error("Error getting products needing attention:", error);
      throw error;
    }
  }
}

// Create singleton instance
const productService = new ProductService();

export default productService;

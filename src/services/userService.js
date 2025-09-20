import { User, ServiceCoverage, LocationUtils } from "../models/index.js";
import { createLogger } from "../utils/logger.js";
import { AppError } from "../middlewares/errorMiddleware.js";
import passwordManager from "../utils/password.js";

const logger = createLogger("UserService");

class UserService {
  // Get user by ID with population options
  async getUserById(userId, populateOptions = {}) {
    try {
      let query = User.findById(userId);

      // Handle population
      if (populateOptions.addresses) {
        query = query.select("+addresses");
      }
      if (populateOptions.rtRwData) {
        query = query.select("+rtRwData");
      }
      if (populateOptions.collectorData) {
        query = query.select("+collectorData");
      }

      const user = await query.exec();

      if (!user) {
        throw new AppError("errors.user_not_found", 404);
      }

      return this.sanitizeUser(user);
    } catch (error) {
      logger.error("Error getting user by ID:", error);
      throw error;
    }
  }

  // Get user profile (detailed info for profile page)
  async getUserProfile(userId) {
    try {
      const user = await User.findById(userId)
        .select("+addresses +preferences +rtRwData +collectorData")
        .exec();

      if (!user) {
        throw new AppError("errors.user_not_found", 404);
      }

      const profile = this.sanitizeUser(user);

      // Add computed fields
      profile.profileCompleteness = this.calculateProfileCompleteness(user);
      profile.memberSince = user.createdAt;
      profile.lastActiveAt = user.lastLogin || user.updatedAt;

      return profile;
    } catch (error) {
      logger.error("Error getting user profile:", error);
      throw error;
    }
  }

  // Update user profile
  async updateUserProfile(userId, updateData, currentUser) {
    try {
      const user = await User.findById(userId);

      if (!user) {
        throw new AppError("errors.user_not_found", 404);
      }

      // Check if user can update this profile
      if (
        currentUser._id.toString() !== userId &&
        currentUser.role !== "admin"
      ) {
        throw new AppError("errors.insufficient_permissions", 403);
      }

      // Validate email uniqueness if email is being updated
      if (updateData.email && updateData.email !== user.email) {
        const existingUser = await User.findOne({
          email: updateData.email.toLowerCase(),
          _id: { $ne: userId },
        });

        if (existingUser) {
          throw new AppError("errors.email_already_registered", 400);
        }

        // Reset email verification if email changed
        updateData.isEmailVerified = false;
      }

      // Validate phone uniqueness if phone is being updated
      if (updateData.phone && updateData.phone !== user.phone) {
        const existingUser = await User.findOne({
          phone: updateData.phone,
          _id: { $ne: userId },
        });

        if (existingUser) {
          throw new AppError("errors.phone_already_registered", 400);
        }

        // Reset phone verification if phone changed
        updateData.isPhoneVerified = false;
      }

      // Handle addresses update
      if (updateData.addresses) {
        // Validate coordinates
        for (const address of updateData.addresses) {
          if (address.coordinates && address.coordinates.coordinates) {
            const [lng, lat] = address.coordinates.coordinates;
            if (!LocationUtils.isValidIndonesianCoordinates(lng, lat)) {
              throw new AppError("errors.invalid_coordinates", 400);
            }
          }
        }

        // Ensure only one default address
        let hasDefault = false;
        updateData.addresses.forEach((addr, index) => {
          if (addr.isDefault && !hasDefault) {
            hasDefault = true;
          } else if (addr.isDefault) {
            updateData.addresses[index].isDefault = false;
          }
        });

        // Set first address as default if none specified
        if (!hasDefault && updateData.addresses.length > 0) {
          updateData.addresses[0].isDefault = true;
        }
      }

      // Handle role-specific data updates
      if (updateData.rtRwData && !["rt", "rw"].includes(user.role)) {
        throw new AppError("errors.invalid_role_data", 400, {
          role: user.role,
        });
      }

      if (updateData.collectorData && user.role !== "collector") {
        throw new AppError("errors.invalid_role_data", 400, {
          role: user.role,
        });
      }

      // Update user
      const updatedUser = await User.findByIdAndUpdate(
        userId,
        {
          ...updateData,
          updatedAt: new Date(),
        },
        {
          new: true,
          runValidators: true,
        }
      ).select("+addresses +preferences +rtRwData +collectorData");

      // Update service coverage if collector data changed
      if (updateData.collectorData && user.role === "collector") {
        await this.updateServiceCoverage(userId, updateData.collectorData);
      }

      logger.info(`User profile updated: ${userId}`);

      return this.sanitizeUser(updatedUser);
    } catch (error) {
      logger.error("Error updating user profile:", error);
      throw error;
    }
  }

  // Search users with filters and pagination
  async searchUsers(filters = {}, pagination = {}, currentUser) {
    try {
      const {
        q, // search query
        role,
        isActive,
        isEmailVerified,
        city,
        province,
        rating,
        nearCoordinates,
        radius = 10,
      } = filters;

      const {
        page = 1,
        limit = 20,
        sort = "createdAt",
        order = "desc",
      } = pagination;

      // Build query
      let query = {};

      // Text search across name and email
      if (q) {
        query.$or = [
          { name: { $regex: q, $options: "i" } },
          { email: { $regex: q, $options: "i" } },
        ];
      }

      // Filter by role
      if (role) {
        query.role = role;
      }

      // Filter by active status
      if (typeof isActive === "boolean") {
        query.isActive = isActive;
      }

      // Filter by email verification
      if (typeof isEmailVerified === "boolean") {
        query.isEmailVerified = isEmailVerified;
      }

      // Filter by location
      if (city) {
        query["addresses.city"] = { $regex: city, $options: "i" };
      }
      if (province) {
        query["addresses.province"] = { $regex: province, $options: "i" };
      }

      // Filter by rating
      if (rating) {
        query["rating.average"] = { $gte: parseFloat(rating) };
      }

      // Geospatial search
      if (nearCoordinates) {
        const [lng, lat] = nearCoordinates;
        query["addresses.coordinates"] = {
          $near: {
            $geometry: {
              type: "Point",
              coordinates: [lng, lat],
            },
            $maxDistance: radius * 1000, // Convert km to meters
          },
        };
      }

      // Admin can see all users, others see only active users
      if (currentUser.role !== "admin") {
        query.isActive = true;
      }

      // Build sort object
      const sortObj = {};
      sortObj[sort] = order === "desc" ? -1 : 1;

      // Execute query with pagination
      const totalItems = await User.countDocuments(query);
      const totalPages = Math.ceil(totalItems / limit);
      const skip = (page - 1) * limit;

      const users = await User.find(query)
        .select("-password -emailVerificationToken -passwordResetToken")
        .sort(sortObj)
        .skip(skip)
        .limit(limit)
        .exec();

      const sanitizedUsers = users.map((user) => this.sanitizeUser(user));

      return {
        users: sanitizedUsers,
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
      logger.error("Error searching users:", error);
      throw error;
    }
  }

  // Get users by role with specific filters
  async getUsersByRole(role, filters = {}, pagination = {}) {
    try {
      const roleFilters = { ...filters, role };
      return await this.searchUsers(roleFilters, pagination, { role: "admin" });
    } catch (error) {
      logger.error(`Error getting users by role ${role}:`, error);
      throw error;
    }
  }

  // Find nearby users (collectors, RT, RW)
  async findNearbyUsers(coordinates, role = null, radius = 10) {
    try {
      const [lng, lat] = coordinates;

      if (!LocationUtils.isValidIndonesianCoordinates(lng, lat)) {
        throw new AppError("errors.invalid_coordinates", 400);
      }

      const query = {
        "addresses.coordinates": {
          $near: {
            $geometry: {
              type: "Point",
              coordinates: [lng, lat],
            },
            $maxDistance: radius * 1000,
          },
        },
        isActive: true,
      };

      if (role) {
        query.role = role;
      }

      const users = await User.find(query)
        .select("name avatar rating addresses role collectorData rtRwData")
        .limit(20)
        .exec();

      return users.map((user) => {
        const sanitized = this.sanitizeUser(user);

        // Add distance calculation (approximation)
        const userCoords = user.addresses.find((addr) => addr.isDefault)
          ?.coordinates?.coordinates;
        if (userCoords) {
          const distance = this.calculateDistance([lng, lat], userCoords);
          sanitized.distance = Math.round(distance * 100) / 100; // Round to 2 decimal places
        }

        return sanitized;
      });
    } catch (error) {
      logger.error("Error finding nearby users:", error);
      throw error;
    }
  }

  // Deactivate user account
  async deactivateUser(userId, currentUser, reason) {
    try {
      const user = await User.findById(userId);

      if (!user) {
        throw new AppError("errors.user_not_found", 404);
      }

      // Only admin or user themselves can deactivate
      if (
        currentUser.role !== "admin" &&
        currentUser._id.toString() !== userId
      ) {
        throw new AppError("errors.insufficient_permissions", 403);
      }

      user.isActive = false;
      user.deactivatedAt = new Date();
      user.deactivationReason = reason;
      await user.save();

      // Remove all user sessions
      // This will be handled by auth service if integrated

      logger.info(`User deactivated: ${userId} by ${currentUser._id}`);

      return { message: "User deactivated successfully" };
    } catch (error) {
      logger.error("Error deactivating user:", error);
      throw error;
    }
  }

  // Reactivate user account
  async reactivateUser(userId, currentUser) {
    try {
      // Only admin can reactivate
      if (currentUser.role !== "admin") {
        throw new AppError("errors.insufficient_permissions", 403);
      }

      const user = await User.findById(userId);

      if (!user) {
        throw new AppError("errors.user_not_found", 404);
      }

      user.isActive = true;
      user.deactivatedAt = undefined;
      user.deactivationReason = undefined;
      await user.save();

      logger.info(`User reactivated: ${userId} by ${currentUser._id}`);

      return { message: "User reactivated successfully" };
    } catch (error) {
      logger.error("Error reactivating user:", error);
      throw error;
    }
  }

  // Get user statistics
  async getUserStatistics(userId) {
    try {
      const user = await User.findById(userId);

      if (!user) {
        throw new AppError("errors.user_not_found", 404);
      }

      // This will be enhanced when order/rating services are implemented
      const stats = {
        basicInfo: {
          memberSince: user.createdAt,
          lastActive: user.lastLogin || user.updatedAt,
          profileCompleteness: this.calculateProfileCompleteness(user),
          totalPoints: user.points.current,
          lifetimePoints: user.points.lifetime,
        },
        rating: {
          average: user.rating.average,
          count: user.rating.count,
        },
        verification: {
          emailVerified: user.isEmailVerified,
          phoneVerified: user.isPhoneVerified,
        },
      };

      return stats;
    } catch (error) {
      logger.error("Error getting user statistics:", error);
      throw error;
    }
  }

  // Helper method to calculate profile completeness
  calculateProfileCompleteness(user) {
    const fields = ["name", "email", "phone", "addresses"];

    const roleSpecificFields = {
      rt: ["rtRwData"],
      rw: ["rtRwData"],
      collector: ["collectorData"],
    };

    const requiredFields = [
      ...fields,
      ...(roleSpecificFields[user.role] || []),
    ];

    let completedFields = 0;

    for (const field of requiredFields) {
      if (field === "addresses") {
        if (user.addresses && user.addresses.length > 0) {
          completedFields++;
        }
      } else if (user[field]) {
        completedFields++;
      }
    }

    return Math.round((completedFields / requiredFields.length) * 100);
  }

  // Helper method to update service coverage for collectors
  async updateServiceCoverage(userId, collectorData) {
    try {
      const user = await User.findById(userId).select("addresses");

      if (!user || !user.addresses.length) {
        return;
      }

      const defaultAddress =
        user.addresses.find((addr) => addr.isDefault) || user.addresses[0];

      const serviceCoverageData = {
        serviceProvider: userId,
        coverageType: "collector_radius",
        radiusCoverage: {
          center: {
            type: "Point",
            coordinates: defaultAddress.coordinates.coordinates,
          },
          radius: collectorData.serviceRadius || 10,
        },
        services: ["both"],
        operatingHours: collectorData.operatingHours || {
          monday: { start: "08:00", end: "17:00", isActive: true },
          tuesday: { start: "08:00", end: "17:00", isActive: true },
          wednesday: { start: "08:00", end: "17:00", isActive: true },
          thursday: { start: "08:00", end: "17:00", isActive: true },
          friday: { start: "08:00", end: "17:00", isActive: true },
          saturday: { start: "08:00", end: "17:00", isActive: true },
          sunday: { start: "08:00", end: "17:00", isActive: false },
        },
        isActive: collectorData.isAvailable !== false,
      };

      // Update or create service coverage
      await ServiceCoverage.findOneAndUpdate(
        { serviceProvider: userId },
        serviceCoverageData,
        { upsert: true, new: true }
      );

      logger.info(`Service coverage updated for collector: ${userId}`);
    } catch (error) {
      logger.error("Error updating service coverage:", error);
      // Don't throw error as this is a secondary operation
    }
  }

  // Helper method to calculate distance between coordinates
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

  // Helper method to sanitize user data
  sanitizeUser(user) {
    const userObj = user.toObject();

    // Remove sensitive fields
    delete userObj.password;
    delete userObj.emailVerificationToken;
    delete userObj.passwordResetToken;
    delete userObj.loginAttempts;
    delete userObj.lockUntil;

    return userObj;
  }
}

// Create singleton instance
const userService = new UserService();

export default userService;

import { User, ServiceCoverage, LocationUtils } from "../models/index.js";
import { createLogger } from "../utils/logger.js";
import { AppError } from "../middlewares/errorMiddleware.js";
import passwordManager from "../utils/password.js";
import pointService from "./pointService.js"; // NEW INTEGRATION

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

  // UPDATED: Get user profile (detailed info with multi-role and points)
  async getUserProfile(userId, role = null) {
    try {
      const user = await User.findById(userId)
        .select("+addresses +preferences")
        .exec();

      if (!user) {
        throw new AppError("errors.user_not_found", 404);
      }

      const profile = this.sanitizeUser(user);

      // Add computed fields
      profile.profileCompleteness = this.calculateProfileCompleteness(user);
      profile.memberSince = user.createdAt;
      profile.lastActiveAt = user.lastLogin || user.updatedAt;

      // NEW: Add points summary for current or specified role
      const targetRole = role || user.currentRole;
      if (user.hasRole(targetRole)) {
        profile.pointsSummary = await pointService.getPointsSummary(
          userId,
          targetRole
        );
      }

      // NEW: Add role-specific data
      profile.availableRoles = user.roles.map((r) => ({
        role: r.role,
        isActive: r.isActive,
        isPrimary: r.isPrimary,
        points: r.points,
        rating: r.rating,
      }));

      // NEW: Add current role data with specific info
      const currentRoleData = user.currentRoleData;
      if (currentRoleData) {
        profile.currentRoleData = {
          role: currentRoleData.role,
          points: currentRoleData.points,
          rating: currentRoleData.rating,
          rtRwData: currentRoleData.rtRwData,
          collectorData: currentRoleData.collectorData,
        };
      }

      return profile;
    } catch (error) {
      logger.error("Error getting user profile:", error);
      throw error;
    }
  }

  // UPDATED: Update user profile with multi-role support
  async updateUserProfile(userId, updateData, currentUser) {
    try {
      const user = await User.findById(userId);

      if (!user) {
        throw new AppError("errors.user_not_found", 404);
      }

      // Check if user can update this profile
      if (
        currentUser._id.toString() !== userId &&
        !currentUser.hasRole("admin")
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
        // For multi-role system, phone doesn't need to be unique anymore
        // But we can still warn if it's already used
        const existingUser = await User.findOne({
          phone: updateData.phone,
          _id: { $ne: userId },
        });

        if (existingUser) {
          logger.warn(
            `Phone ${updateData.phone} is already used by another user`
          );
        }

        // Reset phone verification if phone changed
        updateData.isPhoneVerified = false;
      }

      // Handle addresses update with validation
      if (updateData.addresses) {
        updateData.addresses = await this.validateAndProcessAddresses(
          updateData.addresses
        );
      }

      // Handle role-specific data updates
      if (updateData.roleData) {
        await this.updateRoleSpecificData(
          user,
          updateData.roleData,
          currentUser
        );
        delete updateData.roleData; // Remove from general update
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
      ).select("+addresses +preferences");

      // Update service coverage if collector data changed
      if (updateData.roleData?.collectorData && user.hasRole("collector")) {
        await this.updateServiceCoverage(
          userId,
          updateData.roleData.collectorData
        );
      }

      logger.info(`User profile updated: ${userId}`);

      return this.sanitizeUser(updatedUser);
    } catch (error) {
      logger.error("Error updating user profile:", error);
      throw error;
    }
  }

  // NEW: Switch user role
  async switchUserRole(userId, targetRole, currentUser) {
    try {
      // Check permissions
      if (
        currentUser._id.toString() !== userId &&
        !currentUser.hasRole("admin")
      ) {
        throw new AppError("errors.insufficient_permissions", 403);
      }

      const user = await User.findById(userId);
      if (!user) {
        throw new AppError("errors.user_not_found", 404);
      }

      // Switch role
      await user.switchRole(targetRole);

      logger.info(`User ${userId} switched to role: ${targetRole}`);

      return {
        message: "Role switched successfully",
        newRole: targetRole,
        userData: this.sanitizeUser(user),
      };
    } catch (error) {
      logger.error("Error switching user role:", error);
      throw error;
    }
  }

  // NEW: Add new role to user
  async addUserRole(userId, roleData, currentUser) {
    try {
      // Only admin can add roles
      if (!currentUser.hasRole("admin")) {
        throw new AppError("errors.insufficient_permissions", 403);
      }

      const user = await User.findById(userId);
      if (!user) {
        throw new AppError("errors.user_not_found", 404);
      }

      // Validate role data
      const validatedRoleData = await this.validateRoleData(roleData);

      // Add role
      await user.addRole(validatedRoleData);

      logger.info(`Role ${roleData.role} added to user: ${userId}`);

      return {
        message: "Role added successfully",
        newRole: roleData.role,
        userData: this.sanitizeUser(user),
      };
    } catch (error) {
      logger.error("Error adding user role:", error);
      throw error;
    }
  }

  // NEW: Remove role from user
  async removeUserRole(userId, roleName, currentUser) {
    try {
      // Only admin can remove roles
      if (!currentUser.hasRole("admin")) {
        throw new AppError("errors.insufficient_permissions", 403);
      }

      const user = await User.findById(userId);
      if (!user) {
        throw new AppError("errors.user_not_found", 404);
      }

      // Remove role
      await user.removeRole(roleName);

      logger.info(`Role ${roleName} removed from user: ${userId}`);

      return {
        message: "Role removed successfully",
        removedRole: roleName,
        userData: this.sanitizeUser(user),
      };
    } catch (error) {
      logger.error("Error removing user role:", error);
      throw error;
    }
  }

  // NEW: Get user points summary
  async getUserPointsSummary(userId, role = null, currentUser) {
    try {
      // Check permissions
      if (
        currentUser._id.toString() !== userId &&
        !currentUser.hasRole("admin")
      ) {
        throw new AppError("errors.insufficient_permissions", 403);
      }

      const user = await User.findById(userId);
      if (!user) {
        throw new AppError("errors.user_not_found", 404);
      }

      const targetRole = role || user.currentRole;

      // Get comprehensive points summary
      const pointsSummary = await pointService.getPointsSummary(
        userId,
        targetRole
      );

      // Get points history
      const pointsHistory = await pointService.getPointsHistory(
        userId,
        {
          role: targetRole,
        },
        {
          page: 1,
          limit: 10,
        }
      );

      return {
        role: targetRole,
        summary: pointsSummary,
        recentHistory: pointsHistory.transactions,
        availableRoles: user.roles.map((r) => ({
          role: r.role,
          points: r.points,
        })),
      };
    } catch (error) {
      logger.error("Error getting user points summary:", error);
      throw error;
    }
  }

  // UPDATED: Search users with multi-role support
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

      // Build query for multi-role system
      let query = {};

      // Text search across name and email
      if (q) {
        query.$or = [
          { name: { $regex: q, $options: "i" } },
          { email: { $regex: q, $options: "i" } },
        ];
      }

      // Filter by role (now searches in roles array)
      if (role) {
        query["roles.role"] = role;
        query["roles.isActive"] = true;
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

      // Filter by rating (for specific role)
      if (rating && role) {
        query["roles.rating.average"] = { $gte: parseFloat(rating) };
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
      if (!currentUser.hasRole("admin")) {
        query.isActive = true;
      }

      // Build sort object
      const sortObj = {};
      if (sort === "rating" && role) {
        // Sort by role-specific rating
        sortObj["roles.rating.average"] = order === "desc" ? -1 : 1;
      } else {
        sortObj[sort] = order === "desc" ? -1 : 1;
      }

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

  // UPDATED: Get users by role with multi-role support
  async getUsersByRole(role, filters = {}, pagination = {}) {
    try {
      const roleFilters = { ...filters, role };
      return await this.searchUsers(roleFilters, pagination, {
        hasRole: () => true,
      }); // Mock admin user
    } catch (error) {
      logger.error(`Error getting users by role ${role}:`, error);
      throw error;
    }
  }

  // UPDATED: Find nearby users with role filtering
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
        query["roles.role"] = role;
        query["roles.isActive"] = true;
      }

      const users = await User.find(query)
        .select("name avatar addresses roles currentRole")
        .limit(20)
        .exec();

      return users.map((user) => {
        const sanitized = this.sanitizeUser(user);

        // Add distance calculation
        const userCoords = user.addresses.find((addr) => addr.isDefault)
          ?.coordinates?.coordinates;
        if (userCoords) {
          const distance = this.calculateDistance([lng, lat], userCoords);
          sanitized.distance = Math.round(distance * 100) / 100;
        }

        // Add role-specific data
        if (role) {
          const roleData = user.getRoleData(role);
          if (roleData) {
            sanitized.roleSpecific = {
              rating: roleData.rating,
              points: roleData.points,
              rtRwData: roleData.rtRwData,
              collectorData: roleData.collectorData,
            };
          }
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
        !currentUser.hasRole("admin") &&
        currentUser._id.toString() !== userId
      ) {
        throw new AppError("errors.insufficient_permissions", 403);
      }

      user.isActive = false;
      user.deactivatedAt = new Date();
      user.deactivationReason = reason;
      await user.save();

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
      if (!currentUser.hasRole("admin")) {
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

  // UPDATED: Get user statistics with points and multi-role data
  async getUserStatistics(userId, currentUser) {
    try {
      // Check permissions
      if (
        currentUser._id.toString() !== userId &&
        !currentUser.hasRole("admin")
      ) {
        throw new AppError("errors.insufficient_permissions", 403);
      }

      console.log("Fetching statistics for user:", userId);
      const user = await User.findById(userId);

      if (!user) {
        throw new AppError("errors.user_not_found", 404);
      }

      // Get points summary for current role
      const pointsSummary = await pointService.getPointsSummary(
        userId,
        user.currentRole
      );

      const stats = {
        basicInfo: {
          memberSince: user.createdAt,
          lastActive: user.lastLogin || user.updatedAt,
          profileCompleteness: this.calculateProfileCompleteness(user),
          currentRole: user.currentRole,
          totalRoles: user.roles.length,
        },
        roles: user.roles.map((role) => ({
          role: role.role,
          isActive: role.isActive,
          isPrimary: role.isPrimary,
          points: role.points,
          rating: role.rating,
        })),
        pointsSummary,
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

  // NEW: Validate and process addresses
  async validateAndProcessAddresses(addresses) {
    const processedAddresses = [];

    for (const address of addresses) {
      if (address.coordinates && address.coordinates.coordinates) {
        const [lng, lat] = address.coordinates.coordinates;
        if (!LocationUtils.isValidIndonesianCoordinates(lng, lat)) {
          throw new AppError("errors.invalid_coordinates", 400);
        }
      }
      processedAddresses.push(address);
    }

    // Ensure only one default address
    let hasDefault = false;
    processedAddresses.forEach((addr, index) => {
      if (addr.isDefault && !hasDefault) {
        hasDefault = true;
      } else if (addr.isDefault) {
        processedAddresses[index].isDefault = false;
      }
    });

    // Set first address as default if none specified
    if (!hasDefault && processedAddresses.length > 0) {
      processedAddresses[0].isDefault = true;
    }

    return processedAddresses;
  }

  // NEW: Update role-specific data
  async updateRoleSpecificData(user, roleData, currentUser) {
    const { role, data } = roleData;

    // Validate user has the role
    if (!user.hasRole(role)) {
      throw new AppError("errors.role_not_found", 400, { role });
    }

    // Update role-specific data
    const roleIndex = user.roles.findIndex((r) => r.role === role);
    if (roleIndex !== -1) {
      if (role === "rt" || role === "rw") {
        user.roles[roleIndex].rtRwData = {
          ...user.roles[roleIndex].rtRwData,
          ...data,
        };
      } else if (role === "collector") {
        user.roles[roleIndex].collectorData = {
          ...user.roles[roleIndex].collectorData,
          ...data,
        };
      }
    }

    await user.save();
  }

  // NEW: Validate role data
  async validateRoleData(roleData) {
    const { role, rtRwData, collectorData } = roleData;

    // Validate role-specific required data
    if ((role === "rt" || role === "rw") && !rtRwData) {
      throw new AppError("errors.missing_role_data", 400, {
        role,
        required: "rtRwData",
      });
    }

    if (role === "collector" && !collectorData) {
      throw new AppError("errors.missing_role_data", 400, {
        role,
        required: "collectorData",
      });
    }

    return {
      role,
      isActive: true,
      isPrimary: roleData.isPrimary || false,
      rtRwData,
      collectorData,
      points: {
        current: 0,
        lifetime: 0,
      },
      rating: {
        average: 0,
        count: 0,
      },
    };
  }

  // Helper method to calculate profile completeness
  calculateProfileCompleteness(user) {
    const basicFields = ["name", "email", "phone", "addresses"];
    let requiredFields = [...basicFields];

    // Add role-specific requirements
    user.roles.forEach((role) => {
      if (role.role === "rt" || role.role === "rw") {
        requiredFields.push("rtRwData");
      } else if (role.role === "collector") {
        requiredFields.push("collectorData");
      }
    });

    // Remove duplicates
    requiredFields = [...new Set(requiredFields)];

    let completedFields = 0;

    for (const field of requiredFields) {
      if (field === "addresses") {
        if (user.addresses && user.addresses.length > 0) {
          completedFields++;
        }
      } else if (field === "rtRwData") {
        const hasRtRwRole = user.roles.some(
          (r) => (r.role === "rt" || r.role === "rw") && r.rtRwData
        );
        if (hasRtRwRole) completedFields++;
      } else if (field === "collectorData") {
        const hasCollectorRole = user.roles.some(
          (r) => r.role === "collector" && r.collectorData
        );
        if (hasCollectorRole) completedFields++;
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

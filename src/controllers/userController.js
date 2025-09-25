// import userService from "../services/userService.js";
// import { createLogger } from "../utils/logger.js";
// import { AppError } from "../middlewares/errorMiddleware.js";
// import { successResponse, errorResponse } from "../utils/responseHelper.js";

// const logger = createLogger("UserController");

// class UserController {
//   // Get current user profile
//   async getProfile(req, res, next) {
//     try {
//       const userId = req.user._id;
//       const { role } = req.query; // Optional: get profile for specific role

//       const profile = await userService.getUserProfile(userId, role);

//       return successResponse(res, profile, "Profile retrieved successfully");
//     } catch (error) {
//       logger.error("Error getting user profile:", error);
//       next(error);
//     }
//   }

//   // Update current user profile
//   async updateProfile(req, res, next) {
//     try {
//       const userId = req.user._id;
//       const updateData = req.body;

//       // Validate required fields if provided
//       if (updateData.email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(updateData.email)) {
//         throw new AppError("errors.invalid_email_format", 400);
//       }

//       if (updateData.phone && !/^(\+62|62|0)[0-9]{9,13}$/.test(updateData.phone)) {
//         throw new AppError("errors.invalid_phone_format", 400);
//       }

//       const updatedProfile = await userService.updateUserProfile(
//         userId,
//         updateData,
//         req.user
//       );

//       return successResponse(
//         res,
//         updatedProfile,
//         "Profile updated successfully"
//       );
//     } catch (error) {
//       logger.error("Error updating user profile:", error);
//       next(error);
//     }
//   }

//   // Get user by ID (admin or public info)
//   async getUserById(req, res, next) {
//     try {
//       const { userId } = req.params;
//       const { populate } = req.query;

//       // Parse populate options
//       const populateOptions = {};
//       if (populate) {
//         const options = populate.split(',');
//         options.forEach(option => {
//           populateOptions[option.trim()] = true;
//         });
//       }

//       const user = await userService.getUserById(userId, populateOptions);

//       // Check if current user can view this profile
//       const isOwner = req.user._id.toString() === userId;
//       const isAdmin = req.user.hasRole("admin");

//       if (!isOwner && !isAdmin) {
//         // Return limited public info for non-owners
//         const publicUser = {
//           _id: user._id,
//           name: user.name,
//           avatar: user.avatar,
//           currentRole: user.currentRole,
//           memberSince: user.createdAt,
//           isActive: user.isActive,
//         };

//         return successResponse(res, publicUser, "User retrieved successfully");
//       }

//       return successResponse(res, user, "User retrieved successfully");
//     } catch (error) {
//       logger.error("Error getting user by ID:", error);
//       next(error);
//     }
//   }

//   // Search users with filters
//   async searchUsers(req, res, next) {
//     try {
//       const {
//         q,
//         role,
//         isActive,
//         isEmailVerified,
//         city,
//         province,
//         rating,
//         lat,
//         lng,
//         radius,
//         page,
//         limit,
//         sort,
//         order,
//       } = req.query;

//       const filters = {
//         q,
//         role,
//         isActive: isActive !== undefined ? isActive === 'true' : undefined,
//         isEmailVerified: isEmailVerified !== undefined ? isEmailVerified === 'true' : undefined,
//         city,
//         province,
//         rating: rating ? parseFloat(rating) : undefined,
//         nearCoordinates: lat && lng ? [parseFloat(lng), parseFloat(lat)] : undefined,
//         radius: radius ? parseInt(radius) : 10,
//       };

//       const pagination = {
//         page: page ? parseInt(page) : 1,
//         limit: limit ? parseInt(limit) : 20,
//         sort: sort || "createdAt",
//         order: order || "desc",
//       };

//       const result = await userService.searchUsers(filters, pagination, req.user);

//       return successResponse(res, result, "Users retrieved successfully");
//     } catch (error) {
//       logger.error("Error searching users:", error);
//       next(error);
//     }
//   }

//   // Get users by specific role
//   async getUsersByRole(req, res, next) {
//     try {
//       const { role } = req.params;
//       const {
//         city,
//         province,
//         rating,
//         lat,
//         lng,
//         radius,
//         page,
//         limit,
//         sort,
//         order,
//       } = req.query;

//       // Validate role
//       const validRoles = ["individual", "rt", "rw", "collector", "admin"];
//       if (!validRoles.includes(role)) {
//         throw new AppError("errors.invalid_role", 400, { role });
//       }

//       const filters = {
//         city,
//         province,
//         rating: rating ? parseFloat(rating) : undefined,
//         nearCoordinates: lat && lng ? [parseFloat(lng), parseFloat(lat)] : undefined,
//         radius: radius ? parseInt(radius) : 10,
//       };

//       const pagination = {
//         page: page ? parseInt(page) : 1,
//         limit: limit ? parseInt(limit) : 20,
//         sort: sort || "createdAt",
//         order: order || "desc",
//       };

//       const result = await userService.getUsersByRole(role, filters, pagination);

//       return successResponse(res, result, `${role} users retrieved successfully`);
//     } catch (error) {
//       logger.error(`Error getting users by role:`, error);
//       next(error);
//     }
//   }

//   // Find nearby users
//   async findNearbyUsers(req, res, next) {
//     try {
//       const { lat, lng, role, radius } = req.query;

//       if (!lat || !lng) {
//         throw new AppError("errors.coordinates_required", 400);
//       }

//       const coordinates = [parseFloat(lng), parseFloat(lat)];
//       const searchRadius = radius ? parseInt(radius) : 10;

//       const nearbyUsers = await userService.findNearbyUsers(
//         coordinates,
//         role,
//         searchRadius
//       );

//       return successResponse(
//         res,
//         { users: nearbyUsers, radius: searchRadius },
//         "Nearby users retrieved successfully"
//       );
//     } catch (error) {
//       logger.error("Error finding nearby users:", error);
//       next(error);
//     }
//   }

//   // Switch user role
//   async switchRole(req, res, next) {
//     try {
//       const userId = req.user._id;
//       const { role } = req.body;

//       if (!role) {
//         throw new AppError("errors.role_required", 400);
//       }

//       const result = await userService.switchUserRole(userId, role, req.user);

//       return successResponse(res, result, "Role switched successfully");
//     } catch (error) {
//       logger.error("Error switching user role:", error);
//       next(error);
//     }
//   }

//   // Add new role to user (admin only)
//   async addRole(req, res, next) {
//     try {
//       const { userId } = req.params;
//       const roleData = req.body;

//       // Validate required fields
//       if (!roleData.role) {
//         throw new AppError("errors.role_required", 400);
//       }

//       const result = await userService.addUserRole(userId, roleData, req.user);

//       return successResponse(res, result, "Role added successfully");
//     } catch (error) {
//       logger.error("Error adding user role:", error);
//       next(error);
//     }
//   }

//   // Remove role from user (admin only)
//   async removeRole(req, res, next) {
//     try {
//       const { userId, role } = req.params;

//       const result = await userService.removeUserRole(userId, role, req.user);

//       return successResponse(res, result, "Role removed successfully");
//     } catch (error) {
//       logger.error("Error removing user role:", error);
//       next(error);
//     }
//   }

//   // Get user points summary
//   async getPointsSummary(req, res, next) {
//     try {
//       const userId = req.params.userId || req.user._id;
//       const { role } = req.query;

//       const pointsSummary = await userService.getUserPointsSummary(
//         userId,
//         role,
//         req.user
//       );

//       return successResponse(
//         res,
//         pointsSummary,
//         "Points summary retrieved successfully"
//       );
//     } catch (error) {
//       logger.error("Error getting points summary:", error);
//       next(error);
//     }
//   }

//   // Get user statistics
//   async getUserStatistics(req, res, next) {
//     try {
//       const userId = req.params.userId || req.user._id;

//       const statistics = await userService.getUserStatistics(userId, req.user);

//       return successResponse(
//         res,
//         statistics,
//         "User statistics retrieved successfully"
//       );
//     } catch (error) {
//       logger.error("Error getting user statistics:", error);
//       next(error);
//     }
//   }

//   // Update user addresses
//   async updateAddresses(req, res, next) {
//     try {
//       const userId = req.user._id;
//       const { addresses } = req.body;

//       if (!addresses || !Array.isArray(addresses)) {
//         throw new AppError("errors.invalid_addresses_format", 400);
//       }

//       // Validate addresses
//       for (const address of addresses) {
//         if (!address.street || !address.city || !address.province) {
//           throw new AppError("errors.incomplete_address", 400);
//         }

//         if (address.coordinates && address.coordinates.coordinates) {
//           const [lng, lat] = address.coordinates.coordinates;
//           if (typeof lng !== 'number' || typeof lat !== 'number') {
//             throw new AppError("errors.invalid_coordinates_format", 400);
//           }
//         }
//       }

//       const updatedProfile = await userService.updateUserProfile(
//         userId,
//         { addresses },
//         req.user
//       );

//       return successResponse(
//         res,
//         updatedProfile.addresses,
//         "Addresses updated successfully"
//       );
//     } catch (error) {
//       logger.error("Error updating addresses:", error);
//       next(error);
//     }
//   }

//   // Update preferences
//   async updatePreferences(req, res, next) {
//     try {
//       const userId = req.user._id;
//       const { preferences } = req.body;

//       if (!preferences) {
//         throw new AppError("errors.preferences_required", 400);
//       }

//       const updatedProfile = await userService.updateUserProfile(
//         userId,
//         { preferences },
//         req.user
//       );

//       return successResponse(
//         res,
//         updatedProfile.preferences,
//         "Preferences updated successfully"
//       );
//     } catch (error) {
//       logger.error("Error updating preferences:", error);
//       next(error);
//     }
//   }

//   // Update role-specific data
//   async updateRoleData(req, res, next) {
//     try {
//       const userId = req.user._id;
//       const { role, data } = req.body;

//       if (!role || !data) {
//         throw new AppError("errors.role_data_required", 400);
//       }

//       // Validate role-specific data
//       if ((role === "rt" || role === "rw") && !data.rtNumber) {
//         throw new AppError("errors.rt_number_required", 400);
//       }

//       if (role === "collector" && !data.businessName) {
//         throw new AppError("errors.business_name_required", 400);
//       }

//       const updatedProfile = await userService.updateUserProfile(
//         userId,
//         { roleData: { role, data } },
//         req.user
//       );

//       return successResponse(
//         res,
//         updatedProfile,
//         "Role data updated successfully"
//       );
//     } catch (error) {
//       logger.error("Error updating role data:", error);
//       next(error);
//     }
//   }

//   // Deactivate user account
//   async deactivateUser(req, res, next) {
//     try {
//       const { userId } = req.params;
//       const { reason } = req.body;

//       const result = await userService.deactivateUser(userId, req.user, reason);

//       return successResponse(res, result, "User deactivated successfully");
//     } catch (error) {
//       logger.error("Error deactivating user:", error);
//       next(error);
//     }
//   }

//   // Reactivate user account (admin only)
//   async reactivateUser(req, res, next) {
//     try {
//       const { userId } = req.params;

//       const result = await userService.reactivateUser(userId, req.user);

//       return successResponse(res, result, "User reactivated successfully");
//     } catch (error) {
//       logger.error("Error reactivating user:", error);
//       next(error);
//     }
//   }

//   // Admin: Get user management dashboard data
//   async getUserManagementData(req, res, next) {
//     try {
//       // Check admin permission
//       if (!req.user.hasRole("admin")) {
//         throw new AppError("errors.insufficient_permissions", 403);
//       }

//       const {
//         timeframe = "month",
//         includeInactive = false,
//       } = req.query;

//       // Get user statistics by role
//       const roles = ["individual", "rt", "rw", "collector"];
//       const usersByRole = {};

//       for (const role of roles) {
//         const users = await userService.getUsersByRole(role, {
//           isActive: includeInactive ? undefined : true,
//         }, {
//           limit: 100,
//         });
//         usersByRole[role] = users.pagination.totalItems;
//       }

//       // Get recent registrations
//       const thirtyDaysAgo = new Date();
//       thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

//       const recentUsers = await userService.searchUsers({
//         isActive: true,
//       }, {
//         limit: 10,
//         sort: "createdAt",
//         order: "desc",
//       }, req.user);

//       const dashboardData = {
//         summary: {
//           totalUsers: Object.values(usersByRole).reduce((sum, count) => sum + count, 0),
//           usersByRole,
//           recentRegistrations: recentUsers.pagination.totalItems,
//         },
//         recentUsers: recentUsers.users,
//         timeframe,
//       };

//       return successResponse(
//         res,
//         dashboardData,
//         "User management data retrieved successfully"
//       );
//     } catch (error) {
//       logger.error("Error getting user management data:", error);
//       next(error);
//     }
//   }

//   // Get user's addresses
//   async getAddresses(req, res, next) {
//     try {
//       const userId = req.user._id;

//       const user = await userService.getUserById(userId, { addresses: true });

//       return successResponse(
//         res,
//         user.addresses || [],
//         "Addresses retrieved successfully"
//       );
//     } catch (error) {
//       logger.error("Error getting addresses:", error);
//       next(error);
//     }
//   }

//   // Add new address
//   async addAddress(req, res, next) {
//     try {
//       const userId = req.user._id;
//       const newAddress = req.body;

//       // Validate required fields
//       const requiredFields = ["street", "village", "district", "city", "province", "postalCode"];
//       for (const field of requiredFields) {
//         if (!newAddress[field]) {
//           throw new AppError("errors.missing_required_field", 400, { field });
//         }
//       }

//       // Validate coordinates if provided
//       if (newAddress.coordinates && newAddress.coordinates.coordinates) {
//         const [lng, lat] = newAddress.coordinates.coordinates;
//         if (typeof lng !== 'number' || typeof lat !== 'number') {
//           throw new AppError("errors.invalid_coordinates_format", 400);
//         }
//       }

//       // Get current addresses
//       const user = await userService.getUserById(userId, { addresses: true });
//       const currentAddresses = user.addresses || [];

//       // Add new address
//       const updatedAddresses = [...currentAddresses, newAddress];

//       const updatedProfile = await userService.updateUserProfile(
//         userId,
//         { addresses: updatedAddresses },
//         req.user
//       );

//       return successResponse(
//         res,
//         updatedProfile.addresses,
//         "Address added successfully"
//       );
//     } catch (error) {
//       logger.error("Error adding address:", error);
//       next(error);
//     }
//   }

//   // Update specific address
//   async updateAddress(req, res, next) {
//     try {
//       const userId = req.user._id;
//       const { addressIndex } = req.params;
//       const updatedAddress = req.body;

//       const index = parseInt(addressIndex);
//       if (isNaN(index) || index < 0) {
//         throw new AppError("errors.invalid_address_index", 400);
//       }

//       // Get current addresses
//       const user = await userService.getUserById(userId, { addresses: true });
//       const currentAddresses = user.addresses || [];

//       if (index >= currentAddresses.length) {
//         throw new AppError("errors.address_not_found", 404);
//       }

//       // Update the address
//       currentAddresses[index] = { ...currentAddresses[index], ...updatedAddress };

//       const updatedProfile = await userService.updateUserProfile(
//         userId,
//         { addresses: currentAddresses },
//         req.user
//       );

//       return successResponse(
//         res,
//         updatedProfile.addresses,
//         "Address updated successfully"
//       );
//     } catch (error) {
//       logger.error("Error updating address:", error);
//       next(error);
//     }
//   }

//   // Delete address
//   async deleteAddress(req, res, next) {
//     try {
//       const userId = req.user._id;
//       const { addressIndex } = req.params;

//       const index = parseInt(addressIndex);
//       if (isNaN(index) || index < 0) {
//         throw new AppError("errors.invalid_address_index", 400);
//       }

//       // Get current addresses
//       const user = await userService.getUserById(userId, { addresses: true });
//       const currentAddresses = user.addresses || [];

//       if (index >= currentAddresses.length) {
//         throw new AppError("errors.address_not_found", 404);
//       }

//       // Cannot delete if it's the only address
//       if (currentAddresses.length === 1) {
//         throw new AppError("errors.cannot_delete_last_address", 400);
//       }

//       // Remove the address
//       currentAddresses.splice(index, 1);

//       // If deleted address was default, make first address default
//       const hasDefault = currentAddresses.some(addr => addr.isDefault);
//       if (!hasDefault && currentAddresses.length > 0) {
//         currentAddresses[0].isDefault = true;
//       }

//       const updatedProfile = await userService.updateUserProfile(
//         userId,
//         { addresses: currentAddresses },
//         req.user
//       );

//       return successResponse(
//         res,
//         updatedProfile.addresses,
//         "Address deleted successfully"
//       );
//     } catch (error) {
//       logger.error("Error deleting address:", error);
//       next(error);
//     }
//   }
// }

// // Create singleton instance
// const userController = new UserController();

// export default userController;
import userService from "../services/userService.js";
import { createLogger } from "../utils/logger.js";
import { AppError } from "../middlewares/errorMiddleware.js";

const logger = createLogger("UserController");

class UserController {
  // Get current user profile
  async getProfile(req, res, next) {
    try {
      const userId = req.user._id;
      const { role } = req.query; // Optional: get profile for specific role

      const profile = await userService.getUserProfile(userId, role);

      return res.status(200).json({
        success: true,
        message: "Profile retrieved successfully",
        data: profile,
      });
    } catch (error) {
      logger.error("Error getting user profile:", error);
      next(error);
    }
  }

  // Update current user profile
  async updateProfile(req, res, next) {
    try {
      const userId = req.user._id;
      const updateData = req.body;

      // Validate required fields if provided
      if (
        updateData.email &&
        !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(updateData.email)
      ) {
        throw new AppError("errors.invalid_email_format", 400);
      }

      if (
        updateData.phone &&
        !/^(\+62|62|0)[0-9]{9,13}$/.test(updateData.phone)
      ) {
        throw new AppError("errors.invalid_phone_format", 400);
      }

      const updatedProfile = await userService.updateUserProfile(
        userId,
        updateData,
        req.user
      );

      return res.status(200).json({
        success: true,
        message: "Profile updated successfully",
        data: updatedProfile,
      });
    } catch (error) {
      logger.error("Error updating user profile:", error);
      next(error);
    }
  }

  // Get user by ID (admin or public info)
  async getUserById(req, res, next) {
    try {
      const { userId } = req.params;
      const { populate } = req.query;

      // Parse populate options
      const populateOptions = {};
      if (populate) {
        const options = populate.split(",");
        options.forEach((option) => {
          populateOptions[option.trim()] = true;
        });
      }

      const user = await userService.getUserById(userId, populateOptions);

      // Check if current user can view this profile
      const isOwner = req.user._id.toString() === userId;
      const isAdmin = req.user.hasRole("admin");

      if (!isOwner && !isAdmin) {
        // Return limited public info for non-owners
        const publicUser = {
          _id: user._id,
          name: user.name,
          avatar: user.avatar,
          currentRole: user.currentRole,
          memberSince: user.createdAt,
          isActive: user.isActive,
        };

        return res.status(200).json({
          success: true,
          message: "User retrieved successfully",
          data: publicUser,
        });
      }

      return res.status(200).json({
        success: true,
        message: "User retrieved successfully",
        data: user,
      });
    } catch (error) {
      logger.error("Error getting user by ID:", error);
      next(error);
    }
  }

  // Search users with filters
  async searchUsers(req, res, next) {
    try {
      const {
        q,
        role,
        isActive,
        isEmailVerified,
        city,
        province,
        rating,
        lat,
        lng,
        radius,
        page,
        limit,
        sort,
        order,
      } = req.query;

      const filters = {
        q,
        role,
        isActive: isActive !== undefined ? isActive === "true" : undefined,
        isEmailVerified:
          isEmailVerified !== undefined
            ? isEmailVerified === "true"
            : undefined,
        city,
        province,
        rating: rating ? parseFloat(rating) : undefined,
        nearCoordinates:
          lat && lng ? [parseFloat(lng), parseFloat(lat)] : undefined,
        radius: radius ? parseInt(radius) : 10,
      };

      const pagination = {
        page: page ? parseInt(page) : 1,
        limit: limit ? parseInt(limit) : 20,
        sort: sort || "createdAt",
        order: order || "desc",
      };

      const result = await userService.searchUsers(
        filters,
        pagination,
        req.user
      );

      return res.status(200).json({
        success: true,
        message: "Users retrieved successfully",
        data: result,
      });
    } catch (error) {
      logger.error("Error searching users:", error);
      next(error);
    }
  }

  // Get users by specific role
  async getUsersByRole(req, res, next) {
    try {
      const { role } = req.params;
      const {
        city,
        province,
        rating,
        lat,
        lng,
        radius,
        page,
        limit,
        sort,
        order,
      } = req.query;

      // Validate role
      const validRoles = ["individual", "rt", "rw", "collector", "admin"];
      if (!validRoles.includes(role)) {
        throw new AppError("errors.invalid_role", 400, { role });
      }

      const filters = {
        city,
        province,
        rating: rating ? parseFloat(rating) : undefined,
        nearCoordinates:
          lat && lng ? [parseFloat(lng), parseFloat(lat)] : undefined,
        radius: radius ? parseInt(radius) : 10,
      };

      const pagination = {
        page: page ? parseInt(page) : 1,
        limit: limit ? parseInt(limit) : 20,
        sort: sort || "createdAt",
        order: order || "desc",
      };

      const result = await userService.getUsersByRole(
        role,
        filters,
        pagination
      );

      return res.status(200).json({
        success: true,
        message: `${role} users retrieved successfully`,
        data: result,
      });
    } catch (error) {
      logger.error(`Error getting users by role:`, error);
      next(error);
    }
  }

  // Find nearby users
  async findNearbyUsers(req, res, next) {
    try {
      const { lat, lng, role, radius } = req.query;

      if (!lat || !lng) {
        throw new AppError("errors.coordinates_required", 400);
      }

      const coordinates = [parseFloat(lng), parseFloat(lat)];
      const searchRadius = radius ? parseInt(radius) : 10;

      const nearbyUsers = await userService.findNearbyUsers(
        coordinates,
        role,
        searchRadius
      );

      return res.status(200).json({
        success: true,
        message: "Nearby users retrieved successfully",
        data: { users: nearbyUsers, radius: searchRadius },
      });
    } catch (error) {
      logger.error("Error finding nearby users:", error);
      next(error);
    }
  }

  // Switch user role
  async switchRole(req, res, next) {
    try {
      const userId = req.user._id;
      const { role } = req.body;

      if (!role) {
        throw new AppError("errors.role_required", 400);
      }

      const result = await userService.switchUserRole(userId, role, req.user);

      return res.status(200).json({
        success: true,
        message: "Role switched successfully",
        data: result,
      });
    } catch (error) {
      logger.error("Error switching user role:", error);
      next(error);
    }
  }

  // Add new role to user (admin only)
  async addRole(req, res, next) {
    try {
      const { userId } = req.params;
      const roleData = req.body;

      // Validate required fields
      if (!roleData.role) {
        throw new AppError("errors.role_required", 400);
      }

      const result = await userService.addUserRole(userId, roleData, req.user);

      return res.status(200).json({
        success: true,
        message: "Role added successfully",
        data: result,
      });
    } catch (error) {
      logger.error("Error adding user role:", error);
      next(error);
    }
  }

  // Remove role from user (admin only)
  async removeRole(req, res, next) {
    try {
      const { userId, role } = req.params;

      const result = await userService.removeUserRole(userId, role, req.user);

      return res.status(200).json({
        success: true,
        message: "Role removed successfully",
        data: result,
      });
    } catch (error) {
      logger.error("Error removing user role:", error);
      next(error);
    }
  }

  // Get user points summary
  async getPointsSummary(req, res, next) {
    try {
      const userId = req.params.userId || req.user._id;
      const { role } = req.query;

      const pointsSummary = await userService.getUserPointsSummary(
        userId,
        role,
        req.user
      );

      return res.status(200).json({
        success: true,
        message: "Points summary retrieved successfully",
        data: pointsSummary,
      });
    } catch (error) {
      logger.error("Error getting points summary:", error);
      next(error);
    }
  }

  // Get user statistics
  async getUserStatistics(req, res, next) {
    try {
      const userId = req.params.userId || req.user._id;

      console.log("Fetching statistics for user:", userId);

      const statistics = await userService.getUserStatistics(userId, req.user);

      return res.status(200).json({
        success: true,
        message: "User statistics retrieved successfully",
        data: statistics,
      });
    } catch (error) {
      logger.error("Error getting user statistics:", error);
      next(error);
    }
  }

  // Update user addresses
  async updateAddresses(req, res, next) {
    try {
      const userId = req.user._id;
      const { addresses } = req.body;

      if (!addresses || !Array.isArray(addresses)) {
        throw new AppError("errors.invalid_addresses_format", 400);
      }

      // Validate addresses
      for (const address of addresses) {
        if (!address.street || !address.city || !address.province) {
          throw new AppError("errors.incomplete_address", 400);
        }

        if (address.coordinates && address.coordinates.coordinates) {
          const [lng, lat] = address.coordinates.coordinates;
          if (typeof lng !== "number" || typeof lat !== "number") {
            throw new AppError("errors.invalid_coordinates_format", 400);
          }
        }
      }

      const updatedProfile = await userService.updateUserProfile(
        userId,
        { addresses },
        req.user
      );

      return res.status(200).json({
        success: true,
        message: "Addresses updated successfully",
        data: updatedProfile.addresses,
      });
    } catch (error) {
      logger.error("Error updating addresses:", error);
      next(error);
    }
  }

  // Update preferences
  async updatePreferences(req, res, next) {
    try {
      const userId = req.user._id;
      const { preferences } = req.body;

      if (!preferences) {
        throw new AppError("errors.preferences_required", 400);
      }

      const updatedProfile = await userService.updateUserProfile(
        userId,
        { addresses: updatedAddresses },
        req.user
      );

      return res.status(200).json({
        success: true,
        message: "Address added successfully",
        data: updatedProfile.addresses,
      });
    } catch (error) {
      logger.error("Error adding address:", error);
      next(error);
    }
  }

  // Update role-specific data
  async updateRoleData(req, res, next) {
    try {
      const userId = req.user._id;
      const { role, data } = req.body;

      if (!role || !data) {
        throw new AppError("errors.role_data_required", 400);
      }

      // Validate role-specific data
      if ((role === "rt" || role === "rw") && !data.rtNumber) {
        throw new AppError("errors.rt_number_required", 400);
      }

      if (role === "collector" && !data.businessName) {
        throw new AppError("errors.business_name_required", 400);
      }

      const updatedProfile = await userService.updateUserProfile(
        userId,
        { roleData: { role, data } },
        req.user
      );

      return res.status(200).json({
        success: true,
        message: "Role data updated successfully",
        data: updatedProfile,
      });
    } catch (error) {
      logger.error("Error updating role data:", error);
      next(error);
    }
  }

  // Deactivate user account
  async deactivateUser(req, res, next) {
    try {
      const { userId } = req.params;
      const { reason } = req.body;

      const result = await userService.deactivateUser(userId, req.user, reason);

      return res.status(200).json({
        success: true,
        message: "User deactivated successfully",
        data: result,
      });
    } catch (error) {
      logger.error("Error deactivating user:", error);
      next(error);
    }
  }
  // Reactivate user account (admin only)
  async reactivateUser(req, res, next) {
    try {
      const { userId } = req.params;

      const result = await userService.reactivateUser(userId, req.user);

      return res.status(200).json({
        success: true,
        message: "User reactivated successfully",
        data: result,
      });
    } catch (error) {
      logger.error("Error reactivating user:", error);
      next(error);
    }
  }

  // Admin: Get user management dashboard data
  async getUserManagementData(req, res, next) {
    try {
      // Check admin permission
      if (!req.user.hasRole("admin")) {
        throw new AppError("errors.insufficient_permissions", 403);
      }

      const { timeframe = "month", includeInactive = false } = req.query;

      // Get user statistics by role
      const roles = ["individual", "rt", "rw", "collector"];
      const usersByRole = {};

      for (const role of roles) {
        const users = await userService.getUsersByRole(
          role,
          {
            isActive: includeInactive ? undefined : true,
          },
          {
            limit: 100,
          }
        );
        usersByRole[role] = users.pagination.totalItems;
      }

      // Get recent registrations
      const thirtyDaysAgo = new Date();
      thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

      const recentUsers = await userService.searchUsers(
        {
          isActive: true,
        },
        {
          limit: 10,
          sort: "createdAt",
          order: "desc",
        },
        req.user
      );

      const dashboardData = {
        summary: {
          totalUsers: Object.values(usersByRole).reduce(
            (sum, count) => sum + count,
            0
          ),
          usersByRole,
          recentRegistrations: recentUsers.pagination.totalItems,
        },
        recentUsers: recentUsers.users,
        timeframe,
      };

      return res.status(200).json({
        success: true,
        message: "User management data retrieved successfully",
        data: dashboardData,
      });
    } catch (error) {
      logger.error("Error getting user management data:", error);
      next(error);
    }
  }

  // Get user's addresses
  async getAddresses(req, res, next) {
    try {
      const userId = req.user._id;

      const user = await userService.getUserById(userId, { addresses: true });

      return res.status(200).json({
        success: true,
        message: "Addresses retrieved successfully",
        data: user.addresses || [],
      });
    } catch (error) {
      logger.error("Error getting addresses:", error);
      next(error);
    }
  }

  // Add new address
  // Add new address
  async addAddress(req, res, next) {
    try {
      const userId = req.user._id;
      const newAddress = req.body;

      // Validate required fields
      const requiredFields = [
        "street",
        "village",
        "district",
        "city",
        "province",
        "postalCode",
      ];
      for (const field of requiredFields) {
        if (!newAddress[field]) {
          throw new AppError("errors.missing_required_field", 400, { field });
        }
      }

      // Validate coordinates if provided
      if (newAddress.coordinates && newAddress.coordinates.coordinates) {
        const [lng, lat] = newAddress.coordinates.coordinates;
        if (typeof lng !== "number" || typeof lat !== "number") {
          throw new AppError("errors.invalid_coordinates_format", 400);
        }
      }

      // Get current addresses
      const user = await userService.getUserById(userId, { addresses: true });
      const currentAddresses = user.addresses || [];

      // Add new address
      const updatedAddresses = [...currentAddresses, newAddress];

      const updatedProfile = await userService.updateUserProfile(
        userId,
        { addresses: updatedAddresses },
        req.user
      );

      return res.status(200).json({
        success: true,
        message: "Address added successfully",
        data: updatedProfile.addresses,
      });
    } catch (error) {
      logger.error("Error adding address:", error);
      next(error);
    }
  }

  // Update specific address
  async updateAddress(req, res, next) {
    try {
      const userId = req.user._id;
      const { addressIndex } = req.params;
      const updatedAddress = req.body;

      const index = parseInt(addressIndex);
      if (isNaN(index) || index < 0) {
        throw new AppError("errors.invalid_address_index", 400);
      }

      // Get current addresses
      const user = await userService.getUserById(userId, { addresses: true });
      const currentAddresses = user.addresses || [];

      if (index >= currentAddresses.length) {
        throw new AppError("errors.address_not_found", 404);
      }

      // Update the address
      currentAddresses[index] = {
        ...currentAddresses[index],
        ...updatedAddress,
      };

      const updatedProfile = await userService.updateUserProfile(
        userId,
        { addresses: currentAddresses },
        req.user
      );

      return res.status(200).json({
        success: true,
        message: "Address updated successfully",
        data: updatedProfile.addresses,
      });
    } catch (error) {
      logger.error("Error updating address:", error);
      next(error);
    }
  }

  // Delete address
  async deleteAddress(req, res, next) {
    try {
      const userId = req.user._id;
      const { addressIndex } = req.params;

      const index = parseInt(addressIndex);
      if (isNaN(index) || index < 0) {
        throw new AppError("errors.invalid_address_index", 400);
      }

      // Get current addresses
      const user = await userService.getUserById(userId, { addresses: true });
      const currentAddresses = user.addresses || [];

      if (index >= currentAddresses.length) {
        throw new AppError("errors.address_not_found", 404);
      }

      // Cannot delete if it's the only address
      if (currentAddresses.length === 1) {
        throw new AppError("errors.cannot_delete_last_address", 400);
      }

      // Remove the address
      currentAddresses.splice(index, 1);

      // If deleted address was default, make first address default
      const hasDefault = currentAddresses.some((addr) => addr.isDefault);
      if (!hasDefault && currentAddresses.length > 0) {
        currentAddresses[0].isDefault = true;
      }

      const updatedProfile = await userService.updateUserProfile(
        userId,
        { addresses: currentAddresses },
        req.user
      );

      return res.status(200).json({
        success: true,
        message: "Address deleted successfully",
        data: updatedProfile.addresses,
      });
    } catch (error) {
      logger.error("Error deleting address:", error);
      next(error);
    }
  }
}

// Create singleton instance
const userController = new UserController();

export default userController;

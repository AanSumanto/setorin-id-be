import mongoose from "mongoose";

const imageSchema = new mongoose.Schema(
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
    isPrimary: {
      type: Boolean,
      default: false,
    },
  },
  { _id: false }
);

// Barang Rongsok specific fields
const scrapMetalDataSchema = new mongoose.Schema(
  {
    metalType: {
      type: String,
      enum: ["aluminum", "copper", "iron", "steel", "brass", "bronze", "other"],
      required: function () {
        return this.type === "scrap_metal";
      },
    },
    condition: {
      type: String,
      enum: ["excellent", "good", "fair", "poor"],
      required: function () {
        return this.category === "scrap";
      },
    },
    estimatedWeight: {
      type: Number,
      required: function () {
        return this.category === "scrap";
      },
      min: [0.1, "Weight must be at least 0.1 kg"],
    },
    actualWeight: {
      type: Number,
      min: 0,
    },
    pricePerKg: {
      type: Number,
      required: function () {
        return this.category === "scrap";
      },
      min: 0,
    },
  },
  { _id: false }
);

// Minyak Jelantah specific fields
const cookingOilDataSchema = new mongoose.Schema(
  {
    volume: {
      type: Number,
      required: function () {
        return this.category === "cooking_oil";
      },
      min: [1, "Minimum volume is 1 liter"],
    },
    quality: {
      type: String,
      enum: ["grade_a", "grade_b", "grade_c"],
      required: function () {
        return this.category === "cooking_oil";
      },
    },
    containerType: {
      type: String,
      enum: ["plastic_bottle", "jerry_can", "drum", "other"],
      default: "plastic_bottle",
    },
    filterStatus: {
      type: String,
      enum: ["filtered", "unfiltered", "partially_filtered"],
      default: "unfiltered",
    },
    pricePerLiter: {
      type: Number,
      default: 4000, // Base price from business logic
    },
  },
  { _id: false }
);

const productSchema = new mongoose.Schema(
  {
    // Basic Information
    title: {
      type: String,
      required: [true, "Product title is required"],
      trim: true,
      minlength: [5, "Title must be at least 5 characters"],
      maxlength: [200, "Title cannot exceed 200 characters"],
    },
    description: {
      type: String,
      required: [true, "Product description is required"],
      trim: true,
      minlength: [10, "Description must be at least 10 characters"],
      maxlength: [1000, "Description cannot exceed 1000 characters"],
    },

    // Product Category
    category: {
      type: String,
      enum: {
        values: ["scrap", "cooking_oil"],
        message: "Category must be either scrap or cooking_oil",
      },
      required: [true, "Product category is required"],
    },

    // Product Type (subcategory)
    type: {
      type: String,
      enum: {
        values: [
          // Scrap types
          "scrap_metal",
          "scrap_plastic",
          "scrap_paper",
          "scrap_electronics",
          "scrap_glass",
          "scrap_other",
          // Cooking oil type
          "used_cooking_oil",
        ],
        message: "Invalid product type",
      },
      required: [true, "Product type is required"],
    },

    // Owner Information
    owner: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: [true, "Product owner is required"],
    },

    // Location
    location: {
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
          min: -90,
          max: 90,
        },
        longitude: {
          type: Number,
          required: true,
          min: -180,
          max: 180,
        },
      },
    },

    // Images
    images: {
      type: [imageSchema],
      validate: {
        validator: function (images) {
          return images.length >= 1 && images.length <= 10;
        },
        message: "Product must have between 1 and 10 images",
      },
    },

    // Category-specific data
    scrapData: {
      type: scrapMetalDataSchema,
      required: function () {
        return this.category === "scrap";
      },
    },
    cookingOilData: {
      type: cookingOilDataSchema,
      required: function () {
        return this.category === "cooking_oil";
      },
    },

    // Pricing
    estimatedPrice: {
      type: Number,
      min: 0,
    },
    finalPrice: {
      type: Number,
      min: 0,
    },

    // Status
    status: {
      type: String,
      enum: {
        values: ["draft", "active", "reserved", "sold", "cancelled", "expired"],
        message: "Invalid product status",
      },
      default: "active",
    },

    // Availability
    isAvailable: {
      type: Boolean,
      default: true,
    },
    expiresAt: {
      type: Date,
      default: function () {
        // Auto expire after 30 days
        return new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
      },
    },

    // Interaction stats
    views: {
      type: Number,
      default: 0,
    },
    favorites: [
      {
        user: {
          type: mongoose.Schema.Types.ObjectId,
          ref: "User",
        },
        createdAt: {
          type: Date,
          default: Date.now,
        },
      },
    ],

    // Quality assurance
    isQualityChecked: {
      type: Boolean,
      default: false,
    },
    qualityCheckNotes: String,
    qualityRating: {
      type: Number,
      min: 1,
      max: 5,
    },

    // Business logic flags
    meetMinimumRequirement: {
      type: Boolean,
      default: function () {
        if (this.category === "scrap" && this.scrapData) {
          return (
            this.scrapData.estimatedWeight >=
            (process.env.MIN_SCRAP_WEIGHT || 5)
          );
        }
        if (this.category === "cooking_oil" && this.cookingOilData) {
          return (
            this.cookingOilData.volume >=
            (process.env.MIN_COOKING_OIL_VOLUME || 1)
          );
        }
        return false;
      },
    },

    // Tags for search
    tags: [
      {
        type: String,
        trim: true,
        lowercase: true,
      },
    ],

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
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
  }
);

// Indexes for performance
productSchema.index({ category: 1, status: 1 });
productSchema.index({ owner: 1 });
productSchema.index({ "location.coordinates": "2dsphere" }); // for geospatial queries
productSchema.index({ status: 1, isAvailable: 1 });
productSchema.index({ expiresAt: 1 }); // for TTL functionality
productSchema.index({ createdAt: -1 });
productSchema.index({ tags: 1 });

// Virtual for primary image
productSchema.virtual("primaryImage").get(function () {
  const primaryImg = this.images.find((img) => img.isPrimary);
  return primaryImg || this.images[0] || null;
});

// Virtual for favorite count
productSchema.virtual("favoriteCount").get(function () {
  return this.favorites.length;
});

// Virtual for calculated price
productSchema.virtual("calculatedPrice").get(function () {
  if (this.category === "scrap" && this.scrapData) {
    const weight =
      this.scrapData.actualWeight || this.scrapData.estimatedWeight;
    return weight * this.scrapData.pricePerKg;
  }
  if (this.category === "cooking_oil" && this.cookingOilData) {
    return this.cookingOilData.volume * this.cookingOilData.pricePerLiter;
  }
  return this.estimatedPrice || 0;
});

// Pre-save middleware
productSchema.pre("save", function (next) {
  // Ensure only one primary image
  if (this.images.length > 0) {
    const primaryImages = this.images.filter((img) => img.isPrimary);
    if (primaryImages.length === 0) {
      this.images[0].isPrimary = true;
    } else if (primaryImages.length > 1) {
      let firstPrimary = true;
      this.images.forEach((img) => {
        if (img.isPrimary && firstPrimary) {
          firstPrimary = false;
        } else if (img.isPrimary) {
          img.isPrimary = false;
        }
      });
    }
  }

  // Auto-generate tags based on content
  this.tags = [];
  if (this.title) {
    this.tags.push(
      ...this.title
        .toLowerCase()
        .split(" ")
        .filter((word) => word.length > 2)
    );
  }
  if (this.type) {
    this.tags.push(this.type.replace("_", " "));
  }
  if (this.category) {
    this.tags.push(this.category.replace("_", " "));
  }

  // Remove duplicates
  this.tags = [...new Set(this.tags)];

  // Update estimated price
  this.estimatedPrice = this.calculatedPrice;

  next();
});

// Pre middleware for updateOne, updateMany, findOneAndUpdate
productSchema.pre(
  ["updateOne", "updateMany", "findOneAndUpdate"],
  function (next) {
    // Check if status is being updated to sold/cancelled
    const update = this.getUpdate();
    if (
      update.$set &&
      (update.$set.status === "sold" || update.$set.status === "cancelled")
    ) {
      update.$set.isAvailable = false;
    }
    next();
  }
);

// Instance methods
productSchema.methods.incrementViews = function () {
  this.views += 1;
  return this.save({ validateBeforeSave: false });
};

productSchema.methods.addToFavorites = function (userId) {
  if (
    !this.favorites.some((fav) => fav.user.toString() === userId.toString())
  ) {
    this.favorites.push({ user: userId });
    return this.save({ validateBeforeSave: false });
  }
  return Promise.resolve(this);
};

productSchema.methods.removeFromFavorites = function (userId) {
  this.favorites = this.favorites.filter(
    (fav) => fav.user.toString() !== userId.toString()
  );
  return this.save({ validateBeforeSave: false });
};

productSchema.methods.markAsReserved = function (buyerId) {
  this.status = "reserved";
  this.isAvailable = false;
  this.reservedBy = buyerId;
  this.reservedAt = new Date();
  return this.save();
};

productSchema.methods.markAsSold = function (finalPrice, buyerId) {
  this.status = "sold";
  this.isAvailable = false;
  this.finalPrice = finalPrice;
  this.soldTo = buyerId;
  this.soldAt = new Date();
  return this.save();
};

// Static methods
productSchema.statics.findNearby = function (
  coordinates,
  radiusInKm = 10,
  filters = {}
) {
  const query = {
    "location.coordinates": {
      $near: {
        $geometry: {
          type: "Point",
          coordinates: [coordinates.longitude, coordinates.latitude],
        },
        $maxDistance: radiusInKm * 1000, // Convert km to meters
      },
    },
    status: "active",
    isAvailable: true,
    meetMinimumRequirement: true,
    ...filters,
  };

  return this.find(query)
    .populate("owner", "name avatar rating")
    .sort({ createdAt: -1 });
};

productSchema.statics.findByCategory = function (category, filters = {}) {
  const query = {
    category,
    status: "active",
    isAvailable: true,
    meetMinimumRequirement: true,
    ...filters,
  };

  return this.find(query)
    .populate("owner", "name avatar rating")
    .sort({ createdAt: -1 });
};

productSchema.statics.searchProducts = function (searchTerm, filters = {}) {
  const query = {
    $or: [
      { title: { $regex: searchTerm, $options: "i" } },
      { description: { $regex: searchTerm, $options: "i" } },
      { tags: { $in: [new RegExp(searchTerm, "i")] } },
    ],
    status: "active",
    isAvailable: true,
    meetMinimumRequirement: true,
    ...filters,
  };

  return this.find(query)
    .populate("owner", "name avatar rating")
    .sort({ createdAt: -1 });
};

// TTL index to automatically remove expired products
productSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

const Product = mongoose.model("Product", productSchema);

export default Product;

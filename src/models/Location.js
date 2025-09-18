import mongoose from "mongoose";

// Indonesian administrative divisions schema
const administrativeDivisionSchema = new mongoose.Schema(
  {
    // Province (Provinsi)
    province: {
      code: {
        type: String,
        required: true,
        uppercase: true,
      },
      name: {
        type: String,
        required: true,
        trim: true,
      },
    },

    // City/Regency (Kota/Kabupaten)
    city: {
      code: {
        type: String,
        required: true,
      },
      name: {
        type: String,
        required: true,
        trim: true,
      },
      type: {
        type: String,
        enum: ["kota", "kabupaten"],
        required: true,
      },
    },

    // District (Kecamatan)
    district: {
      code: {
        type: String,
        required: true,
      },
      name: {
        type: String,
        required: true,
        trim: true,
      },
    },

    // Village (Kelurahan/Desa)
    village: {
      code: {
        type: String,
        required: true,
      },
      name: {
        type: String,
        required: true,
        trim: true,
      },
      type: {
        type: String,
        enum: ["kelurahan", "desa"],
        required: true,
      },
    },

    // Postal code
    postalCode: {
      type: String,
      required: true,
      match: [/^\d{5}$/, "Postal code must be 5 digits"],
    },

    // Coordinates (centroid of the administrative area)
    coordinates: {
      type: {
        type: String,
        enum: ["Point"],
        default: "Point",
      },
      coordinates: {
        type: [Number], // [longitude, latitude]
        required: true,
        validate: {
          validator: function (coords) {
            return (
              coords.length === 2 &&
              coords[0] >= 95 &&
              coords[0] <= 141 && // Indonesia longitude range
              coords[1] >= -11 &&
              coords[1] <= 6
            ); // Indonesia latitude range
          },
          message: "Coordinates must be within Indonesia boundaries",
        },
      },
    },

    // Metadata
    isActive: {
      type: Boolean,
      default: true,
    },
    lastUpdated: {
      type: Date,
      default: Date.now,
    },
  },
  {
    timestamps: true,
  }
);

// Service coverage area schema
const serviceCoverageSchema = new mongoose.Schema(
  {
    // Service provider (RT, RW, Collector)
    serviceProvider: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },

    // Coverage type
    coverageType: {
      type: String,
      enum: {
        values: ["rt_area", "rw_area", "collector_radius", "custom_polygon"],
        message: "Invalid coverage type",
      },
      required: true,
    },

    // Administrative coverage (for RT/RW)
    administrativeCoverage: {
      province: String,
      city: String,
      district: String,
      villages: [String], // Array of village codes
      rtNumbers: [String], // For RW coverage
      rwNumber: String, // For RT coverage
    },

    // Radius coverage (for collectors)
    radiusCoverage: {
      center: {
        type: {
          type: String,
          enum: ["Point"],
          default: "Point",
        },
        coordinates: {
          type: [Number], // [longitude, latitude]
          required: function () {
            return this.coverageType === "collector_radius";
          },
        },
      },
      radius: {
        type: Number, // in kilometers
        min: 1,
        max: 50,
        required: function () {
          return this.coverageType === "collector_radius";
        },
      },
    },

    // Custom polygon coverage (for special cases)
    polygonCoverage: {
      type: {
        type: String,
        enum: ["Polygon"],
        default: "Polygon",
      },
      coordinates: {
        type: [[[Number]]], // GeoJSON polygon format
        required: function () {
          return this.coverageType === "custom_polygon";
        },
      },
    },

    // Service details
    services: [
      {
        type: String,
        enum: ["scrap_pickup", "cooking_oil_collection", "both"],
        default: "both",
      },
    ],

    // Schedule
    operatingHours: {
      monday: {
        start: String,
        end: String,
        isActive: { type: Boolean, default: true },
      },
      tuesday: {
        start: String,
        end: String,
        isActive: { type: Boolean, default: true },
      },
      wednesday: {
        start: String,
        end: String,
        isActive: { type: Boolean, default: true },
      },
      thursday: {
        start: String,
        end: String,
        isActive: { type: Boolean, default: true },
      },
      friday: {
        start: String,
        end: String,
        isActive: { type: Boolean, default: true },
      },
      saturday: {
        start: String,
        end: String,
        isActive: { type: Boolean, default: true },
      },
      sunday: {
        start: String,
        end: String,
        isActive: { type: Boolean, default: false },
      },
    },

    // Status
    isActive: {
      type: Boolean,
      default: true,
    },
    priority: {
      type: Number,
      default: 1,
      min: 1,
      max: 10, // Higher number = higher priority
    },
  },
  {
    timestamps: true,
  }
);

// Indexes for Administrative Divisions
administrativeDivisionSchema.index({ "province.code": 1, "city.code": 1 });
administrativeDivisionSchema.index({ "district.code": 1 });
administrativeDivisionSchema.index({ "village.code": 1 });
administrativeDivisionSchema.index({ postalCode: 1 });
administrativeDivisionSchema.index({ coordinates: "2dsphere" });

// Indexes for Service Coverage
serviceCoverageSchema.index({ serviceProvider: 1 });
serviceCoverageSchema.index({ coverageType: 1, isActive: 1 });
serviceCoverageSchema.index({ "radiusCoverage.center": "2dsphere" });
serviceCoverageSchema.index({ polygonCoverage: "2dsphere" });
serviceCoverageSchema.index({ services: 1, isActive: 1 });
serviceCoverageSchema.index({ priority: -1 });

// Static methods for Administrative Divisions
administrativeDivisionSchema.statics.findByPostalCode = function (postalCode) {
  return this.findOne({ postalCode, isActive: true });
};

administrativeDivisionSchema.statics.searchLocations = function (searchTerm) {
  const regex = new RegExp(searchTerm, "i");
  return this.find({
    $or: [
      { "province.name": regex },
      { "city.name": regex },
      { "district.name": regex },
      { "village.name": regex },
    ],
    isActive: true,
  }).limit(20);
};

administrativeDivisionSchema.statics.getProvinces = function () {
  return this.aggregate([
    { $match: { isActive: true } },
    { $group: { _id: "$province", count: { $sum: 1 } } },
    { $sort: { "_id.name": 1 } },
  ]);
};

administrativeDivisionSchema.statics.getCitiesByProvince = function (
  provinceCode
) {
  return this.aggregate([
    { $match: { "province.code": provinceCode, isActive: true } },
    { $group: { _id: "$city", count: { $sum: 1 } } },
    { $sort: { "_id.name": 1 } },
  ]);
};

administrativeDivisionSchema.statics.getDistrictsByCity = function (cityCode) {
  return this.aggregate([
    { $match: { "city.code": cityCode, isActive: true } },
    { $group: { _id: "$district", count: { $sum: 1 } } },
    { $sort: { "_id.name": 1 } },
  ]);
};

administrativeDivisionSchema.statics.getVillagesByDistrict = function (
  districtCode
) {
  return this.find({
    "district.code": districtCode,
    isActive: true,
  }).sort({ "village.name": 1 });
};

// Static methods for Service Coverage
serviceCoverageSchema.statics.findServiceProviders = function (
  coordinates,
  serviceType = "both"
) {
  const longitude = coordinates.longitude || coordinates[0];
  const latitude = coordinates.latitude || coordinates[1];

  return this.aggregate([
    {
      $match: {
        isActive: true,
        services: { $in: [serviceType, "both"] },
      },
    },
    {
      $addFields: {
        isInCoverage: {
          $switch: {
            branches: [
              {
                case: { $eq: ["$coverageType", "collector_radius"] },
                then: {
                  $lte: [
                    {
                      $multiply: [
                        {
                          $sqrt: {
                            $add: [
                              {
                                $pow: [
                                  {
                                    $subtract: [
                                      longitude,
                                      {
                                        $arrayElemAt: [
                                          "$radiusCoverage.center.coordinates",
                                          0,
                                        ],
                                      },
                                    ],
                                  },
                                  2,
                                ],
                              },
                              {
                                $pow: [
                                  {
                                    $subtract: [
                                      latitude,
                                      {
                                        $arrayElemAt: [
                                          "$radiusCoverage.center.coordinates",
                                          1,
                                        ],
                                      },
                                    ],
                                  },
                                  2,
                                ],
                              },
                            ],
                          },
                        },
                        111.32, // Approximate km per degree
                      ],
                    },
                    "$radiusCoverage.radius",
                  ],
                },
              },
            ],
            default: true,
          },
        },
      },
    },
    { $match: { isInCoverage: true } },
    {
      $lookup: {
        from: "users",
        localField: "serviceProvider",
        foreignField: "_id",
        as: "provider",
      },
    },
    { $unwind: "$provider" },
    { $sort: { priority: -1, "provider.rating.average": -1 } },
  ]);
};

serviceCoverageSchema.statics.checkCoverage = function (
  serviceProviderId,
  coordinates
) {
  return this.findOne({
    serviceProvider: serviceProviderId,
    isActive: true,
  }).then((coverage) => {
    if (!coverage) return false;

    if (coverage.coverageType === "collector_radius") {
      const distance = this.calculateDistance(
        coordinates,
        coverage.radiusCoverage.center.coordinates
      );
      return distance <= coverage.radiusCoverage.radius;
    }

    // For other coverage types, implement specific logic
    return true;
  });
};

// Helper method to calculate distance between two points
serviceCoverageSchema.statics.calculateDistance = function (coord1, coord2) {
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
  return R * c; // Distance in km
};

// Instance methods for Service Coverage
serviceCoverageSchema.methods.isOperating = function (dateTime = new Date()) {
  const day = dateTime.toLocaleDateString("en-US", { weekday: "lowercase" });
  const time = dateTime.toTimeString().substring(0, 5); // HH:MM format

  const schedule = this.operatingHours[day];
  if (!schedule || !schedule.isActive) return false;

  return time >= schedule.start && time <= schedule.end;
};

serviceCoverageSchema.methods.getNextOperatingTime = function (
  fromDateTime = new Date()
) {
  const days = [
    "sunday",
    "monday",
    "tuesday",
    "wednesday",
    "thursday",
    "friday",
    "saturday",
  ];
  let checkDate = new Date(fromDateTime);

  for (let i = 0; i < 7; i++) {
    const dayName = days[checkDate.getDay()];
    const schedule = this.operatingHours[dayName];

    if (schedule && schedule.isActive) {
      const [startHour, startMinute] = schedule.start.split(":").map(Number);
      const nextOperating = new Date(checkDate);
      nextOperating.setHours(startHour, startMinute, 0, 0);

      if (nextOperating > fromDateTime) {
        return nextOperating;
      }
    }

    checkDate.setDate(checkDate.getDate() + 1);
    checkDate.setHours(0, 0, 0, 0);
  }

  return null; // No operating hours found in next 7 days
};

// Location utility functions
const LocationUtils = {
  // Validate Indonesian coordinates
  isValidIndonesianCoordinates(longitude, latitude) {
    return (
      longitude >= 95 && longitude <= 141 && latitude >= -11 && latitude <= 6
    );
  },

  // Format Indonesian address
  formatIndonesianAddress(addressObj) {
    const parts = [];
    if (addressObj.street) parts.push(addressObj.street);
    if (addressObj.village) parts.push(addressObj.village);
    if (addressObj.district) parts.push(addressObj.district);
    if (addressObj.city) parts.push(addressObj.city);
    if (addressObj.province) parts.push(addressObj.province);
    if (addressObj.postalCode) parts.push(addressObj.postalCode);

    return parts.join(", ");
  },

  // Parse coordinates from various formats
  parseCoordinates(input) {
    if (Array.isArray(input) && input.length === 2) {
      return { longitude: input[0], latitude: input[1] };
    }
    if (input.longitude !== undefined && input.latitude !== undefined) {
      return { longitude: input.longitude, latitude: input.latitude };
    }
    if (input.lng !== undefined && input.lat !== undefined) {
      return { longitude: input.lng, latitude: input.lat };
    }
    throw new Error("Invalid coordinate format");
  },

  // Calculate bounding box for a center point and radius
  getBoundingBox(centerCoords, radiusKm) {
    const lat = centerCoords.latitude;
    const lng = centerCoords.longitude;
    const latDelta = radiusKm / 111.32; // km per degree latitude
    const lngDelta = radiusKm / (111.32 * Math.cos((lat * Math.PI) / 180)); // km per degree longitude

    return {
      north: lat + latDelta,
      south: lat - latDelta,
      east: lng + lngDelta,
      west: lng - lngDelta,
    };
  },

  // Generate GeoJSON point
  createGeoJSONPoint(longitude, latitude) {
    return {
      type: "Point",
      coordinates: [longitude, latitude],
    };
  },

  // Generate GeoJSON circle (approximated as polygon)
  createGeoJSONCircle(centerLng, centerLat, radiusKm, points = 32) {
    const coords = [];
    const earthRadius = 6371; // km

    for (let i = 0; i <= points; i++) {
      const angle = (i / points) * 2 * Math.PI;
      const dx = radiusKm * Math.cos(angle);
      const dy = radiusKm * Math.sin(angle);

      const lat = centerLat + (dy / earthRadius) * (180 / Math.PI);
      const lng =
        centerLng +
        ((dx / earthRadius) * (180 / Math.PI)) /
          Math.cos((centerLat * Math.PI) / 180);

      coords.push([lng, lat]);
    }

    return {
      type: "Polygon",
      coordinates: [coords],
    };
  },

  // Validate postal code format
  isValidPostalCode(postalCode) {
    return /^\d{5}$/.test(postalCode);
  },

  // Extract city type from name
  getCityType(cityName) {
    if (cityName.toLowerCase().startsWith("kota ")) {
      return { type: "kota", cleanName: cityName.substring(5) };
    }
    if (cityName.toLowerCase().startsWith("kabupaten ")) {
      return { type: "kabupaten", cleanName: cityName.substring(10) };
    }
    return { type: "unknown", cleanName: cityName };
  },

  // Extract village type from name
  getVillageType(villageName) {
    if (villageName.toLowerCase().startsWith("kelurahan ")) {
      return { type: "kelurahan", cleanName: villageName.substring(10) };
    }
    if (villageName.toLowerCase().startsWith("desa ")) {
      return { type: "desa", cleanName: villageName.substring(5) };
    }
    return { type: "unknown", cleanName: villageName };
  },
};

// Models
const AdministrativeDivision = mongoose.model(
  "AdministrativeDivision",
  administrativeDivisionSchema
);
const ServiceCoverage = mongoose.model(
  "ServiceCoverage",
  serviceCoverageSchema
);

export { AdministrativeDivision, ServiceCoverage, LocationUtils };

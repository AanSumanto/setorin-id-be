import { createLogger } from "./logger.js";

const logger = createLogger("i18n");

class InternationalizationManager {
  constructor() {
    this.supportedLanguages = ["id", "en"]; // Indonesian, English
    this.defaultLanguage = "id";
    this.translations = this.loadTranslations();
  }

  loadTranslations() {
    return {
      // Authentication & User Management Messages
      auth: {
        registration_success: {
          id: "Akun berhasil dibuat",
          en: "Account created successfully",
        },
        login_success: {
          id: "Login berhasil",
          en: "Login successful",
        },
        logout_success: {
          id: "Logout berhasil",
          en: "Logged out successfully",
        },
        token_refreshed: {
          id: "Token berhasil diperbarui",
          en: "Token refreshed successfully",
        },
        email_verified: {
          id: "Email berhasil diverifikasi",
          en: "Email verified successfully",
        },
        phone_verified: {
          id: "Nomor telepon berhasil diverifikasi",
          en: "Phone number verified successfully",
        },
        password_changed: {
          id: "Password berhasil diubah",
          en: "Password changed successfully",
        },
        password_reset: {
          id: "Password berhasil direset",
          en: "Password reset successfully",
        },
        otp_sent: {
          id: "Kode OTP telah dikirim ke nomor telepon Anda",
          en: "OTP code has been sent to your phone number",
        },
        verification_email_sent: {
          id: "Email verifikasi telah dikirim",
          en: "Verification email sent",
        },
        password_reset_email_sent: {
          id: "Jika email terdaftar, link reset password telah dikirim",
          en: "If the email exists, a reset link has been sent",
        },
        // Additional Authentication Messages
        profile_retrieved: {
          id: "Profil berhasil diambil",
          en: "Profile retrieved successfully",
        },
        password_strength_checked: {
          id: "Kekuatan password berhasil diperiksa",
          en: "Password strength checked successfully",
        },
        password_policy_retrieved: {
          id: "Kebijakan password berhasil diambil",
          en: "Password policy retrieved successfully",
        },
        sessions_retrieved: {
          id: "Daftar sesi berhasil diambil",
          en: "Sessions retrieved successfully",
        },
        lockout_status_retrieved: {
          id: "Status kunci akun berhasil diambil",
          en: "Account lockout status retrieved successfully",
        },
        security_events_retrieved: {
          id: "Riwayat keamanan berhasil diambil",
          en: "Security events retrieved successfully",
        },
        session_validated: {
          id: "Sesi berhasil divalidasi",
          en: "Session validated successfully",
        },
        email_availability_checked: {
          id: "Ketersediaan email berhasil diperiksa",
          en: "Email availability checked successfully",
        },
        phone_availability_checked: {
          id: "Ketersediaan nomor telepon berhasil diperiksa",
          en: "Phone availability checked successfully",
        },
      },

      // Error Messages
      errors: {
        // Validation Errors
        validation_error: {
          id: "Kesalahan validasi",
          en: "Validation error",
        },
        required_field: {
          id: "Field {field} wajib diisi",
          en: "Field {field} is required",
        },
        invalid_email: {
          id: "Format email tidak valid",
          en: "Invalid email format",
        },
        invalid_phone: {
          id: "Format nomor telepon tidak valid",
          en: "Invalid phone number format",
        },
        passwords_not_match: {
          id: "Password tidak cocok",
          en: "Passwords do not match",
        },

        // Authentication Errors
        invalid_credentials: {
          id: "Login atau password salah",
          en: "Invalid login or password",
        },
        account_locked: {
          id: "Akun dikunci sementara karena terlalu banyak percobaan login yang gagal",
          en: "Account temporarily locked due to too many failed login attempts",
        },
        account_deactivated: {
          id: "Akun telah dinonaktifkan",
          en: "Account has been deactivated",
        },
        token_expired: {
          id: "Token telah kedaluwarsa",
          en: "Token has expired",
        },
        invalid_token: {
          id: "Token tidak valid",
          en: "Invalid token",
        },
        insufficient_permissions: {
          id: "Tidak memiliki izin untuk mengakses resource ini",
          en: "Insufficient permissions for this resource",
        },
        authentication_required: {
          id: "Autentikasi diperlukan",
          en: "Authentication required",
        },
        email_verification_required: {
          id: "Verifikasi email diperlukan",
          en: "Email verification required",
        },

        // User Errors
        email_already_registered: {
          id: "Email sudah terdaftar",
          en: "Email already registered",
        },
        phone_already_registered: {
          id: "Nomor telepon sudah terdaftar",
          en: "Phone number already registered",
        },
        user_not_found: {
          id: "Pengguna tidak ditemukan",
          en: "User not found",
        },
        email_already_verified: {
          id: "Email sudah terverifikasi",
          en: "Email already verified",
        },
        phone_already_verified: {
          id: "Nomor telepon sudah terverifikasi",
          en: "Phone number already verified",
        },

        // Password Errors
        weak_password: {
          id: "Password terlalu lemah",
          en: "Password is too weak",
        },
        password_breached: {
          id: "Password ini telah ditemukan dalam data breach",
          en: "This password has been found in data breaches",
        },
        current_password_incorrect: {
          id: "Password saat ini salah",
          en: "Current password is incorrect",
        },
        new_password_same_as_current: {
          id: "Password baru harus berbeda dari password saat ini",
          en: "New password must be different from current password",
        },

        // OTP Errors
        invalid_otp: {
          id: "Kode OTP tidak valid atau sudah kedaluwarsa",
          en: "Invalid or expired OTP code",
        },
        otp_already_sent: {
          id: "Kode OTP sudah dikirim. Silakan tunggu sebelum meminta lagi",
          en: "OTP already sent. Please wait before requesting again",
        },

        // Rate Limiting
        rate_limit_exceeded: {
          id: "Terlalu banyak permintaan. Silakan coba lagi nanti",
          en: "Too many requests. Please try again later",
        },

        // Profile Errors
        profile_incomplete: {
          id: "Profil belum lengkap",
          en: "Profile incomplete",
        },
        missing_required_data: {
          id: "Data wajib tidak lengkap: {fields}",
          en: "Missing required data: {fields}",
        },

        // Business Logic Errors
        business_hours_only: {
          id: "Operasi ini hanya tersedia pada jam kerja (06:00 - 22:00)",
          en: "This operation is only available during business hours (6 AM - 10 PM)",
        },
        account_age_requirement: {
          id: "Akun harus berumur minimal {days} hari untuk operasi ini",
          en: "Account must be at least {days} days old for this operation",
        },
        location_outside_service_area: {
          id: "Lokasi di luar area layanan ({radius}km)",
          en: "Location outside service area ({radius}km radius)",
        },

        // System Errors
        internal_server_error: {
          id: "Terjadi kesalahan internal server",
          en: "Internal server error occurred",
        },
        service_unavailable: {
          id: "Layanan tidak tersedia sementara",
          en: "Service temporarily unavailable",
        },
        // Additional Validation Messages
        field_too_short: {
          id: "Field {field} terlalu pendek",
          en: "Field {field} is too short",
        },
        field_too_long: {
          id: "Field {field} terlalu panjang",
          en: "Field {field} is too long",
        },
        number_too_small: {
          id: "Nilai {field} terlalu kecil",
          en: "Value {field} is too small",
        },
        number_too_large: {
          id: "Nilai {field} terlalu besar",
          en: "Value {field} is too large",
        },
        invalid_array_length: {
          id: "Panjang array {field} tidak valid",
          en: "Invalid array length for {field}",
        },
        duplicate_entry: {
          id: "{field} sudah ada dalam sistem",
          en: "{field} already exists in the system",
        },
        invalid_id: {
          id: "ID tidak valid: {value}",
          en: "Invalid ID: {value}",
        },
      },

      // Business Logic Messages
      business: {
        order_created: {
          id: "Pesanan berhasil dibuat",
          en: "Order created successfully",
        },
        order_updated: {
          id: "Pesanan berhasil diperbarui",
          en: "Order updated successfully",
        },
        order_cancelled: {
          id: "Pesanan berhasil dibatalkan",
          en: "Order cancelled successfully",
        },
        product_created: {
          id: "Produk berhasil dibuat",
          en: "Product created successfully",
        },
        product_updated: {
          id: "Produk berhasil diperbarui",
          en: "Product updated successfully",
        },
        rating_submitted: {
          id: "Rating berhasil diberikan",
          en: "Rating submitted successfully",
        },
        points_earned: {
          id: "Anda mendapat {points} poin",
          en: "You earned {points} points",
        },
        reward_redeemed: {
          id: "Reward berhasil ditukar",
          en: "Reward redeemed successfully",
        },

        // Product Business Logic
        minimum_weight_not_met: {
          id: "Berat minimum tidak terpenuhi. Minimal {required}kg, Anda input {provided}kg",
          en: "Minimum weight not met. Required {required}kg, you provided {provided}kg",
        },
        minimum_volume_not_met: {
          id: "Volume minimum tidak terpenuhi. Minimal {required}L, Anda input {provided}L",
          en: "Minimum volume not met. Required {required}L, you provided {provided}L",
        },
        product_not_available: {
          id: "Produk tidak tersedia",
          en: "Product not available",
        },
        product_cannot_be_updated: {
          id: "Produk dengan status {status} tidak dapat diperbarui",
          en: "Product with status {status} cannot be updated",
        },
        product_cannot_be_deleted: {
          id: "Produk dengan status {status} tidak dapat dihapus",
          en: "Product with status {status} cannot be deleted",
        },
        cannot_favorite_own_product: {
          id: "Tidak dapat menambahkan produk sendiri ke favorit",
          en: "Cannot favorite your own product",
        },

        // Order Business Logic
        cannot_order_own_product: {
          id: "Tidak dapat memesan produk sendiri",
          en: "Cannot order your own product",
        },
        order_cannot_be_accepted: {
          id: "Pesanan dengan status {status} tidak dapat diterima",
          en: "Order with status {status} cannot be accepted",
        },
        order_already_assigned: {
          id: "Pesanan sudah ditugaskan ke pengepul lain",
          en: "Order already assigned to another collector",
        },
        order_cannot_be_cancelled: {
          id: "Pesanan dengan status {status} tidak dapat dibatalkan",
          en: "Order with status {status} cannot be cancelled",
        },
        order_cannot_be_completed: {
          id: "Pesanan dengan status {status} tidak dapat diselesaikan",
          en: "Order with status {status} cannot be completed",
        },
        invalid_status_transition: {
          id: "Transisi status tidak valid dari {from} ke {to}",
          en: "Invalid status transition from {from} to {to}",
        },
        collector_not_available: {
          id: "Pengepul tidak tersedia saat ini",
          en: "Collector not available at this time",
        },

        // Cooking Oil Business Logic
        only_individuals_can_sell_to_rt: {
          id: "Hanya individu yang dapat menjual ke RT",
          en: "Only individuals can sell to RT",
        },
        only_rt_can_sell_to_rw: {
          id: "Hanya RT yang dapat menjual ke RW",
          en: "Only RT can sell to RW",
        },
        only_rw_can_sell_to_platform: {
          id: "Hanya RW yang dapat menjual ke Platform",
          en: "Only RW can sell to Platform",
        },
        invalid_product_category: {
          id: "Kategori produk tidak valid. Diharapkan {expected}",
          en: "Invalid product category. Expected {expected}",
        },
        invalid_rt: {
          id: "RT tidak valid",
          en: "Invalid RT",
        },
        invalid_rw: {
          id: "RW tidak valid",
          en: "Invalid RW",
        },
        invalid_collector: {
          id: "Pengepul tidak valid",
          en: "Invalid collector",
        },
        insufficient_cooking_oil_balance: {
          id: "Saldo minyak jelantah tidak mencukupi. Tersedia {available}L, diminta {requested}L",
          en: "Insufficient cooking oil balance. Available {available}L, requested {requested}L",
        },
        invalid_order_type: {
          id: "Tipe pesanan tidak valid",
          en: "Invalid order type",
        },
        // Rating & Review Business Logic
        can_only_rate_completed_orders: {
          id: "Hanya dapat memberi rating untuk pesanan yang sudah selesai",
          en: "Can only rate completed orders",
        },
        rating_already_exists: {
          id: "Rating sudah pernah diberikan untuk pesanan ini",
          en: "Rating already exists for this order",
        },
        rating_edit_deadline_passed: {
          id: "Batas waktu edit rating sudah lewat (24 jam)",
          en: "Rating edit deadline has passed (24 hours)",
        },
        cannot_vote_on_own_rating: {
          id: "Tidak dapat vote rating sendiri",
          en: "Cannot vote on your own rating",
        },
        rating_response_already_exists: {
          id: "Respon untuk rating ini sudah ada",
          en: "Response for this rating already exists",
        },
        cannot_report_own_rating: {
          id: "Tidak dapat melaporkan rating sendiri",
          en: "Cannot report your own rating",
        },

        // Additional error keys
        rating_not_found: {
          id: "Rating tidak ditemukan",
          en: "Rating not found",
        },
        invalid_user_role: {
          id: "Role user tidak valid. Diharapkan {expected}, aktual {actual}",
          en: "Invalid user role. Expected {expected}, actual {actual}",
        },
        invalid_transaction_type: {
          id: "Tipe transaksi tidak valid: {type}",
          en: "Invalid transaction type: {type}",
        },
      },

      // Field Labels (for forms)
      fields: {
        name: {
          id: "Nama",
          en: "Name",
        },
        email: {
          id: "Email",
          en: "Email",
        },
        phone: {
          id: "Nomor Telepon",
          en: "Phone Number",
        },
        password: {
          id: "Password",
          en: "Password",
        },
        current_password: {
          id: "Password Saat Ini",
          en: "Current Password",
        },
        new_password: {
          id: "Password Baru",
          en: "New Password",
        },
        confirm_password: {
          id: "Konfirmasi Password",
          en: "Confirm Password",
        },
        address: {
          id: "Alamat",
          en: "Address",
        },
        street: {
          id: "Jalan",
          en: "Street",
        },
        village: {
          id: "Kelurahan/Desa",
          en: "Village",
        },
        district: {
          id: "Kecamatan",
          en: "District",
        },
        city: {
          id: "Kota/Kabupaten",
          en: "City",
        },
        province: {
          id: "Provinsi",
          en: "Province",
        },
        postal_code: {
          id: "Kode Pos",
          en: "Postal Code",
        },
        date_of_birth: {
          id: "Tanggal Lahir",
          en: "Date of Birth",
        },
        gender: {
          id: "Jenis Kelamin",
          en: "Gender",
        },
        role: {
          id: "Peran",
          en: "Role",
        },
      },

      // Status Messages
      status: {
        active: {
          id: "Aktif",
          en: "Active",
        },
        inactive: {
          id: "Tidak Aktif",
          en: "Inactive",
        },
        pending: {
          id: "Menunggu",
          en: "Pending",
        },
        completed: {
          id: "Selesai",
          en: "Completed",
        },
        cancelled: {
          id: "Dibatalkan",
          en: "Cancelled",
        },
        verified: {
          id: "Terverifikasi",
          en: "Verified",
        },
        not_verified: {
          id: "Belum Terverifikasi",
          en: "Not Verified",
        },
      },

      // Role Names
      roles: {
        individual: {
          id: "Individu",
          en: "Individual",
        },
        rt: {
          id: "RT (Rukun Tetangga)",
          en: "RT (Neighborhood Unit)",
        },
        rw: {
          id: "RW (Rukun Warga)",
          en: "RW (Community Unit)",
        },
        collector: {
          id: "Pengepul",
          en: "Collector",
        },
        admin: {
          id: "Administrator",
          en: "Administrator",
        },
      },

      // Product Categories
      categories: {
        scrap: {
          id: "Barang Rongsok",
          en: "Scrap Materials",
        },
        cooking_oil: {
          id: "Minyak Jelantah",
          en: "Used Cooking Oil",
        },
      },

      // Validation Messages for Password Policy
      password_policy: {
        title: {
          id: "Kebijakan Password",
          en: "Password Policy",
        },
        requirements: {
          id: "Persyaratan",
          en: "Requirements",
        },
        min_length: {
          id: "Minimal 8 karakter",
          en: "At least 8 characters long",
        },
        lowercase: {
          id: "Mengandung huruf kecil (a-z)",
          en: "Contains lowercase letters (a-z)",
        },
        uppercase: {
          id: "Mengandung huruf besar (A-Z)",
          en: "Contains uppercase letters (A-Z)",
        },
        numbers: {
          id: "Mengandung angka (0-9)",
          en: "Contains numbers (0-9)",
        },
        symbols: {
          id: "Mengandung karakter khusus (!@#$%^&*)",
          en: "Contains special characters (!@#$%^&*)",
        },
        no_common_patterns: {
          id: "Tidak mengandung pola yang umum",
          en: "No common weak patterns",
        },
        not_breached: {
          id: "Tidak ditemukan dalam data breach",
          en: "Not found in data breaches",
        },
        recommendations_title: {
          id: "Rekomendasi",
          en: "Recommendations",
        },
        unique_password: {
          id: "Gunakan password unik untuk akun ini",
          en: "Use a unique password for this account",
        },
        password_manager: {
          id: "Pertimbangkan menggunakan password manager",
          en: "Consider using a password manager",
        },
        two_factor: {
          id: "Aktifkan autentikasi dua faktor jika tersedia",
          en: "Enable two-factor authentication when available",
        },
        regular_update: {
          id: "Perbarui password secara berkala",
          en: "Update your password regularly",
        },
      },
    };
  }

  // Get translation for specific key
  translate(key, interpolations = {}) {
    const keys = key.split(".");
    let translation = this.translations;

    // Navigate through nested object
    for (const k of keys) {
      translation = translation?.[k];
      if (!translation) {
        logger.warn(`Translation key not found: ${key}`);
        return key; // Return key if translation not found
      }
    }

    // Return all languages for the key
    const result = {};
    for (const lang of this.supportedLanguages) {
      let text = translation[lang] || translation[this.defaultLanguage] || key;

      // Handle interpolations (placeholders)
      if (Object.keys(interpolations).length > 0) {
        text = this.interpolate(text, interpolations);
      }

      result[lang] = text;
    }

    return result;
  }

  // Get single language translation
  translateSingle(key, language = "id", interpolations = {}) {
    const keys = key.split(".");
    let translation = this.translations;

    // Navigate through nested object
    for (const k of keys) {
      translation = translation?.[k];
      if (!translation) {
        logger.warn(`Translation key not found: ${key}`);
        return key;
      }
    }

    let text =
      translation[language] || translation[this.defaultLanguage] || key;

    // Handle interpolations
    if (Object.keys(interpolations).length > 0) {
      text = this.interpolate(text, interpolations);
    }

    return text;
  }

  // Handle placeholder interpolations
  interpolate(text, interpolations) {
    let result = text;
    for (const [key, value] of Object.entries(interpolations)) {
      const placeholder = `{${key}}`;
      result = result.replace(new RegExp(placeholder, "g"), value);
    }
    return result;
  }

  // Create multilingual response
  createResponse(status, messageKey, data = null, interpolations = {}) {
    const message = this.translate(messageKey, interpolations);

    const response = {
      status,
      message,
      timestamp: new Date().toISOString(),
    };

    if (data !== null) {
      response.data = data;
    }

    return response;
  }

  // Create multilingual error response
  createErrorResponse(statusCode, messageKey, interpolations = {}) {
    const message = this.translate(messageKey, interpolations);

    return {
      status: "error",
      statusCode,
      message,
      timestamp: new Date().toISOString(),
    };
  }

  // Create multilingual validation error response
  createValidationErrorResponse(errors) {
    const message = this.translate("errors.validation_error");

    // Translate field names in error details
    const translatedErrors = errors.map((error) => {
      const fieldTranslation = this.translate(
        `fields.${error.field}`,
        {},
        true
      );
      return {
        field: error.field,
        fieldName: fieldTranslation,
        message: this.translate(
          `errors.${error.code}`,
          error.interpolations || {}
        ),
      };
    });

    return {
      status: "error",
      statusCode: 400,
      message,
      errors: translatedErrors,
      timestamp: new Date().toISOString(),
    };
  }

  // Get supported languages
  getSupportedLanguages() {
    return this.supportedLanguages;
  }

  // Add new translation dynamically
  addTranslation(key, translations) {
    const keys = key.split(".");
    let current = this.translations;

    // Navigate to the right nested level
    for (let i = 0; i < keys.length - 1; i++) {
      if (!current[keys[i]]) {
        current[keys[i]] = {};
      }
      current = current[keys[i]];
    }

    // Set the translation
    current[keys[keys.length - 1]] = translations;

    logger.info(`New translation added: ${key}`);
  }

  // Get all translations (for debugging)
  getAllTranslations() {
    return this.translations;
  }

  // Detect preferred language from request
  detectLanguage(req) {
    // Check Accept-Language header
    const acceptLanguage = req.headers["accept-language"];
    if (acceptLanguage) {
      const languages = acceptLanguage
        .split(",")
        .map((lang) => lang.trim().split(";")[0]);
      for (const lang of languages) {
        const shortLang = lang.substring(0, 2);
        if (this.supportedLanguages.includes(shortLang)) {
          return shortLang;
        }
      }
    }

    // Check user preference if authenticated
    if (req.user && req.user.preferences && req.user.preferences.language) {
      return req.user.preferences.language;
    }

    return this.defaultLanguage;
  }
}

// Create singleton instance
const i18n = new InternationalizationManager();

export default i18n;

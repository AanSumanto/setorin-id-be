import nodemailer from "nodemailer";
import twilio from "twilio";
import admin from "firebase-admin";
import { createLogger } from "../utils/logger.js";
import i18n from "../utils/i18n.js";
import { User } from "../models/index.js";

const logger = createLogger("NotificationService");

class NotificationService {
  constructor() {
    this.initializeServices();
  }

  initializeServices() {
    // Initialize Email Transport
    this.emailTransporter = nodemailer.createTransport({
      host: process.env.EMAIL_HOST,
      port: process.env.EMAIL_PORT,
      secure: process.env.EMAIL_PORT == 465,
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    // Initialize Twilio for SMS
    if (process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN) {
      this.twilioClient = twilio(
        process.env.TWILIO_ACCOUNT_SID,
        process.env.TWILIO_AUTH_TOKEN
      );
      this.twilioPhoneNumber = process.env.TWILIO_PHONE_NUMBER;
    }

    // Initialize Firebase Admin for Push Notifications
    if (process.env.FIREBASE_SERVICE_ACCOUNT) {
      try {
        const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
        admin.initializeApp({
          credential: admin.credential.cert(serviceAccount),
        });
        this.fcm = admin.messaging();
      } catch (error) {
        logger.error("Failed to initialize Firebase:", error);
      }
    }
  }

  // Send Email
  async sendEmail(to, subject, template, data = {}, language = "id") {
    try {
      const html = await this.renderEmailTemplate(template, data, language);

      const mailOptions = {
        from: `${process.env.APP_NAME} <${process.env.EMAIL_FROM}>`,
        to,
        subject,
        html,
      };

      const info = await this.emailTransporter.sendMail(mailOptions);
      logger.info(`Email sent to ${to}: ${info.messageId}`);

      return { success: true, messageId: info.messageId };
    } catch (error) {
      logger.error("Email sending failed:", error);
      return { success: false, error: error.message };
    }
  }

  // Send SMS
  async sendSMS(phoneNumber, message) {
    try {
      if (!this.twilioClient) {
        throw new Error("SMS service not configured");
      }

      // Format Indonesian phone number
      const formattedPhone = this.formatPhoneNumber(phoneNumber);

      const result = await this.twilioClient.messages.create({
        body: message,
        from: this.twilioPhoneNumber,
        to: formattedPhone,
      });

      logger.info(`SMS sent to ${formattedPhone}: ${result.sid}`);
      return { success: true, messageId: result.sid };
    } catch (error) {
      logger.error("SMS sending failed:", error);
      return { success: false, error: error.message };
    }
  }

  // Send Push Notification
  async sendPushNotification(userId, notification) {
    try {
      if (!this.fcm) {
        throw new Error("Push notification service not configured");
      }

      const user = await User.findById(userId).select("fcmToken");
      if (!user || !user.fcmToken) {
        throw new Error("User FCM token not found");
      }

      const message = {
        token: user.fcmToken,
        notification: {
          title: notification.title,
          body: notification.body,
        },
        data: notification.data || {},
        android: {
          priority: "high",
          notification: {
            icon: "ic_launcher",
            color: "#4CAF50",
          },
        },
        apns: {
          payload: {
            aps: {
              badge: notification.badge || 1,
              sound: "default",
            },
          },
        },
      };

      const response = await this.fcm.send(message);
      logger.info(`Push notification sent to user ${userId}: ${response}`);

      return { success: true, messageId: response };
    } catch (error) {
      logger.error("Push notification failed:", error);
      return { success: false, error: error.message };
    }
  }

  // Send Multi-channel Notification
  async sendNotification(userId, notificationType, data) {
    try {
      const user = await User.findById(userId).select(
        "email phone preferences name fcmToken"
      );

      if (!user) {
        throw new Error("User not found");
      }

      const results = {};
      const template = this.getNotificationTemplate(
        notificationType,
        data,
        user.preferences.language
      );

      // Send Email if enabled
      if (user.preferences.notifications.email && user.email) {
        results.email = await this.sendEmail(
          user.email,
          template.subject,
          template.emailTemplate,
          { ...data, userName: user.name },
          user.preferences.language
        );
      }

      // Send SMS if enabled
      if (user.preferences.notifications.sms && user.phone) {
        results.sms = await this.sendSMS(user.phone, template.smsMessage);
      }

      // Send Push Notification if enabled
      if (user.preferences.notifications.push && user.fcmToken) {
        results.push = await this.sendPushNotification(userId, {
          title: template.pushTitle,
          body: template.pushBody,
          data: template.pushData,
        });
      }

      // Store notification in database
      await this.storeNotification(userId, notificationType, data, results);

      return results;
    } catch (error) {
      logger.error("Multi-channel notification failed:", error);
      throw error;
    }
  }

  // Notification Templates
  getNotificationTemplate(type, data, language = "id") {
    const templates = {
      order_created: {
        subject:
          language === "id" ? "Pesanan Baru Dibuat" : "New Order Created",
        emailTemplate: "order-created",
        smsMessage:
          language === "id"
            ? `Pesanan #${data.orderNumber} telah dibuat. Total: Rp ${data.amount}`
            : `Order #${data.orderNumber} has been created. Total: Rp ${data.amount}`,
        pushTitle: language === "id" ? "Pesanan Baru" : "New Order",
        pushBody:
          language === "id"
            ? `Pesanan Anda #${data.orderNumber} sedang diproses`
            : `Your order #${data.orderNumber} is being processed`,
        pushData: { orderId: data.orderId, type: "order" },
      },
      order_accepted: {
        subject: language === "id" ? "Pesanan Diterima" : "Order Accepted",
        emailTemplate: "order-accepted",
        smsMessage:
          language === "id"
            ? `Pesanan #${data.orderNumber} telah diterima oleh pengepul`
            : `Order #${data.orderNumber} has been accepted by collector`,
        pushTitle: language === "id" ? "Pesanan Diterima" : "Order Accepted",
        pushBody:
          language === "id"
            ? `Pengepul sedang menuju lokasi Anda`
            : `Collector is on the way to your location`,
        pushData: { orderId: data.orderId, type: "order" },
      },
      order_completed: {
        subject: language === "id" ? "Pesanan Selesai" : "Order Completed",
        emailTemplate: "order-completed",
        smsMessage:
          language === "id"
            ? `Pesanan #${data.orderNumber} selesai. Anda mendapat ${data.points} poin!`
            : `Order #${data.orderNumber} completed. You earned ${data.points} points!`,
        pushTitle: language === "id" ? "Pesanan Selesai" : "Order Completed",
        pushBody:
          language === "id"
            ? `Terima kasih! Anda mendapat ${data.points} poin`
            : `Thank you! You earned ${data.points} points`,
        pushData: { orderId: data.orderId, points: data.points, type: "order" },
      },
      payment_received: {
        subject: language === "id" ? "Pembayaran Diterima" : "Payment Received",
        emailTemplate: "payment-received",
        smsMessage:
          language === "id"
            ? `Pembayaran Rp ${data.amount} telah diterima`
            : `Payment of Rp ${data.amount} has been received`,
        pushTitle:
          language === "id" ? "Pembayaran Diterima" : "Payment Received",
        pushBody:
          language === "id"
            ? `Pembayaran sebesar Rp ${data.amount} berhasil`
            : `Payment of Rp ${data.amount} successful`,
        pushData: { amount: data.amount, type: "payment" },
      },
      verification_code: {
        subject: language === "id" ? "Kode Verifikasi" : "Verification Code",
        emailTemplate: "verification-code",
        smsMessage:
          language === "id"
            ? `Kode verifikasi Setorin: ${data.code}. Berlaku 5 menit.`
            : `Setorin verification code: ${data.code}. Valid for 5 minutes.`,
        pushTitle: language === "id" ? "Kode Verifikasi" : "Verification Code",
        pushBody:
          language === "id"
            ? `Kode verifikasi: ${data.code}`
            : `Verification code: ${data.code}`,
        pushData: { type: "verification" },
      },
      welcome: {
        subject:
          language === "id"
            ? "Selamat Datang di Setorin!"
            : "Welcome to Setorin!",
        emailTemplate: "welcome",
        smsMessage:
          language === "id"
            ? `Selamat datang di Setorin! Mulai jual sampah Anda dan dapatkan poin.`
            : `Welcome to Setorin! Start selling your waste and earn points.`,
        pushTitle: language === "id" ? "Selamat Datang!" : "Welcome!",
        pushBody:
          language === "id"
            ? `Akun Anda berhasil dibuat. Mulai transaksi pertama Anda!`
            : `Your account has been created. Start your first transaction!`,
        pushData: { type: "welcome" },
      },
    };

    return templates[type] || templates.welcome;
  }

  // Email Template Renderer
  async renderEmailTemplate(template, data, language) {
    // In production, use a template engine like Handlebars or EJS
    const baseTemplate = `
    <!DOCTYPE html>
    <html>
    <head>
      <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background-color: #4CAF50; color: white; padding: 20px; text-align: center; }
        .content { padding: 20px; background-color: #f4f4f4; }
        .footer { text-align: center; padding: 20px; color: #666; }
        .button { display: inline-block; padding: 10px 20px; background-color: #4CAF50; color: white; text-decoration: none; border-radius: 5px; }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h1>Setorin</h1>
        </div>
        <div class="content">
          ${this.getEmailContent(template, data, language)}
        </div>
        <div class="footer">
          <p>&copy; 2024 Setorin. All rights reserved.</p>
        </div>
      </div>
    </body>
    </html>
    `;

    return baseTemplate;
  }

  getEmailContent(template, data, language) {
    const contents = {
      "order-created":
        language === "id"
          ? `<h2>Pesanan Baru!</h2>
           <p>Hai ${data.userName},</p>
           <p>Pesanan Anda #${data.orderNumber} telah berhasil dibuat.</p>
           <p>Total: Rp ${data.amount}</p>
           <a href="${process.env.APP_URL}/orders/${data.orderId}" class="button">Lihat Pesanan</a>`
          : `<h2>New Order!</h2>
           <p>Hi ${data.userName},</p>
           <p>Your order #${data.orderNumber} has been created successfully.</p>
           <p>Total: Rp ${data.amount}</p>
           <a href="${process.env.APP_URL}/orders/${data.orderId}" class="button">View Order</a>`,

      welcome:
        language === "id"
          ? `<h2>Selamat Datang di Setorin!</h2>
           <p>Hai ${data.userName},</p>
           <p>Terima kasih telah mendaftar di Setorin. Mulai jual sampah Anda dan dapatkan keuntungan!</p>
           <a href="${process.env.APP_URL}/verify/${data.verificationToken}" class="button">Verifikasi Email</a>`
          : `<h2>Welcome to Setorin!</h2>
           <p>Hi ${data.userName},</p>
           <p>Thank you for registering with Setorin. Start selling your waste and earn rewards!</p>
           <a href="${process.env.APP_URL}/verify/${data.verificationToken}" class="button">Verify Email</a>`,
    };

    return contents[template] || contents.welcome;
  }

  // Store notification history
  async storeNotification(userId, type, data, results) {
    try {
      // Implementation depends on your notification model
      // This is a placeholder
      logger.info(`Notification stored for user ${userId}: ${type}`);
    } catch (error) {
      logger.error("Failed to store notification:", error);
    }
  }

  // Format Indonesian phone number
  formatPhoneNumber(phone) {
    // Remove any non-numeric characters
    phone = phone.replace(/\D/g, "");

    // Convert to international format
    if (phone.startsWith("0")) {
      phone = "62" + phone.substring(1);
    }
    if (!phone.startsWith("62")) {
      phone = "62" + phone;
    }

    return "+" + phone;
  }

  // Bulk notifications
  async sendBulkNotifications(userIds, notificationType, data) {
    const results = [];

    for (const userId of userIds) {
      try {
        const result = await this.sendNotification(
          userId,
          notificationType,
          data
        );
        results.push({ userId, success: true, result });
      } catch (error) {
        results.push({ userId, success: false, error: error.message });
      }
    }

    return results;
  }

  // Schedule notification
  async scheduleNotification(userId, notificationType, data, scheduledTime) {
    // This would integrate with a job queue like Bull
    logger.info(
      `Notification scheduled for user ${userId} at ${scheduledTime}`
    );
    // Implementation with Bull queue would go here
  }

  // Notification Templates (Updated with Password Reset)
  getNotificationTemplate(type, data, language = "id") {
    const templates = {
      order_created: {
        subject:
          language === "id" ? "Pesanan Baru Dibuat" : "New Order Created",
        emailTemplate: "order-created",
        smsMessage:
          language === "id"
            ? `Pesanan #${data.orderNumber} telah dibuat. Total: Rp ${data.amount}`
            : `Order #${data.orderNumber} has been created. Total: Rp ${data.amount}`,
        pushTitle: language === "id" ? "Pesanan Baru" : "New Order",
        pushBody:
          language === "id"
            ? `Pesanan Anda #${data.orderNumber} sedang diproses`
            : `Your order #${data.orderNumber} is being processed`,
        pushData: { orderId: data.orderId, type: "order" },
      },
      order_accepted: {
        subject: language === "id" ? "Pesanan Diterima" : "Order Accepted",
        emailTemplate: "order-accepted",
        smsMessage:
          language === "id"
            ? `Pesanan #${data.orderNumber} telah diterima oleh pengepul`
            : `Order #${data.orderNumber} has been accepted by collector`,
        pushTitle: language === "id" ? "Pesanan Diterima" : "Order Accepted",
        pushBody:
          language === "id"
            ? `Pengepul sedang menuju lokasi Anda`
            : `Collector is on the way to your location`,
        pushData: { orderId: data.orderId, type: "order" },
      },
      order_completed: {
        subject: language === "id" ? "Pesanan Selesai" : "Order Completed",
        emailTemplate: "order-completed",
        smsMessage:
          language === "id"
            ? `Pesanan #${data.orderNumber} selesai. Anda mendapat ${data.points} poin!`
            : `Order #${data.orderNumber} completed. You earned ${data.points} points!`,
        pushTitle: language === "id" ? "Pesanan Selesai" : "Order Completed",
        pushBody:
          language === "id"
            ? `Terima kasih! Anda mendapat ${data.points} poin`
            : `Thank you! You earned ${data.points} points`,
        pushData: { orderId: data.orderId, points: data.points, type: "order" },
      },
      payment_received: {
        subject: language === "id" ? "Pembayaran Diterima" : "Payment Received",
        emailTemplate: "payment-received",
        smsMessage:
          language === "id"
            ? `Pembayaran Rp ${data.amount} telah diterima`
            : `Payment of Rp ${data.amount} has been received`,
        pushTitle:
          language === "id" ? "Pembayaran Diterima" : "Payment Received",
        pushBody:
          language === "id"
            ? `Pembayaran sebesar Rp ${data.amount} berhasil`
            : `Payment of Rp ${data.amount} successful`,
        pushData: { amount: data.amount, type: "payment" },
      },
      verification_code: {
        subject: language === "id" ? "Kode Verifikasi" : "Verification Code",
        emailTemplate: "verification-code",
        smsMessage:
          language === "id"
            ? `Kode verifikasi Setorin: ${data.code}. Berlaku 5 menit.`
            : `Setorin verification code: ${data.code}. Valid for 5 minutes.`,
        pushTitle: language === "id" ? "Kode Verifikasi" : "Verification Code",
        pushBody:
          language === "id"
            ? `Kode verifikasi: ${data.code}`
            : `Verification code: ${data.code}`,
        pushData: { type: "verification" },
      },
      // NEW: Password Reset Templates
      password_reset_email: {
        subject:
          language === "id"
            ? "Reset Password - Setorin"
            : "Password Reset - Setorin",
        emailTemplate: "password-reset-email",
        smsMessage: null, // Email only
        pushTitle: language === "id" ? "Reset Password" : "Password Reset",
        pushBody:
          language === "id"
            ? `Link reset password telah dikirim ke email Anda`
            : `Password reset link has been sent to your email`,
        pushData: { type: "password_reset" },
      },
      password_reset_otp: {
        subject: null, // SMS only
        emailTemplate: null, // SMS only
        smsMessage:
          language === "id"
            ? `Kode reset password Setorin: ${data.otp}. Berlaku 5 menit. Jangan bagikan kode ini kepada siapapun.`
            : `Setorin password reset code: ${data.otp}. Valid for 5 minutes. Don't share this code with anyone.`,
        pushTitle:
          language === "id" ? "Kode Reset Password" : "Password Reset Code",
        pushBody:
          language === "id"
            ? `Kode OTP telah dikirim ke nomor Anda`
            : `OTP code has been sent to your number`,
        pushData: { type: "password_reset_otp" },
      },
      password_reset_success: {
        subject:
          language === "id"
            ? "Password Berhasil Direset - Setorin"
            : "Password Successfully Reset - Setorin",
        emailTemplate: "password-reset-success",
        smsMessage:
          language === "id"
            ? `Password akun Setorin Anda berhasil direset. Jika bukan Anda yang melakukan ini, segera hubungi customer service.`
            : `Your Setorin account password has been successfully reset. If this wasn't you, please contact customer service immediately.`,
        pushTitle: language === "id" ? "Password Direset" : "Password Reset",
        pushBody:
          language === "id"
            ? `Password Anda berhasil diubah`
            : `Your password has been successfully changed`,
        pushData: { type: "password_reset_success" },
      },
      welcome: {
        subject:
          language === "id"
            ? "Selamat Datang di Setorin!"
            : "Welcome to Setorin!",
        emailTemplate: "welcome",
        smsMessage:
          language === "id"
            ? `Selamat datang di Setorin! Mulai jual sampah Anda dan dapatkan poin.`
            : `Welcome to Setorin! Start selling your waste and earn points.`,
        pushTitle: language === "id" ? "Selamat Datang!" : "Welcome!",
        pushBody:
          language === "id"
            ? `Akun Anda berhasil dibuat. Mulai transaksi pertama Anda!`
            : `Your account has been created. Start your first transaction!`,
        pushData: { type: "welcome" },
      },
    };

    return templates[type] || templates.welcome;
  }

  // Updated Email Content with Password Reset Templates
  getEmailContent(template, data, language) {
    const contents = {
      "order-created":
        language === "id"
          ? `<h2>Pesanan Baru!</h2>
           <p>Hai ${data.userName},</p>
           <p>Pesanan Anda #${data.orderNumber} telah berhasil dibuat.</p>
           <p>Total: Rp ${data.amount}</p>
           <a href="${process.env.APP_URL}/orders/${data.orderId}" class="button">Lihat Pesanan</a>`
          : `<h2>New Order!</h2>
           <p>Hi ${data.userName},</p>
           <p>Your order #${data.orderNumber} has been created successfully.</p>
           <p>Total: Rp ${data.amount}</p>
           <a href="${process.env.APP_URL}/orders/${data.orderId}" class="button">View Order</a>`,

      // NEW: Password Reset Email Template
      "password-reset-email":
        language === "id"
          ? `<h2>Reset Password</h2>
           <p>Hai ${data.userName},</p>
           <p>Anda meminta reset password untuk akun Setorin Anda.</p>
           <div style="background-color: #fff; padding: 20px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #4CAF50;">
             <p><strong>Untuk keamanan akun Anda:</strong></p>
             <ul style="margin: 10px 0; padding-left: 20px;">
               <li>Jangan bagikan link ini kepada siapapun</li>
               <li>Link ini berlaku selama 15 menit</li>
               <li>Gunakan password yang kuat dan unik</li>
             </ul>
           </div>
           <p>Klik tombol di bawah untuk reset password:</p>
           <div style="text-align: center; margin: 30px 0;">
             <a href="${process.env.APP_URL}/auth/reset-password?token=${data.resetToken}" 
                style="display: inline-block; padding: 15px 30px; background-color: #4CAF50; color: white; text-decoration: none; border-radius: 8px; font-weight: bold; font-size: 16px;">
               Reset Password Sekarang
             </a>
           </div>
           <p style="color: #666; font-size: 14px;">
             Atau copy dan paste link berikut di browser Anda:<br>
             <span style="background-color: #f5f5f5; padding: 5px; border-radius: 3px; word-break: break-all;">
               ${process.env.APP_URL}/auth/reset-password?token=${data.resetToken}
             </span>
           </p>
           <div style="background-color: #fff3cd; padding: 15px; border-radius: 5px; margin: 20px 0; border: 1px solid #ffeaa7;">
             <p style="margin: 0; color: #856404;">
               <strong>⚠️ Tidak meminta reset password?</strong><br>
               Jika Anda tidak meminta reset password, abaikan email ini. Akun Anda tetap aman.
             </p>
           </div>`
          : `<h2>Password Reset</h2>
           <p>Hi ${data.userName},</p>
           <p>You requested a password reset for your Setorin account.</p>
           <div style="background-color: #fff; padding: 20px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #4CAF50;">
             <p><strong>For your account security:</strong></p>
             <ul style="margin: 10px 0; padding-left: 20px;">
               <li>Don't share this link with anyone</li>
               <li>This link is valid for 15 minutes</li>
               <li>Use a strong and unique password</li>
             </ul>
           </div>
           <p>Click the button below to reset your password:</p>
           <div style="text-align: center; margin: 30px 0;">
             <a href="${process.env.APP_URL}/auth/reset-password?token=${data.resetToken}" 
                style="display: inline-block; padding: 15px 30px; background-color: #4CAF50; color: white; text-decoration: none; border-radius: 8px; font-weight: bold; font-size: 16px;">
               Reset Password Now
             </a>
           </div>
           <p style="color: #666; font-size: 14px;">
             Or copy and paste this link in your browser:<br>
             <span style="background-color: #f5f5f5; padding: 5px; border-radius: 3px; word-break: break-all;">
               ${process.env.APP_URL}/auth/reset-password?token=${data.resetToken}
             </span>
           </p>
           <div style="background-color: #fff3cd; padding: 15px; border-radius: 5px; margin: 20px 0; border: 1px solid #ffeaa7;">
             <p style="margin: 0; color: #856404;">
               <strong>⚠️ Didn't request a password reset?</strong><br>
               If you didn't request this reset, please ignore this email. Your account remains secure.
             </p>
           </div>`,

      // NEW: Password Reset Success Template
      "password-reset-success":
        language === "id"
          ? `<h2>Password Berhasil Direset</h2>
           <p>Hai ${data.userName},</p>
           <div style="background-color: #d4edda; padding: 20px; border-radius: 8px; margin: 20px 0; border: 1px solid #c3e6cb;">
             <p style="margin: 0; color: #155724;">
               <strong>✅ Password Anda berhasil direset!</strong><br>
               Sekarang Anda dapat login dengan password baru Anda.
             </p>
           </div>
           <p><strong>Detail reset password:</strong></p>
           <ul style="background-color: #f8f9fa; padding: 15px; border-radius: 5px;">
             <li>Waktu: ${new Date().toLocaleString("id-ID")}</li>
             <li>IP Address: ${data.ipAddress || "N/A"}</li>
             <li>Browser: ${data.userAgent || "N/A"}</li>
           </ul>
           <div style="text-align: center; margin: 30px 0;">
             <a href="${process.env.APP_URL}/auth/login" 
                style="display: inline-block; padding: 15px 30px; background-color: #4CAF50; color: white; text-decoration: none; border-radius: 8px; font-weight: bold;">
               Login Sekarang
             </a>
           </div>
           <div style="background-color: #f8d7da; padding: 15px; border-radius: 5px; margin: 20px 0; border: 1px solid #f1aeb5;">
             <p style="margin: 0; color: #721c24;">
               <strong>🔒 Bukan Anda yang melakukan ini?</strong><br>
               Jika Anda tidak melakukan reset password, segera hubungi customer service kami di support@setorin.id atau +62 711 7101234.
             </p>
           </div>`
          : `<h2>Password Successfully Reset</h2>
           <p>Hi ${data.userName},</p>
           <div style="background-color: #d4edda; padding: 20px; border-radius: 8px; margin: 20px 0; border: 1px solid #c3e6cb;">
             <p style="margin: 0; color: #155724;">
               <strong>✅ Your password has been successfully reset!</strong><br>
               You can now login with your new password.
             </p>
           </div>
           <p><strong>Password reset details:</strong></p>
           <ul style="background-color: #f8f9fa; padding: 15px; border-radius: 5px;">
             <li>Time: ${new Date().toLocaleString("en-US")}</li>
             <li>IP Address: ${data.ipAddress || "N/A"}</li>
             <li>Browser: ${data.userAgent || "N/A"}</li>
           </ul>
           <div style="text-align: center; margin: 30px 0;">
             <a href="${process.env.APP_URL}/auth/login" 
                style="display: inline-block; padding: 15px 30px; background-color: #4CAF50; color: white; text-decoration: none; border-radius: 8px; font-weight: bold;">
               Login Now
             </a>
           </div>
           <div style="background-color: #f8d7da; padding: 15px; border-radius: 5px; margin: 20px 0; border: 1px solid #f1aeb5;">
             <p style="margin: 0; color: #721c24;">
               <strong>🔒 This wasn't you?</strong><br>
               If you didn't reset your password, please contact our customer service immediately at support@setorin.id or +62 711 7101234.
             </p>
           </div>`,

      welcome:
        language === "id"
          ? `<h2>Selamat Datang di Setorin!</h2>
           <p>Hai ${data.userName},</p>
           <p>Terima kasih telah mendaftar di Setorin. Mulai jual sampah Anda dan dapatkan keuntungan!</p>
           <a href="${process.env.APP_URL}/verify/${data.verificationToken}" class="button">Verifikasi Email</a>`
          : `<h2>Welcome to Setorin!</h2>
           <p>Hi ${data.userName},</p>
           <p>Thank you for registering with Setorin. Start selling your waste and earn rewards!</p>
           <a href="${process.env.APP_URL}/verify/${data.verificationToken}" class="button">Verify Email</a>`,
    };

    return contents[template] || contents.welcome;
  }

  // Helper method specifically for password reset notifications
  async sendPasswordResetNotification(user, resetType, data) {
    try {
      const language = user.preferences?.language || "id";
      let notificationType;
      let notificationData = {
        userName: user.name,
        ...data,
      };

      if (resetType === "email") {
        notificationType = "password_reset_email";
        // Send email with reset token
        if (user.email) {
          const result = await this.sendEmail(
            user.email,
            this.getNotificationTemplate(
              notificationType,
              notificationData,
              language
            ).subject,
            this.getNotificationTemplate(
              notificationType,
              notificationData,
              language
            ).emailTemplate,
            notificationData,
            language
          );
          return { email: result };
        }
      } else if (resetType === "otp") {
        notificationType = "password_reset_otp";
        // Send SMS with OTP
        if (user.phone) {
          const template = this.getNotificationTemplate(
            notificationType,
            notificationData,
            language
          );
          const result = await this.sendSMS(user.phone, template.smsMessage);
          return { sms: result };
        }
      } else if (resetType === "success") {
        notificationType = "password_reset_success";
        const results = {};

        // Send success notification via email if available
        if (user.email) {
          results.email = await this.sendEmail(
            user.email,
            this.getNotificationTemplate(
              notificationType,
              notificationData,
              language
            ).subject,
            this.getNotificationTemplate(
              notificationType,
              notificationData,
              language
            ).emailTemplate,
            notificationData,
            language
          );
        }

        // Send success notification via SMS if available
        if (user.phone) {
          const template = this.getNotificationTemplate(
            notificationType,
            notificationData,
            language
          );
          results.sms = await this.sendSMS(user.phone, template.smsMessage);
        }

        return results;
      }

      return { success: false, error: "Invalid reset type" };
    } catch (error) {
      logger.error("Password reset notification failed:", error);
      throw error;
    }
  }
}

// Create singleton instance
const notificationService = new NotificationService();

export default notificationService;

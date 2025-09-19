import i18n from "./utils/i18n.js";

console.log("🌍 Testing Multilingual System\n");

// Test 1: Basic translation
console.log("✅ Test 1: Basic Translation");
const loginSuccess = i18n.translate("auth.login_success");
console.log("auth.login_success:", loginSuccess);
console.log("");

// Test 2: Translation with interpolations
console.log("✅ Test 2: Translation with Interpolations");
const pointsEarned = i18n.translate("business.points_earned", { points: 50 });
console.log("business.points_earned (50 points):", pointsEarned);
console.log("");

// Test 3: Error messages
console.log("✅ Test 3: Error Messages");
const emailError = i18n.translate("errors.email_already_registered");
console.log("errors.email_already_registered:", emailError);
console.log("");

// Test 4: Field labels
console.log("✅ Test 4: Field Labels");
const nameField = i18n.translate("fields.name");
console.log("fields.name:", nameField);
console.log("");

// Test 5: Password policy
console.log("✅ Test 5: Password Policy");
const policyTitle = i18n.translate("password_policy.title");
const requirements = i18n.translate("password_policy.min_length");
console.log("password_policy.title:", policyTitle);
console.log("password_policy.min_length:", requirements);
console.log("");

// Test 6: Single language translation
console.log("✅ Test 6: Single Language Translation");
const indonesianOnly = i18n.translateSingle("auth.login_success", "id");
const englishOnly = i18n.translateSingle("auth.login_success", "en");
console.log("Indonesian only:", indonesianOnly);
console.log("English only:", englishOnly);
console.log("");

// Test 7: Create response format
console.log("✅ Test 7: Response Format");
const successResponse = i18n.createResponse(
  "success",
  "auth.registration_success",
  {
    user: { name: "John Doe", email: "john@example.com" },
  }
);
console.log("Success Response:", JSON.stringify(successResponse, null, 2));
console.log("");

// Test 8: Create error response format
console.log("✅ Test 8: Error Response Format");
const errorResponse = i18n.createErrorResponse(
  400,
  "errors.email_already_registered"
);
console.log("Error Response:", JSON.stringify(errorResponse, null, 2));
console.log("");

// Test 9: Validation error format
console.log("✅ Test 9: Validation Error Format");
const validationErrors = [
  {
    field: "email",
    code: "invalid_email",
    interpolations: {},
  },
  {
    field: "password",
    code: "required_field",
    interpolations: { field: "password" },
  },
];
const validationResponse = i18n.createValidationErrorResponse(validationErrors);
console.log(
  "Validation Error Response:",
  JSON.stringify(validationResponse, null, 2)
);
console.log("");

// Test 10: Non-existent key handling
console.log("✅ Test 10: Non-existent Key Handling");
const nonExistent = i18n.translate("non.existent.key");
console.log("non.existent.key:", nonExistent);
console.log("");

// Test 11: Supported languages
console.log("✅ Test 11: Supported Languages");
const supportedLangs = i18n.getSupportedLanguages();
console.log("Supported languages:", supportedLangs);
console.log("");

// Test 12: Add new translation dynamically
console.log("✅ Test 12: Dynamic Translation Addition");
i18n.addTranslation("test.dynamic", {
  id: "Terjemahan dinamis",
  en: "Dynamic translation",
});
const dynamicTranslation = i18n.translate("test.dynamic");
console.log("test.dynamic (added dynamically):", dynamicTranslation);
console.log("");

console.log("🎉 All tests completed!");

// Export untuk testing framework jika diperlukan
export default {
  testBasicTranslation: () => i18n.translate("auth.login_success"),
  testInterpolation: () =>
    i18n.translate("business.points_earned", { points: 100 }),
  testErrorResponse: () =>
    i18n.createErrorResponse(400, "errors.invalid_credentials"),
  testSuccessResponse: () =>
    i18n.createResponse("success", "auth.registration_success", {
      user: "test",
    }),
};

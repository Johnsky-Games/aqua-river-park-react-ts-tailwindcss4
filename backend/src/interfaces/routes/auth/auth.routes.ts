// src/interfaces/routes/auth/auth.routes.ts
import { Router } from "express";
import * as authController from "@/interfaces/controllers/auth/auth.controller";
import {
  confirmUser,
  resendConfirmation,
} from "@/interfaces/controllers/auth/confirm.controller";
import {
  sendRecovery,
  checkTokenStatus,
  resetPassword,
} from "@/interfaces/controllers/auth/recover.controller";
import { authMiddleware } from "@/interfaces/middlewares/auth/auth.middleware";
import { loginLimiter } from "@/infrastructure/security/rateLimit";
import { validate } from "@/interfaces/middlewares/validate/validateInput";
import { registerSchema, loginSchema } from "@/shared/validations/auth.schema";
// nuevo middleware para validar el token reCAPTCHA v3
import { verifyRecaptcha } from "@/interfaces/middlewares/validate/recaptcha.middleware";


const router = Router();

// Registro
router.post(
  "/register",
  verifyRecaptcha,           // 1️⃣ chequea reCAPTCHA
  validate(registerSchema),  // 2️⃣ valida payload
  authController.register    // 3️⃣ corre el controlador
);

// Login
router.post(
  "/login",
  verifyRecaptcha,           // 1️⃣ chequea reCAPTCHA
  loginLimiter,              // 2️⃣ rate‐limit
  validate(loginSchema),     // 3️⃣ valida payload
  authController.login       // 4️⃣ corre el controlador
);

router.post("/logout", authMiddleware, authController.logout);

// Confirmación de cuenta
router.get("/confirm/:token", confirmUser);
router.post("/resend-confirmation", loginLimiter, resendConfirmation);

// Recuperación de contraseña
router.post("/send-recovery", loginLimiter, sendRecovery);
router.post("/reset-password", resetPassword);
router.post("/check-token-status", checkTokenStatus);

// Refresh token
router.get("/refresh", authController.refreshToken);

export default router;

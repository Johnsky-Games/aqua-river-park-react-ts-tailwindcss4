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
import { loginLimiter } from "@/infraestructure/security/rateLimit";
import { validate } from "@/interfaces/middlewares/validate/validateInput";
import { registerSchema, loginSchema } from "@/shared/validations/auth.schema";

const router = Router();

// Registro y autenticación
router.post("/register", validate(registerSchema), authController.register);
router.post("/login", loginLimiter, validate(loginSchema), authController.login);
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

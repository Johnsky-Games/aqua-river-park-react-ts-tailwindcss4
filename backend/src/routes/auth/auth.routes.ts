import { Router } from "express";
import { login, register, logout } from "@/controllers/auth/auth.controller";
import {
  confirmUser,
  resendConfirmation,
} from "@/controllers/confirm/confirm.controller";
// import { checkTokenStatus } from '../controllers/tokenStatus.controller';
import {
  sendRecovery,
  checkTokenStatus,
  resetPassword,
} from "@/controllers/recover/recover.controller"; // 👈 nuevo

import { authMiddleware } from "@/middlewares/auth/auth.middleware";
import { getDashboard } from "@/controllers/dashboard/dashboard.controller";
import { checkRole } from "@/middlewares/role/role.middleware";
import { validate } from "@/middlewares/validate/validateInput";
import { registerSchema, loginSchema } from "@/validations/auth.schema";
import { loginLimiter } from "@/config/rateLimit";
import { AuthenticatedRequest } from "@/types/express";

const router = Router();

// Auth
router.post("/register", validate(registerSchema), register);
router.post("/login", loginLimiter, validate(loginSchema), login);
router.post("/logout", logout);

// Confirmación
router.get("/confirm/:token", confirmUser);
router.post("/resend-confirmation", loginLimiter, resendConfirmation);

// Recuperación de contraseña
router.post("/send-recovery", loginLimiter, sendRecovery); // 👈 nuevo
router.post("/reset-password", resetPassword); // 👈 nuevo
router.post("/reset-password/:token", resetPassword); // 👈 importante
router.post("/check-token-status", checkTokenStatus); // 👈 nuevo

// Protegidas
router.get(
  "/dashboard",
  authMiddleware,
  (req, res) => getDashboard(req as AuthenticatedRequest, res)
);

export default router;

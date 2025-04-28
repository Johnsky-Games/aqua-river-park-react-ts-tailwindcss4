import { Router } from "express";
import {
  login,
  register,
  logout,
  refreshToken,
} from "@/interfaces/controllers/auth/auth.controller";
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
import { checkRoleById } from "@/interfaces/middlewares/role/role.middleware";
import { getDashboard } from "@/interfaces/controllers/dashboard/dashboard.controller";
import { validate } from "@/interfaces/middlewares/validate/validateInput";
import { registerSchema, loginSchema } from "@/shared/validations/auth.schema";
import { loginLimiter } from "@/infraestructure/security/rateLimit";
import { AuthenticatedRequest } from "@/types/express";

const router = Router();

// ✅ Registro y autenticación
router.post("/register", validate(registerSchema), register);
router.post("/login", loginLimiter, validate(loginSchema), login);
router.post("/logout", logout);

// ✅ Confirmación de cuenta
router.get("/confirm/:token", confirmUser);
router.post("/resend-confirmation", loginLimiter, resendConfirmation);

// ✅ Recuperación de contraseña
router.post("/send-recovery", loginLimiter, sendRecovery);
router.post("/reset-password", resetPassword);
router.post("/reset-password/:token", resetPassword); // vía URL directa
router.post("/check-token-status", checkTokenStatus);

// ✅ Refresh token — asegurarte que devuelve void en el controller
router.get("/refresh", refreshToken);



export default router;

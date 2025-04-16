import { Router } from 'express';
import {
    login,
    register,
    logout,
} from '../controllers/auth.controller';
import { confirmUser, resendConfirmation } from '../controllers/confirm.controller';
// import { checkTokenStatus } from '../controllers/tokenStatus.controller';
import { sendRecovery, checkTokenStatus, resetPassword } from '../controllers/recover.controller'; // 👈 nuevo

import { authMiddleware } from '../middlewares/auth.middleware';
import { getDashboard } from '../controllers/dashboard.controller';
import { checkRole } from '../middlewares/role.middleware';
import { validate } from "../middlewares/validateInput";
import { registerSchema, loginSchema } from "../validations/auth.schema";
import { loginLimiter } from "../config/rateLimit";

const router = Router();

// Auth
router.post('/register', validate(registerSchema), register);
router.post('/login', loginLimiter, validate(loginSchema), login);
router.post('/logout', logout);

// Confirmación
router.get('/confirm/:token', confirmUser);
router.post('/resend-confirmation', loginLimiter, resendConfirmation);

// Recuperación de contraseña
router.post('/send-recovery', loginLimiter, sendRecovery);   // 👈 nuevo
router.post('/reset-password', resetPassword); // 👈 nuevo
router.post("/reset-password/:token", resetPassword); // 👈 importante
router.post('/check-token-status', checkTokenStatus); // 👈 nuevo

// Protegidas
router.get('/admin/dashboard', authMiddleware, checkRole(['admin']), getDashboard);

export default router;

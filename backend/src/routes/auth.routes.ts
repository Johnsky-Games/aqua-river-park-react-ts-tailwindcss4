import { Router } from 'express';
import {
    login,
    register,
    logout,
} from '../controllers/auth.controller';
import { confirmUser } from '../controllers/confirm.controller';
import { resendConfirmation } from '../controllers/resendConfirmation.controller';
// import { checkTokenStatus } from '../controllers/tokenStatus.controller';
import { sendRecovery, checkTokenStatus, resetPassword } from '../controllers/recover.controller'; // 👈 nuevo

import { authMiddleware } from '../middlewares/auth.middleware';
import { getDashboard } from '../controllers/dashboard.controller';
import { checkRole } from '../middlewares/role.middleware';

const router = Router();

// Auth
router.post('/register', register);
router.post('/login', login);
router.post('/logout', logout);

// Confirmación
router.get('/confirm/:token', confirmUser);
router.post('/resend-confirmation', resendConfirmation);

// Recuperación de contraseña
router.post('/send-recovery', sendRecovery);   // 👈 nuevo
router.post('/reset-password', resetPassword); // 👈 nuevo
router.post("/reset-password/:token", resetPassword); // 👈 importante
router.post('/check-token-status', checkTokenStatus); // 👈 nuevo

// Protegidas
router.get('/admin/dashboard', authMiddleware, checkRole(['admin']), getDashboard);

export default router;

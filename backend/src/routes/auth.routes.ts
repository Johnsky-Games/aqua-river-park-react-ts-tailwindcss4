// backend/src/routes/auth.routes.ts
import { Router } from 'express';
import { login, register } from '../controllers/auth.controller';
import { confirmUser } from '../controllers/confirm.controller';
import { resendConfirmation } from '../controllers/resendConfirmation.controller';
import { authMiddleware } from '../middlewares/auth.middleware';
import { getDashboard } from '../controllers/dashboard.controller';
import { checkRole } from '../middlewares/role.middleware';
import { checkTokenStatus } from '../controllers/tokenStatus.controller';

const router = Router();

// Envuelve tus funciones en funciones normales que devuelvan un Promise<void>
router.post('/register', register);
router.post('/login', login);
router.get('/confirm/:token', confirmUser);
router.post('/resend-confirmation', resendConfirmation);
router.post('/check-token-status', checkTokenStatus);


// Rutas protegidas
router.get('/admin/dashboard', authMiddleware, checkRole(['admin']), getDashboard);


export default router;

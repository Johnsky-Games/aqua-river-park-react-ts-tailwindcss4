// backend/src/routes/auth.routes.ts
import { Router, RequestHandler } from 'express';
import { login, register } from '../controllers/auth.controller';
import { confirmUser } from '../controllers/confirm.controller';
import { authMiddleware } from '../middlewares/auth.middleware'; // 👈 importa el middleware
import { getDashboard } from '../controllers/dashboard.controller';
import { checkRole } from '../middlewares/role.middleware';

const router = Router();

// Envuelve tus funciones en funciones normales que devuelvan un Promise<void>
router.post('/register', register);
router.post('/login', login);
router.get('/confirm/:token', confirmUser);

// Rutas protegidas
router.get('/admin/dashboard', authMiddleware, checkRole(['admin']), getDashboard);


export default router;

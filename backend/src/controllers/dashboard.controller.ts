// backend/src/controllers/dashboard.controller.ts
import { Request, Response } from 'express';
import { TokenPayload } from '../config/jwt';

interface AuthenticatedRequest extends Request {
  user?: TokenPayload; // 👈 el signo de pregunta permite que sea opcional
}


export const getDashboard = async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  if (!req.user) {
    res.status(401).json({ message: 'No autorizado' });
    return;
  }

  const user = req.user;

  res.json({
    message: `Hola ${user.name}, bienvenido al dashboard.`,
    role: user.role
  });
};


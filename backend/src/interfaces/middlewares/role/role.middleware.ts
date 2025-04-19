// role.middleware.ts
import { Response, NextFunction } from 'express';
import { AuthenticatedRequest } from '@/types/express'; // Solo importa esto si usas req.user

export const checkRole = (allowedRoles: string[]) => {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
    const user = req.user;

    if (!user || !allowedRoles.includes(user.role)) {
      res.status(403).json({ message: 'Acceso denegado: rol insuficiente' });
      return;
    }

    next();
  };
};

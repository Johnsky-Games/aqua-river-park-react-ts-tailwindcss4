// role.middleware.ts
import { Request, Response, NextFunction } from 'express';
import { TokenPayload } from '../config/jwt';

export const checkRole = (allowedRoles: string[]) => {
    return (req: Request, res: Response, next: NextFunction): void => {
        const user = req.user as TokenPayload;

        if (!req.user || !allowedRoles.includes(req.user.role)) {
            res.status(403).json({ message: 'Acceso denegado: rol insuficiente' });
            return;
        }

        next();
    };
};

// src/interfaces/middlewares/role/role.middleware.ts
import { Request, Response, NextFunction } from "express";
import { AuthenticatedRequest } from "@/types/express";

/**
 * Middleware que permite sólo a ciertos roles acceder
 * @param allowedRoles Lista de roles ("admin", "client", etc.)
 */
export const checkRole = (allowedRoles: string[]) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    const user = (req as AuthenticatedRequest).user;
    if (!user || !allowedRoles.includes(user.role)) {
      res.status(403).json({ message: "Acceso denegado" });
      return;
    }
    next();
  };
};

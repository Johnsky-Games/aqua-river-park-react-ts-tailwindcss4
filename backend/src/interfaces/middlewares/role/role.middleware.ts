// src/interfaces/middlewares/role/role.middleware.ts
import { Request, Response, NextFunction } from "express";
import { AuthenticatedRequest } from "@/types/express";

export const checkRoleById = (allowedIds: number[]) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    const user = (req as AuthenticatedRequest).user;
    if (!user || !allowedIds.includes(user.roleId)) {
      res.status(403).json({ message: "Acceso denegado" });
      return; // ✅ Asegura que se retorna void
    }
    next();
  };
};

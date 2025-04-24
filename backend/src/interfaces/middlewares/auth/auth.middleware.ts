// src/interfaces/middlewares/auth/auth.middleware.ts
import { Request, Response, NextFunction } from "express";
import { verifyAccessToken } from "@/shared/security/jwt";
import { AuthenticatedRequest } from "@/types/express";

export const authMiddleware = (
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    res.status(401).json({ message: "Token no proporcionado" });
    return;
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = verifyAccessToken(token);

    (req as AuthenticatedRequest).user = {
      id: decoded.id,
      email: decoded.email,
      name: decoded.name,
      role: decoded.role,
      roleId: decoded.roleId, // ✅ ya está validado por tipo TokenPayload
    };

    next();
  } catch {
    res.status(401).json({ message: "Token inválido o expirado" });
  }
};

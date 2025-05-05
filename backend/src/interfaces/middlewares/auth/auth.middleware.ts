import { Request, Response, NextFunction } from "express";
import { verifyAccessToken } from "@/shared/security/jwt";
import { AuthenticatedRequest } from "@/types/express";
import { errorCodes } from "@/shared/errors/errorCodes";

export const authMiddleware = (
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  const authHeader = req.headers.authorization;
  const token =
    authHeader?.startsWith("Bearer ")
      ? authHeader.slice(7)
      : (req as any).cookies?.auth_token;

  if (!token) {
    res.status(401).json({ message: "Token no proporcionado" });
    return;
  }

  try {
    // verifyAccessToken retorna { sub, role }
    const payload = verifyAccessToken(token);

    // Inyectamos directamente el payload (TokenPayload) en req.user
    (req as AuthenticatedRequest).user = payload;

    next();
  } catch (err: any) {
    const status =
      err.code === errorCodes.TOKEN_INVALID_OR_EXPIRED ? 401 : 500;
    res.status(status).json({ message: err.message });
  }
};

// backend/src/controllers/dashboard.controller.ts
import { Response } from "express";
import { AuthenticatedRequest } from "@/types/express";

export const getDashboard = async (
  req: AuthenticatedRequest,
  res: Response
): Promise<void> => {
  const user = req.user;

  if (!user) {
    res.status(401).json({ message: "No autorizado" });
    return;
  }

  res.json({
    message: `Hola ${user.name}, bienvenido al dashboard.`,
    role: user.role,
  });
};

// src/interfaces/controllers/user.controller.ts

import { Response, NextFunction } from "express";
import { AuthenticatedRequest } from "@/types/express";
import { userRepository } from "@/infrastructure/db/user.repository";
import { errorMessages } from "@/shared/errors/errorMessages";

export const getMe = async (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    if (!req.user) {
      res.status(401).json({ message: "Token no proporcionado" });
      return;
    }

    const user = await userRepository.findUserById(req.user.sub);
    if (!user) {
      res.status(404).json({ message: errorMessages.userNotFound });
      return;
    }

    res.json({
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role_name || "client",
    });
  } catch (err) {
    next(err);
  }
};

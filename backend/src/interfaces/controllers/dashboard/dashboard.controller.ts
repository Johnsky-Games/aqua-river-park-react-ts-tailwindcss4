// src/interfaces/controllers/dashboard/dashboard.controller.ts

import { Response } from "express";
import { AuthenticatedRequest } from "@/types/express";
import { userRepository } from "@/infraestructure/db/user.repository";

export const getDashboard = async (
  req: AuthenticatedRequest,
  res: Response
): Promise<void> => {
  if (!req.user) {
    res.status(401).json({ message: "No autorizado" });
    return;
  }

  try {
    const user = await userRepository.findUserById(req.user.sub);
    if (!user) {
      res.status(404).json({ message: "Usuario no encontrado" });
      return;
    }

    res.json({
      message: `Hola ${user.name}, bienvenido al dashboard.`,
      role: user.role_name || "client",
    });
  } catch (err) {
    console.error("Error al obtener dashboard:", err);
    res.status(500).json({ message: "Error del servidor" });
  }
};

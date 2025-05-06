// src/interfaces/controllers/auth/recover.controller.ts

import { Request, Response } from "express";
import * as recoveryService from "@/domain/services/auth/recovery.service";
import { userRepository } from "@/infraestructure/db/user.repository";
import { logError } from "@/infraestructure/logger/errorHandler";
import { errorCodes } from "@/shared/errors/errorCodes";

// ✅ 1. Enviar correo de recuperación
export const sendRecovery = async (req: Request, res: Response): Promise<void> => {
  const { email } = req.body;
  try {
    await recoveryService.sendRecoveryService({ userRepository }, email);
    res.status(200).json({ message: "Correo de recuperación enviado. Revisa tu bandeja." });
  } catch (error: any) {
    logError("Enviar recuperación", error);
    const status = error.code === errorCodes.EMAIL_NOT_REGISTERED ? 404 : 400;
    res.status(status).json({ message: error.message || "Error al enviar recuperación" });
  }
};

// ✅ 2. Verificar token
export const checkTokenStatus = async (req: Request, res: Response): Promise<void> => {
  const { token } = req.body;
  try {
    const isValid = await recoveryService.checkTokenStatusService({ userRepository }, token);
    res.status(200).json({ valid: isValid });
  } catch (error: any) {
    logError("Verificar token recuperación", error);
    res.status(500).json({ message: "Error al verificar token" });
  }
};

// ✅ 3. Cambiar contraseña
export const resetPassword = async (req: Request, res: Response): Promise<void> => {
  // permitimos recibir el token en params o en el body
  const tokenFromParams = req.params.token as string | undefined;
  const tokenFromBody = (req.body as any).token as string | undefined;
  const token = tokenFromParams ?? tokenFromBody;

  const { password } = req.body;

  if (!token) {
    res.status(400).json({ message: "Falta el token de recuperación" });
    return;
  }

  try {
    await recoveryService.resetPasswordService({ userRepository }, token, password);
    res.status(200).json({ message: "Contraseña actualizada correctamente" });
  } catch (error: any) {
    logError("Resetear contraseña", error);
    const status = error.code === errorCodes.INVALID_OR_EXPIRED_TOKEN ? 400 : 500;
    res.status(status).json({ message: error.message || "Error al cambiar contraseña" });
  }
};

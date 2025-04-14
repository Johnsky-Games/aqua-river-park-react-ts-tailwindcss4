import { Request, Response } from "express";
import * as authService from "../services/recovery.service";

// ✅ 1. Enviar correo de recuperación
export const sendRecovery = async (req: Request, res: Response) => {
  const { email } = req.body;

  try {
    await authService.sendRecoveryService(email);
    res.json({ message: "Correo de recuperación enviado. Revisa tu bandeja." });
  } catch (error: any) {
    console.error("❌ Error en sendRecovery:", error.message);
    res.status(error.status || 500).json({ message: error.message || "Error del servidor" });
  }
};

// ✅ 2. Verificar token
export const checkTokenStatus = async (req: Request, res: Response) => {
  const { token } = req.body;

  try {
    const isValid = await authService.checkTokenStatusService(token);
    res.json({ valid: isValid });
  } catch (error: any) {
    console.error("❌ Error en checkTokenStatus:", error.message);
    res.status(500).json({ message: "Error al verificar token" });
  }
};

// ✅ 3. Cambiar contraseña
export const resetPassword = async (req: Request, res: Response) => {
  const { token } = req.params;
  const { password } = req.body;

  try {
    await authService.resetPasswordService(token, password);
    res.json({ message: "Contraseña actualizada correctamente" });
  } catch (error: any) {
    console.error("❌ Error en resetPassword:", error.message);
    res.status(500).json({ message: "Error al cambiar contraseña" });
  }
};

import { Request, Response } from "express";
import * as authService from "../services/auth.service";
import { resendConfirmationService } from "../services/confirm.service";
import logger from "../utils/logger";

// ✅ REGISTRO
export const register = async (req: Request, res: Response) => {
  try {
    await authService.registerUser(req.body);
    res.status(201).json({
      message: "Registro exitoso. Revisa tu correo para confirmar tu cuenta.",
    });
    logger.info(`✅ Usuario registrado: ${req.body.email}`);
  } catch (error: any) {
    logger.error("❌ Registro:", error.message);
    res.status(400).json({ message: error.message || "Error al registrar" });
  }
};

// ✅ LOGIN
export const login = async (req: Request, res: Response) => {
  const { email, password } = req.body;

  try {
    const data = await authService.loginUser(email, password);
    res.json(data);
    logger.info(`✅ Login exitoso: ${email}`);
  } catch (error: any) {
    if (error.message === "Debes confirmar tu cuenta") {
      res.status(401).json({
        message: error.message,
        tokenExpired: error.tokenExpired || false,
      });
    } else {
      res
        .status(401)
        .json({ message: error.message || "Error al iniciar sesión" });
    }
  }
};

// ✅ LOGOUT (placeholder si usas JWT)
export const logout = async (_req: Request, res: Response) => {
  res.json({ message: "Sesión cerrada" });
};

// ✅ REENVIAR CONFIRMACIÓN
export const resendConfirmation = async (req: Request, res: Response) => {
  const { email } = req.body;

  try {
    await resendConfirmationService(email); // 👈 llamado correcto
    res.json({ message: "Correo de confirmación reenviado." });
    logger.info(`✅ Correo de confirmación reenviado: ${email}`);
  } catch (error: any) {
    logger.error("❌ Reenviar confirmación:", error.message);
    res.status(400).json({ message: error.message });
  }
};

// ✅ SOLICITAR RECUPERACIÓN DE CONTRASEÑA
export const sendRecovery = async (req: Request, res: Response) => {
  const { email } = req.body;

  try {
    await authService.sendResetPassword(email);
    res.json({ message: "Correo de recuperación enviado." });
    logger.info(`✅ Correo de recuperación enviado: ${email}`);
  } catch (error: any) {
    logger.error("❌ Enviar recuperación:", error.message);
    res.status(400).json({ message: error.message });
  }
};

// ✅ CAMBIAR CONTRASEÑA
export const resetPassword = async (req: Request, res: Response) => {
  const { token, password } = req.body;

  try {
    await authService.resetPassword(token, password);
    res.json({ message: "Contraseña actualizada con éxito." });
    logger.info(`✅ Clave actualizada con éxito`);
  } catch (error: any) {
    logger.error("❌ Reset password:", error.message);
    res.status(400).json({ message: error.message });
  }
};

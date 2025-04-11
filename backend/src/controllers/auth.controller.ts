import { Request, Response } from "express";
import * as authService from "../services/auth.service";

// ✅ REGISTRO
export const register = async (req: Request, res: Response) => {
  try {
    await authService.registerUser(req.body);
    res.status(201).json({
      message: "Registro exitoso. Revisa tu correo para confirmar tu cuenta.",
    });
  } catch (error: any) {
    console.error("❌ Registro:", error.message);
    res.status(400).json({ message: error.message || "Error al registrar" });
  }
};

// ✅ LOGIN
export const login = async (req: Request, res: Response) => {
  const { email, password } = req.body;

  try {
    const data = await authService.loginUser(email, password);
    res.json(data);
  } catch (error: any) {
    if (error.message === "Debes confirmar tu cuenta") {
      res.status(401).json({
        message: error.message,
        tokenExpired: error.tokenExpired || false,
      });
    } else {
      res.status(401).json({ message: error.message || "Error al iniciar sesión" });
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
    await authService.resendConfirmation(email);
    res.json({ message: "Correo de confirmación reenviado." });
  } catch (error: any) {
    console.error("❌ Reenviar confirmación:", error.message);
    res.status(400).json({ message: error.message });
  }
};

// ✅ SOLICITAR RECUPERACIÓN DE CONTRASEÑA
export const sendRecovery = async (req: Request, res: Response) => {
  const { email } = req.body;

  try {
    await authService.sendResetPassword(email);
    res.json({ message: "Correo de recuperación enviado." });
  } catch (error: any) {
    console.error("❌ Enviar recuperación:", error.message);
    res.status(400).json({ message: error.message });
  }
};

// ✅ CAMBIAR CONTRASEÑA
export const resetPassword = async (req: Request, res: Response) => {
  const { token, password } = req.body;

  try {
    await authService.resetPassword(token, password);
    res.json({ message: "Contraseña actualizada con éxito." });
  } catch (error: any) {
    console.error("❌ Reset password:", error.message);
    res.status(400).json({ message: error.message });
  }
};

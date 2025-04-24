import { Request, Response } from "express";
import * as authService from "@/domain/services/auth/auth.service";
import { userRepository } from "@/infraestructure/db/user.repository";
import logger from "@/infraestructure/logger/logger";

// ✅ REGISTRO
export const register = async (req: Request, res: Response) => {
  try {
    await authService.registerUser({ userRepository }, req.body);
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
export const login = async (req: Request, res: Response): Promise<void> => {
  const { email, password } = req.body;

  try {
    const { accessToken, refreshToken, user } = await authService.loginUser(
      { userRepository },
      email,
      password
    );

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    res.status(200).json({
      token: accessToken,
      user,
    });

    logger.info(`✅ Login exitoso: ${email}`);
  } catch (error: any) {
    logger.error("❌ Login:", error.message);

    if (error.message === "Debes confirmar tu cuenta") {
      res.status(401).json({
        message: error.message,
        tokenExpired: error.tokenExpired || false,
      });
      return; // ← IMPORTANTE
    }

    res.status(401).json({
      message: error.message || "Error al iniciar sesión",
    });
  }
};


// ✅ LOGOUT - elimina cookie
export const logout = (_req: Request, res: Response) => {
  res.clearCookie("refreshToken", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
  });
  res.json({ message: "Sesión cerrada correctamente." });
};

// ✅ ENVIAR CORREO DE RECUPERACIÓN
export const sendRecovery = async (req: Request, res: Response) => {
  const { email } = req.body;

  try {
    await authService.sendResetPassword({ userRepository }, email);
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
    await authService.resetPassword({ userRepository }, token, password);
    res.json({ message: "Contraseña actualizada con éxito." });
    logger.info(`✅ Clave actualizada con éxito`);
  } catch (error: any) {
    logger.error("❌ Reset password:", error.message);
    res.status(400).json({ message: error.message });
  }
};

// ✅ REFRESH TOKEN
export const refreshToken = async (req: Request, res: Response): Promise<void> => {
  const refreshToken = req.cookies?.refreshToken;
  if (!refreshToken) {
    res.status(401).json({ message: "No se encontró token de refresco" });
    return;
  }

  try {
    const { accessToken } = await authService.refreshAccessToken(
      { userRepository },
      refreshToken
    );

    // ❌ NO hacer: return res.json(...)
    // ✅ Solo llamar res.json(...) sin return
    res.json({ token: accessToken });
  } catch (error: any) {
    res.status(403).json({ message: error.message || "Token inválido" });
  }
};


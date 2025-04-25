import { Request, Response } from "express";
import * as authService from "@/domain/services/auth/auth.service";
import { userRepository } from "@/infraestructure/db/user.repository";
import { logError } from "@/infraestructure/logger/errorHandler";
import logger from "@/infraestructure/logger/logger";
import { errorCodes } from "@/shared/errors/errorCodes";

// ✅ REGISTRO
export const register = async (req: Request, res: Response) => {
  try {
    await authService.registerUser({ userRepository }, req.body);
    res.status(201).json({
      message: "Registro exitoso. Revisa tu correo para confirmar tu cuenta.",
    }); // Incrementar el contador de usuarios registrados
    logger.info(`✅ Usuario registrado: ${req.body.email}`);

  } catch (error: any) {
    logError("Registro", error);
    const status = error.code === errorCodes.EMAIL_ALREADY_REGISTERED ? 409 : 400;
    res.status(status).json({ message: error.message });
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
    logError("Login", error);

    if (error.code === errorCodes.ACCOUNT_NOT_CONFIRMED) {
      res.status(401).json({
        message: error.message,
        tokenExpired: error.tokenExpired || false,
      });
      return;
    }

    const status =
      error.code === errorCodes.EMAIL_NOT_REGISTERED ||
        error.code === errorCodes.INVALID_CREDENTIALS
        ? 401
        : 400;

    res.status(status).json({
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
    logError("Enviar recuperación", error);
    const status = error.code === errorCodes.EMAIL_NOT_REGISTERED ? 404 : 400;
    res.status(status).json({ message: error.message });
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
    logError("Reset password", error);
    const status = error.code === errorCodes.INVALID_OR_EXPIRED_TOKEN ? 400 : 500;
    res.status(status).json({ message: error.message });
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
    res.json({ token: accessToken });
  } catch (error: any) {
    logError("Refresh token", error);
    const status = error.code === errorCodes.TOKEN_INVALID_OR_EXPIRED ? 403 : 500;
    res.status(status).json({ message: error.message || "Token inválido" });
  }
};

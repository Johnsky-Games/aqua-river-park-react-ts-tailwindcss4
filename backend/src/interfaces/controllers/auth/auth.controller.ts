// src/interfaces/controllers/auth/auth.controller.ts

import { Request, Response } from "express";
import * as authService from "@/domain/services/auth/auth.service";
import { userRepository } from "@/infraestructure/db/user.repository";
import { logError } from "@/infraestructure/logger/errorHandler";
import logger from "@/infraestructure/logger/logger";
import { errorCodes } from "@/shared/errors/errorCodes";

const isProd = process.env.NODE_ENV === "production";

// Opciones comunes para todas las cookies
const cookieOptions = {
  httpOnly: true,
  secure: isProd,                           // solo HTTPS en prod
  sameSite: isProd ? "none" as const : "lax" as const,  
  path: "/",
};

export const register = async (req: Request, res: Response): Promise<void> => {
  try {
    await authService.registerUser({ userRepository }, req.body);
    res.status(201).json({
      message: "Registro exitoso. Revisa tu correo para confirmar tu cuenta.",
    });
    logger.info(`✅ Usuario registrado: ${req.body.email}`);
  } catch (error: any) {
    logError("Registro", error);
    const status =
      error.code === errorCodes.EMAIL_ALREADY_REGISTERED ? 409 : 400;
    res.status(status).json({ message: error.message });
  }
};

export const login = async (
  req: Request,
  res: Response
): Promise<void> => {
  const { email, password } = req.body;
  try {
    const { accessToken, refreshToken, user } = await authService.loginUser(
      { userRepository },
      email,
      password
    );

    // 1) Access Token
    res.cookie("auth_token", accessToken, {
      ...cookieOptions,
      maxAge: 15 * 60 * 1000, // 15 min
    });

    // 2) Refresh Token
    res.cookie("refresh_token", refreshToken, {
      ...cookieOptions,
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 días
    });

    // 3) Respuesta
    res.status(200).json({ success: true, user });
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

export const logout = (_req: Request, res: Response): void => {
  res
    .clearCookie("auth_token", cookieOptions)
    .clearCookie("refresh_token", cookieOptions)
    .json({ message: "Sesión cerrada correctamente." });
};

export const refreshToken = async (
  req: Request,
  res: Response
): Promise<void> => {
  const rt = req.cookies?.refresh_token;
  if (!rt) {
    res.status(401).json({ message: "No se encontró token de refresco" });
    return;
  }

  try {
    const { accessToken } = await authService.refreshAccessToken(
      { userRepository },
      rt
    );

    // Emitimos nuevo access token
    res
      .cookie("auth_token", accessToken, {
        ...cookieOptions,
        maxAge: 15 * 60 * 1000, // 15 min
      })
      .json({ success: true });
  } catch (error: any) {
    if (error.code === errorCodes.TOKEN_INVALID_OR_EXPIRED) {
      // Limpio ambas cookies al expirar
      res
        .clearCookie("auth_token", cookieOptions)
        .clearCookie("refresh_token", cookieOptions)
        .status(401)
        .json({
          message: "Sesión expirada. Por favor, inicia sesión nuevamente.",
        });
      return;
    }
    logError("Refresh token", error);
    res.status(500).json({ message: "Error interno al refrescar token" });
  }
};

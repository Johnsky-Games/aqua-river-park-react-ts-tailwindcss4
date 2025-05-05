// src/shared/security/jwt.ts

import jwt, { JwtPayload, Secret, SignOptions } from "jsonwebtoken";
import dotenv from "dotenv";
import { TokenPayload } from "@/types/express";
import { errorMessages } from "@/shared/errors/errorMessages";
import { errorCodes } from "@/shared/errors/errorCodes";
import { PRIVATE_KEY, PUBLIC_KEY } from "@/config/jwtKeys";

dotenv.config();

// Duraciones leídas desde .env
const ACCESS_EXPIRES_IN = process.env.JWT_ACCESS_EXPIRES_IN || "15m";
const REFRESH_EXPIRES_IN = process.env.JWT_REFRESH_EXPIRES_IN || "7d";

/**
 * Genera un JWT de acceso con payload { sub, role }.
 */
export const generateAccessToken = (payload: TokenPayload): string =>
  jwt.sign(
    payload as object,
    PRIVATE_KEY as Secret,
    {
      algorithm: "RS256",
      expiresIn: ACCESS_EXPIRES_IN,
    } as SignOptions
  );

/**
 * Genera un JWT de refresco con payload { sub, role }.
 */
export const generateRefreshToken = (payload: TokenPayload): string =>
  jwt.sign(
    payload as object,
    PRIVATE_KEY as Secret,
    {
      algorithm: "RS256",
      expiresIn: REFRESH_EXPIRES_IN,
    } as SignOptions
  );

/**
 * Verifica un JWT de acceso y retorna { sub, role }.
 * Lanza un error con código apropiado si es inválido o expirado.
 */
export const verifyAccessToken = (token: string): TokenPayload => {
  try {
    const decodedRaw = jwt.verify(
      token,
      PUBLIC_KEY as Secret,
      { algorithms: ["RS256"] }
    );
    const decoded = decodedRaw as JwtPayload;

    if (
      (typeof decoded.sub !== "string" && typeof decoded.sub !== "number") ||
      typeof decoded.role !== "string"
    ) {
      const e = new Error(errorMessages.tokenInvalidOrExpired) as any;
      e.code = errorCodes.TOKEN_INVALID_OR_EXPIRED;
      throw e;
    }

    return {
      sub:
        typeof decoded.sub === "number"
          ? decoded.sub
          : parseInt(decoded.sub as string, 10),
      role: decoded.role,
    };
  } catch (err: any) {
    const e = new Error(errorMessages.tokenInvalidOrExpired) as any;
    e.code = errorCodes.TOKEN_INVALID_OR_EXPIRED;
    throw e;
  }
};

/**
 * Verifica un JWT de refresco y retorna { sub, role }.
 * Lanza un error con código apropiado si es inválido o expirado.
 */
export const verifyRefreshToken = (token: string): TokenPayload => {
  try {
    const decodedRaw = jwt.verify(
      token,
      PUBLIC_KEY as Secret,
      { algorithms: ["RS256"] }
    );
    const decoded = decodedRaw as JwtPayload;

    if (
      (typeof decoded.sub !== "string" && typeof decoded.sub !== "number") ||
      typeof decoded.role !== "string"
    ) {
      const e = new Error(errorMessages.tokenInvalidOrExpired) as any;
      e.code = errorCodes.TOKEN_INVALID_OR_EXPIRED;
      throw e;
    }

    return {
      sub:
        typeof decoded.sub === "number"
          ? decoded.sub
          : parseInt(decoded.sub as string, 10),
      role: decoded.role,
    };
  } catch (err: any) {
    const e = new Error(errorMessages.tokenInvalidOrExpired) as any;
    e.code = errorCodes.TOKEN_INVALID_OR_EXPIRED;
    throw e;
  }
};

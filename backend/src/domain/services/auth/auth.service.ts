// src/domain/services/auth/auth.service.ts

import { UserRepository } from "@/domain/ports/user.repository";
import { RefreshTokenRepository } from "@/domain/ports/refreshToken.repository";
import sendConfirmationEmail from "@/infraestructure/mail/mailerConfirmation";
import {
  validateEmail,
  validateNewPassword,
  validatePasswordChange,
} from "@/shared/validations/validators";
import {
  generateAccessToken,
  generateRefreshToken,
  verifyRefreshToken as jwtVerifyRefresh,
  REFRESH_EXPIRES_IN,
} from "@/shared/security/jwt";
import { hashPassword } from "@/shared/hash";
import { generateToken } from "@/shared/tokens";
import { errorMessages } from "@/shared/errors/errorMessages";
import { errorCodes } from "@/shared/errors/errorCodes";
import { createError } from "@/shared/errors/createError";
import logger from "@/infraestructure/logger/logger";
import bcrypt from "bcryptjs";
import ms, { StringValue } from "ms";
import {
  passwordResetCounter,
  userLoginCounter,
  userRegisterCounter,
} from "@/infraestructure/metrics/customMetrics";
import { TokenPayload } from "@/types/express";

type RoleName = "admin" | "client";

const MAX_LOGIN_ATTEMPTS = 3;
const LOCK_DURATION_MINUTES = 15;

/**
 * Registro de nuevo usuario
 */
export const registerUser = async (
  deps: { userRepository: UserRepository },
  {
    name,
    email,
    password,
    phone,
  }: { name: string; email: string; password: string; phone: string }
) => {
  validateEmail(email);
  validateNewPassword(password);

  const existing = await deps.userRepository.findUserByEmail(email);
  if (existing) {
    throw createError(
      errorMessages.emailAlreadyRegistered,
      errorCodes.EMAIL_ALREADY_REGISTERED,
      409
    );
  }

  const password_hash = await hashPassword(password);
  const confirmation_token = generateToken();
  const confirmation_expires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24h

  await deps.userRepository.createUser({
    name,
    email,
    password_hash,
    phone,
    role_id: 4,
    confirmation_token,
    confirmation_expires,
  });

  userRegisterCounter.inc();
  await sendConfirmationEmail(email, confirmation_token);
};

/**
 * Inicio de sesión de usuario con lockout y registro de last_login
 */
export const loginUser = async (
  deps: {
    userRepository: UserRepository;
    refreshTokenRepository: RefreshTokenRepository;
  },
  email: string,
  password: string
) => {
  const { userRepository, refreshTokenRepository } = deps;
  const user = await userRepository.findUserByEmail(email);

  if (!user) {
    throw createError(
      errorMessages.invalidCredentials,
      errorCodes.INVALID_CREDENTIALS,
      404
    );
  }

  // Check locked_until
  if (user.locked_until && new Date(user.locked_until) > new Date()) {
    throw createError(
      `Cuenta bloqueada hasta ${user.locked_until}`,
      errorCodes.INVALID_CREDENTIALS,
      403
    );
  }

  if (!user.is_confirmed) {
    const expired =
      !user.confirmation_token ||
      !user.confirmation_expires ||
      new Date(user.confirmation_expires) < new Date();
    const e = createError(
      errorMessages.accountNotConfirmed,
      errorCodes.ACCOUNT_NOT_CONFIRMED,
      401
    );
    (e as any).tokenExpired = expired;
    throw e;
  }

  // Verify password
  const match = await bcrypt.compare(password, user.password_hash);
  if (!match) {
    // Increment failed attempts
    const attempts = (user.login_attempts || 0) + 1;
    await userRepository.updateLoginAttempts(user.id, attempts);

    // If exceeded max, lock account
    if (attempts >= MAX_LOGIN_ATTEMPTS) {
      const until = new Date(Date.now() + LOCK_DURATION_MINUTES * 60000);
      await userRepository.updateLockedUntil(user.id, until);
    }

    throw createError(
      errorMessages.invalidCredentials,
      errorCodes.INVALID_CREDENTIALS,
      401
    );
  }

  // Reset attempts and lock
  await userRepository.updateLoginAttempts(user.id, 0);
  await userRepository.updateLockedUntil(user.id, null);

  // Record last login
  await userRepository.updateLastLogin(user.id, new Date());

  userLoginCounter.inc();

  const payload: TokenPayload = {
    sub: user.id,
    role: (user.role_name || "client") as RoleName,
  };

  // Genera tokens
  const accessToken = generateAccessToken(payload);
  const { token: refreshToken, jti } = generateRefreshToken(payload);

  // Persiste el refresh token en BD
  const expiresAt = new Date(Date.now() + ms(REFRESH_EXPIRES_IN as StringValue));
  await refreshTokenRepository.saveToken(jti, user.id, expiresAt);

  return {
    accessToken,
    refreshToken,
    user: {
      id: user.id,
      name: user.name,
      role: payload.role,
    },
  };
};

/**
 * Refrescar token de acceso usando refresh token
 */
export const refreshAccessToken = async (
  deps: {
    userRepository: UserRepository;
    refreshTokenRepository: RefreshTokenRepository;
  },
  refreshToken: string
) => {
  try {
    const decoded = jwtVerifyRefresh(refreshToken) as TokenPayload & { jti: string };
    const { sub: userId, role, jti } = decoded;

    const stored = await deps.refreshTokenRepository.findToken(jti);
    if (!stored || stored.revoked || stored.expiresAt < new Date()) {
      throw new Error("Revocado o expirado");
    }

    await deps.userRepository.findUserById(userId);

    const newPayload: TokenPayload = { sub: userId, role };
    const accessToken = generateAccessToken(newPayload);
    return { accessToken };
  } catch {
    throw createError(
      errorMessages.tokenInvalidOrExpired,
      errorCodes.TOKEN_INVALID_OR_EXPIRED,
      403
    );
  }
};

/**
 * Enviar enlace de recuperación de contraseña
 */
export const sendResetPassword = async (
  deps: { userRepository: UserRepository },
  email: string
) => {
  const { userRepository } = deps;
  const user = await userRepository.findUserByEmail(email);
  if (!user) {
    throw createError(
      errorMessages.emailNotRegistered,
      errorCodes.EMAIL_NOT_REGISTERED,
      404
    );
  }

  const token = generateToken();
  const expires = new Date(Date.now() + 60 * 60 * 1000); // 1h
  await userRepository.updateResetToken(email, token, expires);

  passwordResetCounter.inc();
  logger.info(`📧 Enlace de recuperación enviado a ${email}`);
};

/**
 * Cambiar contraseña usando token válido
 */
export const resetPassword = async (
  deps: { userRepository: UserRepository },
  token: string,
  newPassword: string
) => {
  const { userRepository } = deps;
  const user = await userRepository.findUserByResetToken(token);

  passwordResetCounter.inc();

  if (!user) {
    throw createError(
      errorMessages.invalidOrExpiredToken,
      errorCodes.INVALID_OR_EXPIRED_TOKEN,
      400
    );
  }

  await validatePasswordChange(newPassword, user.email, user.password_hash);
  const password_hash = await hashPassword(newPassword);
  await userRepository.updatePassword(user.id, password_hash);
};

/**
 * Verificar si un token de recuperación es válido
 */
export const checkResetToken = async (
  deps: { userRepository: UserRepository },
  token: string
): Promise<boolean> => {
  const { userRepository } = deps;
  const user = await userRepository.findUserByResetToken(token);

  if (!user || !user.reset_expires) {
    return false;
  }
  const expires =
    user.reset_expires instanceof Date
      ? user.reset_expires
      : new Date(user.reset_expires);
  return expires > new Date();
};

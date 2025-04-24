// src/domain/services/auth/auth.service.ts
import bcrypt from "bcryptjs";
import crypto from "crypto";
import sendConfirmationEmail from "@/infraestructure/mail/mailerConfirmation";
import { UserRepository } from "@/domain/ports/user.repository";
import {
  validateEmail,
  validateNewPassword,
  validatePasswordChange,
} from "@/shared/validations/validators";
import logger from "@/infraestructure/logger/logger";
import {
  generateAccessToken,
  generateRefreshToken,
  verifyRefreshToken,
} from "@/shared/security/jwt";

// 👇 Define aquí los roles permitidos para el JWT
type RoleName = "admin" | "client";

export const registerUser = async (
  deps: { userRepository: UserRepository },
  {
    name,
    email,
    password,
    phone,
  }: {
    name: string;
    email: string;
    password: string;
    phone: string;
  }
) => {
  const { userRepository } = deps;
  validateEmail(email);
  validateNewPassword(password);

  const existingUser = await userRepository.findUserByEmail(email);
  if (existingUser) throw new Error("El correo ya está registrado");

  const password_hash = await bcrypt.hash(password, 10);
  const confirmation_token = crypto.randomBytes(32).toString("hex");
  const confirmation_expires = new Date(Date.now() + 24 * 60 * 60 * 1000);

  await userRepository.createUser({
    name,
    email,
    password_hash,
    phone,
    role_id: 4, // 👈 este número deberías mapearlo con un nombre si lo necesitas
    confirmation_token,
    confirmation_expires,
  });

  await sendConfirmationEmail(email, confirmation_token);
};

export const loginUser = async (
  deps: { userRepository: UserRepository },
  email: string,
  password: string
) => {
  const { userRepository } = deps;
  const user = await userRepository.findUserByEmail(email);
  if (!user) throw new Error("Correo no registrado");

  if (!user.is_confirmed) {
    const tokenExpired =
      !user.confirmation_token ||
      !user.confirmation_expires ||
      new Date(user.confirmation_expires) < new Date();

    throw {
      message: "Debes confirmar tu cuenta",
      tokenExpired,
    };
  }

  const isMatch = await bcrypt.compare(password, user.password_hash);
  if (!isMatch) throw new Error("Contraseña incorrecta");

  const accessToken = generateAccessToken({
    id: user.id,
    email: user.email,
    name: user.name,
    role: (user.role_name || "client") as RoleName,
    roleId: user.role_id || 0, // ✅ fallback por si es undefined
  });

  const refreshToken = generateRefreshToken({
    id: user.id,
    email: user.email,
    name: user.name,
    role: (user.role_name || "client") as RoleName,
    roleId: user.role_id || 0,
  });

  return {
    accessToken,
    refreshToken,
    user: {
      email: user.email,
      isConfirmed: Boolean(user.is_confirmed),
    },
  };
};

export const refreshAccessToken = async (
  deps: { userRepository: UserRepository },
  refreshToken: string
) => {
  try {
    const payload = verifyRefreshToken(refreshToken);
    const { userRepository } = deps;

    const user = await userRepository.findUserBasicByEmail(payload.email);
    if (!user) throw new Error("Usuario no encontrado");

    const newAccessToken = generateAccessToken({
      id: payload.id,
      email: payload.email,
      name: payload.name,
      role: payload.role,
      roleId: payload.roleId || 0,
    });

    return { accessToken: newAccessToken };
  } catch (error) {
    throw new Error("Token de refresco inválido o expirado");
  }
};

export const sendResetPassword = async (
  deps: { userRepository: UserRepository },
  email: string
) => {
  const { userRepository } = deps;
  const user = await userRepository.findUserByEmail(email);
  if (!user) throw new Error("Correo no registrado");

  const token = crypto.randomBytes(32).toString("hex");
  const expires = new Date(Date.now() + 60 * 60 * 1000);

  await userRepository.updateResetToken(email, token, expires);
  logger.info(`📧 Enlace de recuperación enviado a ${email}`);
};

export const resetPassword = async (
  deps: { userRepository: UserRepository },
  token: string,
  newPassword: string
) => {
  const { userRepository } = deps;
  const user = await userRepository.findUserByResetToken(token);
  if (!user) throw new Error("Token inválido o expirado");

  await validatePasswordChange(newPassword, user.email, user.password_hash);

  const password_hash = await bcrypt.hash(newPassword, 10);
  await userRepository.updatePassword(user.id, password_hash);
};

export const checkResetToken = async (
  deps: { userRepository: UserRepository },
  token: string
) => {
  const { userRepository } = deps;
  const user = await userRepository.findUserByResetToken(token);
  return (
    !!user &&
    user.reset_expires !== null &&
    user.reset_expires !== undefined &&
    new Date(user.reset_expires) > new Date()
  );
};

// src/services/auth.service.ts
import bcrypt from "bcryptjs";
import crypto from "crypto";
import { generateToken } from "../config/jwt";
import sendConfirmationEmail from "../utils/mailerConfirmation";
import {
  createUser,
  findUserBasicByEmail,
  findUserByEmail,
  findUserByResetToken,
  updateConfirmationToken,
  updatePassword,
  updateResetToken,
} from "../repositories/user.repository";

export const registerUser = async ({
  name,
  email,
  password,
  phone,
}: {
  name: string;
  email: string;
  password: string;
  phone: string;
}) => {
  const existingUser = await findUserBasicByEmail(email);
  if (existingUser) throw new Error("El correo ya está registrado");

  const password_hash = await bcrypt.hash(password, 10);
  const confirmation_token = crypto.randomBytes(32).toString("hex");
  const confirmation_expires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24h

  await createUser({
    name,
    email,
    password_hash,
    phone,
    role_id: 4,
    confirmation_token,
    confirmation_expires,
  });

  await sendConfirmationEmail(email, confirmation_token);
};

export const loginUser = async (email: string, password: string) => {
  const user = await findUserByEmail(email);
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

  const token = generateToken({
    id: user.id,
    email: user.email,
    name: user.name,
    role: user.role_name || "client",
  });

  return {
    token,
    user: {
      email: user.email,
      isConfirmed: Boolean(user.is_confirmed),
    },
  };
};

export const resendConfirmation = async (email: string) => {
  const user = await findUserByEmail(email);
  if (!user) throw new Error("Correo no registrado");

  if (user.is_confirmed) throw new Error("La cuenta ya está confirmada");

  const token = crypto.randomBytes(32).toString("hex");
  const expires = new Date(Date.now() + 24 * 60 * 60 * 1000);

  await updateConfirmationToken(email, token, expires);
  await sendConfirmationEmail(email, token);
};

export const sendResetPassword = async (email: string) => {
  const user = await findUserByEmail(email);
  if (!user) throw new Error("Correo no registrado");

  const token = crypto.randomBytes(32).toString("hex");
  const expires = new Date(Date.now() + 1 * 60 * 60 * 1000); // 1h

  await updateResetToken(email, token, expires);

  // Aquí enviarías un correo real con el link
  console.log(`📧 Enlace de recuperación: http://localhost:3000/reset-password/${token}`);
};

export const resetPassword = async (token: string, newPassword: string) => {
  const user = await findUserByResetToken(token);
  if (!user) throw new Error("Token inválido o expirado");

  const password_hash = await bcrypt.hash(newPassword, 10);
  await updatePassword(user.id, password_hash);
};

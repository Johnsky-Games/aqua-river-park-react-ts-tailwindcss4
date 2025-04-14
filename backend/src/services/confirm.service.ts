// src/services/confirm.service.ts
import crypto from "crypto";
import sendConfirmationEmail from "../utils/mailerConfirmation";
import * as userRepo from "../repositories/user.repository";

export const confirmAccountService = async (token: string, email?: string) => {
  const user = await userRepo.findUserByToken(token);

  if (!user) {
    if (email) {
      const userFromEmail = await userRepo.findUserByEmail(email);
      if (userFromEmail?.is_confirmed === 1) {
        return { code: 200, message: "La cuenta ya ha sido confirmada." };
      }
    }
    return { code: 400, message: "Token inválido o expirado" };
  }

  if (user.is_confirmed === 1) {
    return { code: 200, message: "La cuenta ya ha sido confirmada." };
  }

  if (new Date(user.confirmation_expires) < new Date()) {
    return { code: 400, message: "Token inválido o expirado" };
  }

  await userRepo.confirmUserById(user.id);
  return { code: 200, message: "Cuenta confirmada exitosamente." };
};

export const resendConfirmationService = async (email: string) => {
  const user = await userRepo.findUserByEmail(email);
  if (!user) throw new Error("Correo no encontrado");

  if (user.is_confirmed) throw new Error("La cuenta ya está confirmada");

  const token = crypto.randomBytes(32).toString("hex");
  const expires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24h

  await userRepo.updateConfirmationToken(email, token, expires);
  await sendConfirmationEmail(email, token);
};

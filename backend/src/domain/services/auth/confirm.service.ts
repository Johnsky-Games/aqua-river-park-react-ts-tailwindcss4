// src/domain/services/auth/confirm.service.ts
import crypto from "crypto";
import sendConfirmationEmail from "@/infraestructure/mail/mailerConfirmation";
import { UserRepository } from "@/domain/ports/user.repository";

export const confirmAccountService = async (
  deps: { userRepository: UserRepository },
  token: string,
  email?: string
) => {
  const { userRepository } = deps;
  const user = await userRepository.findUserByToken(token);

  if (!user) {
    if (email) {
      const userFromEmail = await userRepository.findUserByEmail(email);
      if (userFromEmail?.is_confirmed === true) {
        return { code: 200, message: "La cuenta ya ha sido confirmada." };
      }
    }
    return { code: 400, message: "Token inválido o expirado" };
  }

  if (user.is_confirmed === true) {
    return { code: 200, message: "La cuenta ya ha sido confirmada." };
  }

  if (!user.confirmation_expires || new Date(user.confirmation_expires) < new Date()) {
    return { code: 400, message: "Token inválido o expirado" };
  }

  await userRepository.confirmUserById(user.id);
  return { code: 200, message: "Cuenta confirmada exitosamente." };
};

export const resendConfirmationService = async (
  deps: { userRepository: UserRepository },
  email: string
) => {
  const { userRepository } = deps;
  const user = await userRepository.findUserByEmail(email);
  if (!user) throw new Error("Correo no encontrado");
  if (user.is_confirmed === true) throw new Error("La cuenta ya está confirmada");

  const token = crypto.randomBytes(32).toString("hex");
  const expires = new Date(Date.now() + 24 * 60 * 60 * 1000);

  await userRepository.updateConfirmationToken(email, token, expires);
  await sendConfirmationEmail(email, token);
};

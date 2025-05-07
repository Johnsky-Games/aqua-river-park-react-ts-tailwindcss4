// src/domain/services/auth/confirm.service.ts
import { UserRepository } from "@/domain/ports/user.repository";
import sendConfirmationEmail from "@/infrastructure/mail/mailerConfirmation";
import { generateToken } from "@/shared/tokens";
import { errorMessages } from "@/shared/errors/errorMessages";
import { errorCodes } from "@/shared/errors/errorCodes";
import { createError } from "@/shared/errors/createError";

/**
 * ✅ Confirma la cuenta de un usuario mediante un token
 */
export const confirmAccountService = async (
  deps: { userRepository: UserRepository },
  token: string,
  email?: string
): Promise<{ code: number; message: string }> => {
  const { userRepository } = deps;

  const user = await userRepository.findUserByToken(token);

  if (!user) {
    if (email) {
      const userFromEmail = await userRepository.findUserByEmail(email);
      if (userFromEmail?.is_confirmed) {
        return { code: 200, message: errorMessages.accountAlreadyConfirmed };
      }
    }
    return { code: 400, message: errorMessages.invalidOrExpiredToken };
  }

  if (user.is_confirmed) {
    return { code: 200, message: errorMessages.accountAlreadyConfirmed };
  }

  if (!user.confirmation_expires || new Date(user.confirmation_expires) < new Date()) {
    return { code: 400, message: errorMessages.invalidOrExpiredToken };
  }

  await userRepository.confirmUserById(user.id);

  return { code: 200, message: errorMessages.accountConfirmedSuccessfully };
};

/**
 * ✅ Reenvía un nuevo token de confirmación al usuario
 */
export const resendConfirmationService = async (
  deps: { userRepository: UserRepository },
  email: string
): Promise<void> => {
  const { userRepository } = deps;

  const user = await userRepository.findUserByEmail(email);

  if (!user) {
    throw createError(
      errorMessages.emailNotRegistered,
      errorCodes.EMAIL_NOT_REGISTERED,
      404
    );
  }

  if (user.is_confirmed) {
    throw createError(
      errorMessages.accountAlreadyConfirmed,
      errorCodes.ACCOUNT_ALREADY_CONFIRMED,
      409
    );
  }

  const token = generateToken();
  const expires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 horas

  await userRepository.updateConfirmationToken(email, token, expires);
  await sendConfirmationEmail(email, token);
};

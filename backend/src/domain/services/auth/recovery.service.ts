// src/domain/services/auth/recovery.service.ts
import sendRecoveryEmail from "@/infrastructure/mail/mailerRecovery";
import { UserRepository } from "@/domain/ports/user.repository";
import { validatePasswordChange } from "@/shared/validations/validators";
import { hashPassword } from "@/shared/hash";
import { generateToken } from "@/shared/tokens";
import { errorMessages } from "@/shared/errors/errorMessages";
import { errorCodes } from "@/shared/errors/errorCodes";
import { createError } from "@/shared/errors/createError";

/**
 * ✅ Enviar enlace de recuperación por correo
 */
export const sendRecoveryService = async (
  deps: { userRepository: UserRepository },
  email: string
) => {
  const { userRepository } = deps;
  const user = await userRepository.findUserBasicByEmail(email);

  if (!user) {
    throw createError(errorMessages.emailNotRegistered, errorCodes.EMAIL_NOT_REGISTERED);
  }

  const token = generateToken();
  const expires = new Date(Date.now() + 60 * 60 * 1000); // 1 hora

  await userRepository.updateResetToken(email, token, expires);
  await sendRecoveryEmail(email, token);
};

/**
 * ✅ Verificar validez de token de recuperación
 */
export const checkTokenStatusService = async (
  deps: { userRepository: UserRepository },
  token: string
): Promise<boolean> => {
  const { userRepository } = deps;
  const resetData = await userRepository.getResetTokenExpiration(token);

  return !!resetData?.reset_expires && new Date(resetData.reset_expires) > new Date();
};

/**
 * ✅ Cambiar contraseña mediante token válido
 */
export const resetPasswordService = async (
  deps: { userRepository: UserRepository },
  token: string,
  newPassword: string
) => {
  const { userRepository } = deps;
  const user = await userRepository.findUserByResetToken(token);

  if (!user) {
    throw createError(errorMessages.invalidOrExpiredToken, errorCodes.INVALID_OR_EXPIRED_TOKEN);
  }

  // Validar reglas de seguridad de contraseña
  await validatePasswordChange(newPassword, user.email, user.password_hash);

  const password_hash = await hashPassword(newPassword);
  await userRepository.updatePassword(user.id, password_hash);
};

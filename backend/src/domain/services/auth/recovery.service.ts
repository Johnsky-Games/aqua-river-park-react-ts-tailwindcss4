import crypto from "crypto";
import bcrypt from "bcryptjs";
import sendRecoveryEmail from "@/infraestructure/mail/mailerRecovery";
import { UserRepository } from "@/domain/ports/user.repository";
import { validatePasswordChange } from "@/shared/validations/validators";

/**
 * ✅ Enviar enlace de recuperación por correo
 */
export const sendRecoveryService = async (
  deps: { userRepository: UserRepository },
  email: string
) => {
  const { userRepository } = deps;
  const user = await userRepository.findUserBasicByEmail(email);
  if (!user) throw new Error("Correo no registrado");

  const token = crypto.randomBytes(32).toString("hex");
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
  if (!user) throw new Error("Token inválido o expirado");

  // Validar que no sea la misma contraseña ni igual al correo (reglas fuertes)
  await validatePasswordChange(newPassword, user.email, user.password_hash);

  const password_hash = await bcrypt.hash(newPassword, 10);
  await userRepository.updatePassword(user.id, password_hash);
};

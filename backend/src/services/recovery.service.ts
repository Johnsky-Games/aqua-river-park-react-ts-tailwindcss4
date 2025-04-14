import crypto from "crypto";
import bcrypt from "bcryptjs";
import sendRecoveryEmail from "../utils/mailerRecovery";
import * as userRepo from "../repositories/user.repository";

// ✅ 1. Enviar correo de recuperación
export const sendRecoveryService = async (email: string) => {
  const user = await userRepo.findUserBasicByEmail(email);
  if (!user) throw new Error("Correo no registrado");

  const token = crypto.randomBytes(32).toString("hex");
  const expires = new Date(Date.now() + 60 * 60 * 1000); // 1 hora

  await userRepo.updateResetToken(email, token, expires);
  await sendRecoveryEmail(email, token);
};

// ✅ 2. Verificar token
export const checkTokenStatusService = async (token: string): Promise<boolean> => {
  const resetData = await userRepo.getResetTokenExpiration(token);
  if (!resetData || new Date(resetData.reset_expires) < new Date()) return false;
  return true;
};

// ✅ 3. Cambiar contraseña
export const resetPasswordService = async (token: string, newPassword: string) => {
  const user = await userRepo.findUserByResetToken(token);
  if (!user) throw new Error("Token inválido o expirado");

  const password_hash = await bcrypt.hash(newPassword, 10);
  await userRepo.updatePassword(user.id, password_hash);
};

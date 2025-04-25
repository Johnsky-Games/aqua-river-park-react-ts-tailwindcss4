import { Request, Response } from "express";
import {
  confirmAccountService,
  resendConfirmationService,
} from "@/domain/services/auth/confirm.service";
import { userRepository } from "@/infraestructure/db/user.repository";
import logger from "@/infraestructure/logger/logger";
import { logError } from "@/infraestructure/logger/errorHandler";
import { errorCodes } from "@/shared/errors/errorCodes";

// ✅ CONFIRMAR USUARIO
export const confirmUser = async (req: Request, res: Response): Promise<void> => {
  const { token } = req.params;
  const { email } = req.query;

  try {
    const result = await confirmAccountService({ userRepository }, token, email as string | undefined);
    res.status(result.code).json({ message: result.message });
  } catch (error: any) {
    logError("Confirmar usuario", error);

    const status =
      error.code === errorCodes.INVALID_OR_EXPIRED_TOKEN
        ? 400
        : 500;

    res.status(status).json({ message: error.message || "Error en el servidor" });
  }
};

// ✅ REENVIAR CONFIRMACIÓN
export const resendConfirmation = async (req: Request, res: Response): Promise<void> => {
  const { email } = req.body;

  try {
    await resendConfirmationService({ userRepository }, email);
    res.status(200).json({
      message: "Se envió un nuevo enlace de confirmación a tu correo",
    });
    logger.info(`✅ Correo de confirmación reenviado: ${email}`);
  } catch (error: any) {
    logError("Reenviar confirmación", error);

    const status =
      error.code === errorCodes.EMAIL_NOT_REGISTERED
      || error.code === errorCodes.ACCOUNT_ALREADY_CONFIRMED
        ? 409
        : 400;

    res.status(status).json({
      message: error.message || "Error al reenviar confirmación",
    });
  }
};

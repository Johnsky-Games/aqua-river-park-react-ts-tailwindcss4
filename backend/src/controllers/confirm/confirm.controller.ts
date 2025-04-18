// src/controllers/confirm.controller.ts
import { Request, Response } from "express";
import {
    confirmAccountService,
    resendConfirmationService,
  } from "@/services/confirm/confirm.service";  
import logger from "@/utils/logger";

// ✅ CONFIRMAR USUARIO
export const confirmUser = async (req: Request, res: Response): Promise<void> => {
    const { token } = req.params;
    const { email } = req.query;

    try {
        const result = await confirmAccountService(token, email as string | undefined);
        res.status(result.code).json({ message: result.message });
    } catch (error: any) {
        logger.error("❌ Error al confirmar:", error);
        res.status(500).json({ message: "Error en el servidor" });
    }
};


// ✅ REENVIAR CONFIRMACIÓN
export const resendConfirmation = async (req: Request, res: Response): Promise<void> => {
    const { email } = req.body;

    try {
        await resendConfirmationService(email);
        res.status(200).json({
            message: "Se envió un nuevo enlace de confirmación a tu correo",
        });
    } catch (error: any) {
        logger.error("❌ Error al reenviar confirmación:", error.message || error);
        res.status(400).json({
            message: error.message || "Error al reenviar confirmación",
        });
    }
};

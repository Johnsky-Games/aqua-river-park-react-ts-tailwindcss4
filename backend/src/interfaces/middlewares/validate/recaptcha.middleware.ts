// src/interfaces/middlewares/validate/recaptcha.middleware.ts
import { Request, Response, NextFunction } from "express";
import { createError } from "@/shared/errors/createError";
import { verifyRecaptcha as recaptchaService } from "@/shared/recaptcha";

export async function verifyRecaptcha(
  req: Request,
  res: Response,
  next: NextFunction
) {
  // Leemos el token desde la cabecera
  const token = req.header("x-recaptcha-token");
  if (!token) {
    console.warn("⚠️ reCAPTCHA: faltó la cabecera x-recaptcha-token");
    // mensaje primero, luego código HTTP
    return next(createError("Token de reCAPTCHA faltante", 400));
  }

  try {
    // Verificamos con el servicio de Google
    const ok = await recaptchaService(token);
    if (!ok) {
      console.warn("❌ reCAPTCHA: validación fallida para token", token);
      return next(createError("Validación de reCAPTCHA fallida", 400));
    }
    // Si todo OK, continuamos
    return next();
  } catch (err) {
    console.error("❌ Error interno al verificar reCAPTCHA:", err);
    return next(createError("Error interno de reCAPTCHA", 500));
  }
}

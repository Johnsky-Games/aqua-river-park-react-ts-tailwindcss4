// src/interfaces/middlewares/validate/recaptcha.middleware.ts
import { Request, Response, NextFunction } from "express";
import { createError } from "@/shared/errors/createError";        // IMPORT nombrado
import { verifyRecaptchaToken } from "@/shared/recaptcha";

export async function verifyRecaptcha(
  req: Request,
  res: Response,
  next: NextFunction
) {
  const token = req.header("x-recaptcha-token");
  if (!token) {
    return next(createError("Token de reCAPTCHA faltante", 400));
  }

  try {
    const { success, score, action } = await verifyRecaptchaToken(token);
    if (!success || score < 0.5 || action !== "auth") {
      return next(createError("Validación de reCAPTCHA fallida", 400));
    }
    next();
  } catch (err) {
    return next(createError("Error validando reCAPTCHA", 500));
  }
}

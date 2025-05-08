// src/interfaces/middlewares/validate/recaptcha.middleware.ts
import { Request, Response, NextFunction } from "express";
import { createError } from "@/shared/errors/createError";
import { verifyRecaptchaToken, RecaptchaResponse } from "@/shared/recaptcha";

export async function verifyRecaptcha(
  req: Request,
  _res: Response,
  next: NextFunction
) {
  const token = req.header("x-recaptcha-token");
  if (!token) {
    return next(createError("Token de reCAPTCHA faltante", 400));
  }

  let result: RecaptchaResponse;
  try {
    result = await verifyRecaptchaToken(token);
  } catch (err) {
    console.error("reCAPTCHA error:", err);
    return next(createError("Error validando reCAPTCHA", 500));
  }

  if (!result.success) {
    return next(createError("Validación de reCAPTCHA fallida", 400));
  }
  if (result.score < 0.5) {
    return next(createError("Score de reCAPTCHA demasiado bajo", 400));
  }
  if (result.action !== "login" && result.action !== "register") {
    return next(createError("Acción de reCAPTCHA inválida", 400));
  }

  next();
}

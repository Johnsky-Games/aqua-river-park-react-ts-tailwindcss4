// config/rateLimit.ts
import rateLimit from "express-rate-limit";

export const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 5,
  message: "Demasiados intentos. Intenta nuevamente en 15 minutos.",
  standardHeaders: true,
  legacyHeaders: false,
});

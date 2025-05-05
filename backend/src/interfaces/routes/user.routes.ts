// src/interfaces/routes/user.routes.ts
import { Router }             from "express";
import { getMe }              from "@/interfaces/controllers/user.controller";
import { authMiddleware }     from "@/interfaces/middlewares/auth/auth.middleware";

const router = Router();

// GET /api/me → devuelve datos básicos del usuario logueado
router.get("/me", authMiddleware, getMe);

export default router;

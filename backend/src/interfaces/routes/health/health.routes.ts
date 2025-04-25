// src/interfaces/routes/health/health.routes.ts
import { Router } from "express";
import { healthCheck } from "@/interfaces/controllers/health/health.controller";

const router = Router();

// ✅ Endpoint básico de salud
router.get("/health", healthCheck);

export default router;

// src/interfaces/routes/metrics.routes.ts
import { Router } from "express";
import { register } from "@/infrastructure/metrics/metrics";

const router = Router();

router.get("/metrics", async (_req, res) => {
  try {
    res.set("Content-Type", register.contentType);
    res.end(await register.metrics());
  } catch (error) {
    res.status(500).json({ message: "Error obteniendo métricas" });
  }
});

export default router;

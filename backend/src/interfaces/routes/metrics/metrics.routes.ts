// src/interfaces/routes/metrics/metrics.routes.ts
import { Router } from "express";
import { register } from "@/infrastructure/metrics/metrics";

const router = Router();

router.get("/metrics", async (req, res) => {
  res.set("Content-Type", register.contentType);
  res.end(await register.metrics());
});

export default router;

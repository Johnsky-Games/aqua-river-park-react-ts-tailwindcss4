// src/interfaces/controllers/health/health.controller.ts
import { Request, Response } from "express";

export const healthCheck = async (_req: Request, res: Response) => {
  res.status(200).json({
    status: "ok",
    uptime: process.uptime(), // cuánto tiempo ha estado corriendo el server
    timestamp: Date.now(),    // fecha actual
    environment: process.env.NODE_ENV || "development",
  });
};

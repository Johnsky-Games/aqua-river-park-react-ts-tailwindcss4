// middlewares/notFound.middleware.ts
import { Request, Response } from "express";
import logger from "@/infrastructure/logger/logger";

const notFound = (req: Request, res: Response) => {
  logger.warn(`🚫 Ruta no encontrada: ${req.method} ${req.originalUrl}`);
  res.status(404).json({ message: "Ruta no encontrada" });
};

export default notFound;

// middlewares/errorHandler.middleware.ts
import { Request, Response, NextFunction } from "express";
import logger from "@/utils/logger";

const errorHandler = (
  err: any,
  _req: Request,
  res: Response,
  _next: NextFunction
) => {
  logger.error(`❌ Error global: ${err.stack || err.message}`);
  res.status(err.status || 500).json({ message: err.message || "Error interno del servidor" });
};

export default errorHandler;

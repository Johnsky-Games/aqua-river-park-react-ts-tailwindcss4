// src/interfaces/middlewares/error/errorHandler.middleware.ts
import { Request, Response, NextFunction } from "express";
import logger from "@/infrastructure/logger/logger";
import { errorMessages } from "@/shared/errors/errorMessages";
import { errorCodes } from "@/shared/errors/errorCodes";

const errorHandler = (
  err: any,
  _req: Request,
  res: Response,
  _next: NextFunction
) => {
  const status = err.status || 500;
  const code = err.code || errorCodes.INTERNAL_SERVER_ERROR;
  const message = err.message || errorMessages.internalServerError;

  logger.error(`❌ Error global: ${message}`);

  res.status(status).json({ code, message });
};

export default errorHandler;

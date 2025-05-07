// src/infraestructure/logger/errorHandler.ts
import logger from "./logger";

export const logError = (context: string, error: any) => {
  const message = error?.message || error;
  const code = error?.code ? ` | Code: ${error.code}` : "";
  const status = error?.status ? ` | Status: ${error.status}` : "";
  logger.error(`❌ ${context}: ${message}${code}${status}`);
};

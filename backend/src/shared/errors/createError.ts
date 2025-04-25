// src/shared/errors/createError.ts
export const createError = (message: string, code: number, status = 400): Error & { code: number, status: number } => {
    const error = new Error(message) as Error & { code: number; status: number };
    error.code = code;
    error.status = status;
    return error;
  };
  
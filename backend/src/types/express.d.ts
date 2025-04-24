// src/types/express.d.ts
import { Request } from "express";

export interface TokenPayload {
  id: number;
  email: string;
  name: string;
  role: string;
  roleId: number; // ✅ Asegúrate de que esta propiedad esté presente
}

export interface AuthenticatedRequest extends Request {
  user?: TokenPayload;
}

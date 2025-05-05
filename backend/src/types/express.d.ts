// src/types/express.d.ts

import { Request } from "express";

export interface TokenPayload {
  sub: number;
  role: string;
}

export interface AuthenticatedRequest extends Request {
  user?: TokenPayload;
}

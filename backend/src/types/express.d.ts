// src/types/express.d.ts
import { Request } from "express";
import { TokenPayload } from "../config/jwt";

export interface AuthenticatedRequest extends Request {
  user?: TokenPayload;
}

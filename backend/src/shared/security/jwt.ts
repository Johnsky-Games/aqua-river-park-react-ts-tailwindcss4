// src/shared/security/jwt.ts
import jwt from "jsonwebtoken";
import dotenv from "dotenv";

dotenv.config();

export type TokenPayload = {
  id: number;
  email: string;
  name: string;
  role: string;
  roleId: number; // ✅ Agregado para validaciones por ID
};


const ACCESS_TOKEN_SECRET = process.env.JWT_ACCESS_SECRET || "accesssecret";
const REFRESH_TOKEN_SECRET = process.env.JWT_REFRESH_SECRET || "refreshsecret";

export const generateAccessToken = (payload: TokenPayload): string => {
  return jwt.sign(payload, ACCESS_TOKEN_SECRET, { expiresIn: "15m" });
};

export const generateRefreshToken = (payload: TokenPayload): string => {
  return jwt.sign(payload, REFRESH_TOKEN_SECRET, { expiresIn: "7d" });
};

export const verifyAccessToken = (token: string): TokenPayload => {
  return jwt.verify(token, ACCESS_TOKEN_SECRET) as TokenPayload;
};

export const verifyRefreshToken = (token: string): TokenPayload => {
  return jwt.verify(token, REFRESH_TOKEN_SECRET) as TokenPayload;
};

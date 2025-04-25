// src/shared/security/jwt.ts
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import { TokenPayload } from "@/types/express";
import { errorMessages } from "@/shared/errors/errorMessages";
import { errorCodes } from "@/shared/errors/errorCodes";

dotenv.config();

const ACCESS_TOKEN_SECRET = process.env.JWT_ACCESS_SECRET || "accesssecret";
const REFRESH_TOKEN_SECRET = process.env.JWT_REFRESH_SECRET || "refreshsecret";

export const generateAccessToken = (payload: TokenPayload): string => {
  return jwt.sign(payload, ACCESS_TOKEN_SECRET, { expiresIn: "15m" });
};

export const generateRefreshToken = (payload: TokenPayload): string => {
  return jwt.sign(payload, REFRESH_TOKEN_SECRET, { expiresIn: "7d" });
};

export const verifyAccessToken = (token: string): TokenPayload => {
  try {
    return jwt.verify(token, ACCESS_TOKEN_SECRET) as TokenPayload;
  } catch (error: any) {
    const err = new Error(errorMessages.tokenInvalidOrExpired) as any;
    err.code = errorCodes.TOKEN_INVALID_OR_EXPIRED;
    throw err;
  }
};

export const verifyRefreshToken = (token: string): TokenPayload => {
  try {
    return jwt.verify(token, REFRESH_TOKEN_SECRET) as TokenPayload;
  } catch (error: any) {
    const err = new Error(errorMessages.tokenInvalidOrExpired) as any;
    err.code = errorCodes.TOKEN_INVALID_OR_EXPIRED;
    throw err;
  }
};

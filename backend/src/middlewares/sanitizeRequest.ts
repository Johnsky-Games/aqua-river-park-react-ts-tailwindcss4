// middlewares/sanitizeRequest.ts
import { sanitize } from "../utils/sanitize";
import { Request, Response, NextFunction } from "express";

const sanitizeObject = (obj: any) => {
  for (const key in obj) {
    if (typeof obj[key] === "string") {
      obj[key] = sanitize(obj[key]);
    } else if (typeof obj[key] === "object") {
      sanitizeObject(obj[key]);
    }
  }
};

export const sanitizeRequest = (req: Request, _res: Response, next: NextFunction) => {
  sanitizeObject(req.body);
  sanitizeObject(req.query);
  sanitizeObject(req.params);
  next();
};

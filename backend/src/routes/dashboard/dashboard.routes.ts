import { Router } from "express";
import { getDashboard } from "@/controllers/dashboard/dashboard.controller";
import { authMiddleware } from "@/middlewares/auth/auth.middleware";
import { AuthenticatedRequest } from "@/types/express";

const router = Router();

router.get("/dashboard", authMiddleware, (req, res) =>
    getDashboard(req as AuthenticatedRequest, res)
  );

export default router;

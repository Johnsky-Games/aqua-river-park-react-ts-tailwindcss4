import { Router } from "express";
import { getDashboard } from "../controllers/dashboard.controller";
import { authMiddleware } from "../middlewares/auth.middleware";

const router = Router();

router.get("/dashboard", authMiddleware, getDashboard);

export default router;

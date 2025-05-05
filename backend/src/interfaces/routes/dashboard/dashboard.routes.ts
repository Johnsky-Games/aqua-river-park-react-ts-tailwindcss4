// src/interfaces/routes/dashboard/dashboard.routes.ts
import { Router } from "express";
import { getDashboard } from "@/interfaces/controllers/dashboard/dashboard.controller";
import { authMiddleware } from "@/interfaces/middlewares/auth/auth.middleware";
import { checkRole } from "@/interfaces/middlewares/role/role.middleware";

const router = Router();

router.get(
  "/admin/dashboard",
  authMiddleware,
  checkRole(["admin"]),       // <-- now matches on the string role
  (req, res) => getDashboard(req, res)
);

export default router;

import { Router } from "express";
import { getDashboard } from "@/interfaces/controllers/dashboard/dashboard.controller";
import { authMiddleware } from "@/interfaces/middlewares/auth/auth.middleware";
import { AuthenticatedRequest } from "@/types/express";
import { checkRoleById } from "@/interfaces/middlewares/role/role.middleware";

const router = Router();

// ✅ Ruta protegida de prueba
router.get(
  "/admin/dashboard",
  authMiddleware,
  checkRoleById([1, 2, 3, 5, 6]), // admin, staff, reception, editor, validador
  (req, res) => getDashboard(req as AuthenticatedRequest, res)
);

export default router;

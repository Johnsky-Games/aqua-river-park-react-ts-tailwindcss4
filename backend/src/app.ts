import express from "express";
import dashboardRoutes from "@/interfaces/routes/dashboard/dashboard.routes";
import authRoutes from "@/interfaces/routes/auth/auth.routes";
import cors from "cors";
import notFound from "@/interfaces/middlewares/error/notFound.middleware";
import errorHandler from "@/interfaces/middlewares/error/errorHandler.middleware";
import { sanitizeRequest } from "@/interfaces/middlewares/sanitize/sanitizeRequest";
import helmet from "helmet";
import cookieParser from "cookie-parser";

const app = express();
app.use(cookieParser());
app.use(express.json({ limit: "10kb" })); // Evita ataques de payloads masivos (DoS)
app.use(
  helmet.hsts({
    maxAge: 60 * 60 * 24 * 365, // 1 año
    includeSubDomains: true,
  })
); // 🔒 Agrega cabeceras de seguridad
app.use(
  cors({
    origin: "http://localhost:5173", // 👈 Asegúrate que coincida con el frontend
    credentials: true,
  })
);
app.use(sanitizeRequest);

// Agrupar rutas protegidas bajo /api
app.use("/api", dashboardRoutes);
app.use("/api", authRoutes);
app.use(notFound); // 👉 Para rutas no encontradas
app.use(errorHandler); // 👉 Para manejar errores de forma centralizada

export default app;

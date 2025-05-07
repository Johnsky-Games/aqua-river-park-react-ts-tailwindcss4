import express from "express";
import cors from "cors";
import helmet from "helmet";
import cookieParser from "cookie-parser";

import dashboardRoutes from "@/interfaces/routes/dashboard/dashboard.routes";
import authRoutes from "@/interfaces/routes/auth/auth.routes";
import userRoutes from "@/interfaces/routes/user.routes";
import healthRoutes from "@/interfaces/routes/health/health.routes";
import metricsRoutes from "@/interfaces/routes/health/metrics.routes";

import { metricsMiddleware } from "@/infrastructure/metrics/requestDurationHistogram";
import { sanitizeRequest } from "@/interfaces/middlewares/sanitize/sanitizeRequest";
import notFound from "@/interfaces/middlewares/error/notFound.middleware";
import errorHandler from "@/interfaces/middlewares/error/errorHandler.middleware";

const app = express();
const FRONTEND = process.env.FRONTEND_ORIGIN || "http://localhost:5173";

app.use(cookieParser());
app.use(express.json({ limit: "10kb" }));
app.use(
  helmet.hsts({
    maxAge: 60 * 60 * 24 * 365,
    includeSubDomains: true,
  })
);
app.use(
  cors({
    origin: FRONTEND,
    credentials: true,
  })
);
app.use(sanitizeRequest);
app.use(metricsMiddleware);

// Rutas
app.use("/api", dashboardRoutes);
app.use("/api", authRoutes);
app.use("/api", userRoutes);
app.use("/api", healthRoutes);
app.use("/api", metricsRoutes);
app.get("/", (_req, res) => {
  res.json({
    name: "Aqua River Park API",
    version: process.env.npm_package_version || "dev",
    uptime: process.uptime(),
    timestamp: Date.now(),
    routes: {
      health: "/api/health",
      metrics: "/api/metrics",
      docs: "/docs"
    }
  });
});


// Errores
app.use(notFound);
app.use(errorHandler);

export default app;

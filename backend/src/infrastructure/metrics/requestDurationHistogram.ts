// src/infraestructure/metrics/requestDurationHistogram.ts
import client from "prom-client";

export const httpRequestDurationHistogram = new client.Histogram({
  name: "http_request_duration_seconds",
  help: "Duración de las solicitudes HTTP en segundos",
  labelNames: ["method", "route", "status_code"],
  buckets: [0.005, 0.01, 0.05, 0.1, 0.3, 0.5, 1, 2, 5],
});

// Middleware para medir duración
export const metricsMiddleware = (req: import("express").Request, res: import("express").Response, next: import("express").NextFunction) => {
  const end = httpRequestDurationHistogram.startTimer();

  res.on("finish", () => {
    end({
      method: req.method,
      route: req.route?.path || req.path || req.url,
      status_code: res.statusCode,
    });
  });

  next();
};

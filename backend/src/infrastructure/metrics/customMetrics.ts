// src/infraestructure/metrics/customMetrics.ts
import client from "prom-client";

export const userRegisterCounter = new client.Counter({
  name: "user_register_total",
  help: "Total de usuarios registrados",
});

export const userLoginCounter = new client.Counter({
  name: "user_login_total",
  help: "Total de logins exitosos",
});

export const passwordResetCounter = new client.Counter({
  name: "password_reset_success_total",
  help: "Total de contraseñas restablecidas con éxito",
});

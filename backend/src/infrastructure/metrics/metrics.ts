// src/infraestructure/metrics/metrics.ts
import client from "prom-client";

// Inicia la colección de métricas predeterminadas
client.collectDefaultMetrics(); // ✅ no necesita interval desde v15+

// Exporta el registro global
export const register = client.register;

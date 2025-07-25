// index.ts
import app from "@/app";
import logger from "@/infrastructure/logger/logger";

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  logger.info(`✅ Servidor iniciado en http://localhost:${PORT}`);
});

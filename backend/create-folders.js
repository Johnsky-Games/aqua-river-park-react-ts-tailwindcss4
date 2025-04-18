import { existsSync, mkdirSync } from "fs";
import { resolve } from "path";

const folders = [
  "src/controllers/auth",
  "src/controllers/dashboard",
  "src/controllers/confirm",
  "src/controllers/recover",

  "src/services/auth",
  "src/services/confirm",
  "src/services/recovery",
  "src/services/user",

  "src/routes/auth",
  "src/routes/dashboard",

  "src/repositories/user",

  "src/models/user",

  "src/middlewares/auth",
  "src/middlewares/sanitize",
  "src/middlewares/validate",
  "src/middlewares/role",
  "src/middlewares/error",

  "src/utils/auth",
  "src/utils/mailer",

  "src/validations/auth",
  "src/validations/user",

  "src/types/express"
];

folders.forEach(folder => {
  const dir = resolve(__dirname, folder);
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
    console.log("✅ Carpeta creada:", folder);
  } else {
    console.log("📁 Ya existe:", folder);
  }
});

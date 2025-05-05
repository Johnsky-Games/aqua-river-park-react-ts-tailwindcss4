// backend/src/config/jwtKeys.ts
import fs from "fs";
import path from "path";
import dotenv from "dotenv";
dotenv.config();

// si env es absoluto, lo usamos; si no, lo resolvemos desde process.cwd()
const keysDirEnv = process.env.JWT_KEYS_DIR || "keys";
const keysDir = path.isAbsolute(keysDirEnv)
  ? keysDirEnv
  : path.resolve(process.cwd(), keysDirEnv);

export const PRIVATE_KEY = fs.readFileSync(
  path.join(keysDir, "private.key"),
  "utf-8"
);
export const PUBLIC_KEY = fs.readFileSync(
  path.join(keysDir, "public.key"),
  "utf-8"
);

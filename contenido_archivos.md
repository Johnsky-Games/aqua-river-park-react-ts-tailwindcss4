# Contenido de Archivos

## backend\logs\app.log

```
{"level":"info","message":"✅ Servidor iniciado en http://localhost:3000"}
{"level":"info","message":"✅ Servidor iniciado en http://localhost:3000"}
{"level":"info","message":"✅ Servidor iniciado en http://localhost:3000"}
{"level":"info","message":"✅ Servidor iniciado en http://localhost:3000"}
{"level":"info","message":"✅ Servidor iniciado en http://localhost:3000"}
{"level":"info","message":"✅ Servidor iniciado en http://localhost:3000"}
{"level":"info","message":"📨 Enviando correo de confirmación a carlos-boada14@hotmail.com"}
{"level":"warn","message":"🚫 Ruta no encontrada: GET /api/resend-confirmation"}
{"level":"warn","message":"🚫 Ruta no encontrada: GET /favicon.ico"}
{"level":"info","message":"📨 Enviando correo de confirmación a carlos-boada14@hotmail.com"}
{"level":"info","message":"✅ Login exitoso: carlos-boada14@hotmail.com"}
{"level":"warn","message":"🚫 Ruta no encontrada: GET /api/resend-confirmation"}
{"level":"warn","message":"🚫 Ruta no encontrada: GET /api/resend-confirmation"}
{"level":"warn","message":"🚫 Ruta no encontrada: GET /api/resend-confirmation"}
{"level":"warn","message":"🚫 Ruta no encontrada: GET /api/resend-confirmation"}
{"level":"info","message":"✅ Servidor iniciado en http://localhost:3000"}
{"level":"info","message":"✅ Servidor iniciado en http://localhost:3000"}
{"level":"info","message":"✅ Servidor iniciado en http://localhost:3000"}
{"level":"info","message":"✅ Servidor iniciado en http://localhost:3000"}
{"level":"info","message":"✅ Servidor iniciado en http://localhost:3000"}
{"level":"info","message":"✅ Servidor iniciado en http://localhost:3000"}
{"level":"info","message":"✅ Servidor iniciado en http://localhost:3000"}
{"level":"info","message":"✅ Servidor iniciado en http://localhost:3000"}
{"level":"info","message":"✅ Servidor iniciado en http://localhost:3000"}
{"level":"info","message":"✅ Servidor iniciado en http://localhost:3000"}
{"level":"info","message":"✅ Servidor iniciado en http://localhost:3000"}
{"level":"info","message":"✅ Servidor iniciado en http://localhost:3000"}
{"level":"info","message":"✅ Servidor iniciado en http://localhost:3000"}
{"level":"info","message":"✅ Servidor iniciado en http://localhost:3000"}
{"level":"info","message":"✅ Servidor iniciado en http://localhost:3000"}
{"level":"info","message":"📨 Enviando correo de confirmación a carlos-boada14@hotmail.com"}
{"level":"info","message":"✅ Servidor iniciado en http://localhost:3000"}
{"level":"info","message":"✅ Servidor iniciado en http://localhost:3000"}
{"level":"info","message":"✅ Servidor iniciado en http://localhost:3000"}
{"level":"info","message":"✅ Servidor iniciado en http://localhost:3000"}
{"level":"info","message":"✅ Servidor iniciado en http://localhost:3000"}

```

## backend\src\app.ts

```typescript
import express from "express";
import dashboardRoutes from "@/routes/dashboard/dashboard.routes";
import authRoutes from "@/routes/auth/auth.routes";
import cors from "cors";
import notFound from "@/middlewares/error/notFound.middleware";
import errorHandler from "@/middlewares/error/errorHandler.middleware";
import { sanitizeRequest } from "@/middlewares/sanitize/sanitizeRequest";
import helmet from "helmet";

const app = express();
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

```

## backend\src\config\db.ts

```typescript
// db.ts
import mysql from 'mysql2/promise';
import dotenv from 'dotenv';
dotenv.config();

export const db = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'aqua_river_park',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// console.log('Conectando a la DB con usuario:', process.env.DB_USER);
// console.log('Contraseña:', process.env.DB_PASSWORD);



export default db;

```

## backend\src\config\jwt.ts

```typescript
// jwt.ts
import jwt, { JwtPayload } from 'jsonwebtoken';
import dotenv from 'dotenv';

dotenv.config();

const JWT_SECRET = process.env.JWT_SECRET || 'supersecret';
const JWT_EXPIRES_IN = '7d';

export interface TokenPayload {
  id: number;
  email: string;
  name: string;
  role: 'admin';
}

export const generateToken = (payload: TokenPayload): string => {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
};

export const verifyToken = (token: string): TokenPayload => {
  return jwt.verify(token, JWT_SECRET) as TokenPayload;
};

```

## backend\src\config\mailer.ts

```typescript
// backend/config/mailer.ts
import dotenv from 'dotenv';
dotenv.config();
import nodemailer from 'nodemailer';

export const transporter = nodemailer.createTransport({
  host: process.env.MAIL_HOST,
  port: Number(process.env.MAIL_PORT),
  auth: {
    user: process.env.MAIL_USER,
    pass: process.env.MAIL_PASS
  }
});

```

## backend\src\config\rateLimit.ts

```typescript
// config/rateLimit.ts
import rateLimit from "express-rate-limit";

export const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 5,
  message: "Demasiados intentos. Intenta nuevamente en 15 minutos.",
  standardHeaders: true,
  legacyHeaders: false,
});

```

## backend\src\controllers\auth\auth.controller.ts

```typescript
import { Request, Response } from "express";
import * as authService from "@/services/auth/auth.service";
import logger from "@/utils/logger";

// ✅ REGISTRO
export const register = async (req: Request, res: Response) => {
  try {
    await authService.registerUser(req.body);
    res.status(201).json({
      message: "Registro exitoso. Revisa tu correo para confirmar tu cuenta.",
    });
    logger.info(`✅ Usuario registrado: ${req.body.email}`);
  } catch (error: any) {
    logger.error("❌ Registro:", error.message);
    res.status(400).json({ message: error.message || "Error al registrar" });
  }
};

// ✅ LOGIN
export const login = async (req: Request, res: Response) => {
  const { email, password } = req.body;

  try {
    const data = await authService.loginUser(email, password);
    res.json(data);
    logger.info(`✅ Login exitoso: ${email}`);
  } catch (error: any) {
    if (error.message === "Debes confirmar tu cuenta") {
      res.status(401).json({
        message: error.message,
        tokenExpired: error.tokenExpired || false,
      });
    } else {
      res
        .status(401)
        .json({ message: error.message || "Error al iniciar sesión" });
    }
  }
};

// ✅ LOGOUT (placeholder si usas JWT)
export const logout = async (_req: Request, res: Response) => {
  res.json({ message: "Sesión cerrada" });
};

// ✅ SOLICITAR RECUPERACIÓN DE CONTRASEÑA
export const sendRecovery = async (req: Request, res: Response) => {
  const { email } = req.body;

  try {
    await authService.sendResetPassword(email);
    res.json({ message: "Correo de recuperación enviado." });
    logger.info(`✅ Correo de recuperación enviado: ${email}`);
  } catch (error: any) {
    logger.error("❌ Enviar recuperación:", error.message);
    res.status(400).json({ message: error.message });
  }
};

// ✅ CAMBIAR CONTRASEÑA
export const resetPassword = async (req: Request, res: Response) => {
  const { token, password } = req.body;

  try {
    await authService.resetPassword(token, password);
    res.json({ message: "Contraseña actualizada con éxito." });
    logger.info(`✅ Clave actualizada con éxito`);
  } catch (error: any) {
    logger.error("❌ Reset password:", error.message);
    res.status(400).json({ message: error.message });
  }
};

```

## backend\src\controllers\confirm\confirm.controller.ts

```typescript
// src/controllers/confirm.controller.ts
import { Request, Response } from "express";
import {
    confirmAccountService,
    resendConfirmationService,
  } from "@/services/confirm/confirm.service";  
import logger from "@/utils/logger";

// ✅ CONFIRMAR USUARIO
export const confirmUser = async (req: Request, res: Response): Promise<void> => {
    const { token } = req.params;
    const { email } = req.query;

    try {
        const result = await confirmAccountService(token, email as string | undefined);
        res.status(result.code).json({ message: result.message });
    } catch (error: any) {
        logger.error("❌ Error al confirmar:", error);
        res.status(500).json({ message: "Error en el servidor" });
    }
};


// ✅ REENVIAR CONFIRMACIÓN
export const resendConfirmation = async (req: Request, res: Response): Promise<void> => {
    const { email } = req.body;

    try {
        await resendConfirmationService(email);
        res.status(200).json({
            message: "Se envió un nuevo enlace de confirmación a tu correo",
        });
    } catch (error: any) {
        logger.error("❌ Error al reenviar confirmación:", error.message || error);
        res.status(400).json({
            message: error.message || "Error al reenviar confirmación",
        });
    }
};

```

## backend\src\controllers\dashboard\dashboard.controller.ts

```typescript
// backend/src/controllers/dashboard.controller.ts
import { Response } from "express";
import { AuthenticatedRequest } from "@/types/express";

export const getDashboard = async (
  req: AuthenticatedRequest,
  res: Response
): Promise<void> => {
  const user = req.user;

  res.json({
    message: `Hola ${user.name}, bienvenido al dashboard.`,
    role: user.role,
  });
};

```

## backend\src\controllers\recover\recover.controller.ts

```typescript
import { Request, Response } from "express";
import * as authService from "@/services/recovery/recovery.service";
import logger from "@/utils/logger";

// ✅ 1. Enviar correo de recuperación
export const sendRecovery = async (req: Request, res: Response) => {
  const { email } = req.body;

  try {
    await authService.sendRecoveryService(email);
    res.json({ message: "Correo de recuperación enviado. Revisa tu bandeja." });
  } catch (error: any) {
    logger.error("❌ Error en sendRecovery:", error.message);
    res
      .status(error.status || 500)
      .json({ message: error.message || "Error del servidor" });
  }
};

// ✅ 2. Verificar token
export const checkTokenStatus = async (req: Request, res: Response) => {
  const { token } = req.body;

  try {
    const isValid = await authService.checkTokenStatusService(token);
    res.json({ valid: isValid });
  } catch (error: any) {
    logger.error("❌ Error en checkTokenStatus:", error.message);
    res.status(500).json({ message: "Error al verificar token" });
  }
};

// ✅ 3. Cambiar contraseña
export const resetPassword = async (req: Request, res: Response) => {
  const { token } = req.params;
  const { password } = req.body;

  try {
    await authService.resetPasswordService(token, password);
    res.json({ message: "Contraseña actualizada correctamente" });
  } catch (error: any) {
    logger.error("❌ Error en resetPassword:", error.message);
    res.status(500).json({ message: "Error al cambiar contraseña" });
  }
};

```

## backend\src\index.ts

```typescript
// index.ts
import app from '@/app';
import logger from '@/utils/logger';

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  logger.info(`✅ Servidor iniciado en http://localhost:${PORT}`);
});
```

## backend\src\middlewares\auth\auth.middleware.ts

```typescript
import { Request, Response, NextFunction } from "express";
import { verifyToken, TokenPayload } from "@/config/jwt";
import { AuthenticatedRequest } from "@/types/express";

export const authMiddleware = (
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    res.status(401).json({ message: "Token no proporcionado" });
    return;
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = verifyToken(token) as TokenPayload;
    (req as AuthenticatedRequest).user = decoded;
    next();
  } catch {
    res.status(401).json({ message: "Token inválido o expirado" });
  }
};

```

## backend\src\middlewares\error\errorHandler.middleware.ts

```typescript
// middlewares/errorHandler.middleware.ts
import { Request, Response, NextFunction } from "express";
import logger from "@/utils/logger";

const errorHandler = (
  err: any,
  _req: Request,
  res: Response,
  _next: NextFunction
) => {
  logger.error(`❌ Error global: ${err.stack || err.message}`);
  res.status(err.status || 500).json({ message: err.message || "Error interno del servidor" });
};

export default errorHandler;

```

## backend\src\middlewares\error\notFound.middleware.ts

```typescript
// middlewares/notFound.middleware.ts
import { Request, Response } from "express";
import logger from "@/utils/logger";

const notFound = (req: Request, res: Response) => {
  logger.warn(`🚫 Ruta no encontrada: ${req.method} ${req.originalUrl}`);
  res.status(404).json({ message: "Ruta no encontrada" });
};

export default notFound;

```

## backend\src\middlewares\role\role.middleware.ts

```typescript
// role.middleware.ts
import { Response, NextFunction } from 'express';
import { AuthenticatedRequest } from '@/types/express'; // Solo importa esto si usas req.user

export const checkRole = (allowedRoles: string[]) => {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
    const user = req.user;

    if (!user || !allowedRoles.includes(user.role)) {
      res.status(403).json({ message: 'Acceso denegado: rol insuficiente' });
      return;
    }

    next();
  };
};

```

## backend\src\middlewares\sanitize\sanitizeRequest.ts

```typescript
// middlewares/sanitizeRequest.ts
import { sanitize } from "@/utils/sanitize";
import { Request, Response, NextFunction } from "express";

const sanitizeObject = (obj: any) => {
  for (const key in obj) {
    if (typeof obj[key] === "string") {
      obj[key] = sanitize(obj[key]);
    } else if (typeof obj[key] === "object") {
      sanitizeObject(obj[key]);
    }
  }
};

export const sanitizeRequest = (
  req: Request,
  _res: Response,
  next: NextFunction
) => {
  sanitizeObject(req.body);
  sanitizeObject(req.query);
  sanitizeObject(req.params);
  next();
};

```

## backend\src\middlewares\validate\validateInput.ts

```typescript
// middlewares/validateInput.ts
import { Request, Response, NextFunction } from "express";
import { ZodSchema } from "zod";

export const validate = (schema: ZodSchema) => async (
    req: Request,
    res: Response,
    next: NextFunction
) => {
    try {
        req.body = await schema.parseAsync(req.body);
        next();
    } catch (err: any) {
        res.status(400).json({ errors: err.errors });
    }
};

```

## backend\src\repositories\user\user.repository.ts

```typescript
// src/repositories/user.repository.ts
import db from "@/config/db";
import { RowDataPacket, ResultSetHeader } from "mysql2";

export const findUserByEmail = async (email: string) => {
  const [rows] = await db.query<RowDataPacket[]>(
    "SELECT u.*, r.name as role_name FROM users u LEFT JOIN roles r ON u.role_id = r.id WHERE u.email = ?",
    [email]
  );
  return rows[0] || null;
};

export const createUser = async (user: {
  name: string;
  email: string;
  password_hash: string;
  phone: string;
  role_id: number;
  confirmation_token: string;
  confirmation_expires: Date;
}) => {
  const {
    name,
    email,
    password_hash,
    phone,
    role_id,
    confirmation_token,
    confirmation_expires,
  } = user;

  const [result] = await db.query<ResultSetHeader>(
    `INSERT INTO users (name, email, password_hash, phone, role_id, confirmation_token, confirmation_expires)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [
      name,
      email,
      password_hash,
      phone,
      role_id,
      confirmation_token,
      confirmation_expires,
    ]
  );

  return result.insertId;
};

export const updateConfirmationToken = async (
  email: string,
  token: string,
  expires: Date
) => {
  await db.query(
    `UPDATE users SET confirmation_token = ?, confirmation_expires = ? WHERE email = ?`,
    [token, expires, email]
  );
};

export const updateResetToken = async (
  email: string,
  token: string,
  expires: Date
) => {
  await db.query(
    `UPDATE users SET reset_token = ?, reset_expires = ? WHERE email = ?`,
    [token, expires, email]
  );
};

// src/repositories/user.repository.ts

export const findUserByResetToken = async (token: string) => {
  const [rows] = await db.query<RowDataPacket[]>(
    `
    SELECT id, email, password_hash, reset_expires 
    FROM users 
    WHERE reset_token = ? AND reset_expires > NOW()`,
    [token]
  );
  return rows[0] || null;
};

export const updatePassword = async (
  userId: number,
  newPasswordHash: string
) => {
  await db.query(
    `UPDATE users SET password_hash = ?, reset_token = NULL, reset_expires = NULL WHERE id = ?`,
    [newPasswordHash, userId]
  );
};

// Consultas para confrimación de cuenta
export const findUserByToken = async (token: string) => {
  const [rows] = await db.query<RowDataPacket[]>(
    "SELECT * FROM users WHERE confirmation_token = ?",
    [token]
  );
  return rows[0];
};

export const checkConfirmedByEmail = async (email: string) => {
  const [rows] = await db.query<RowDataPacket[]>(
    "SELECT is_confirmed FROM users WHERE email = ?",
    [email]
  );
  return rows[0];
};

export const confirmUserById = async (id: number) => {
  await db.query(
    `UPDATE users 
     SET is_confirmed = 1, confirmation_token = NULL, confirmation_expires = NULL 
     WHERE id = ?`,
    [id]
  );
};

export const findUserBasicByEmail = async (email: string) => {
  const [rows] = await db.query<RowDataPacket[]>(
    "SELECT id FROM users WHERE email = ?",
    [email]
  );
  return rows[0] || null;
};

export const getResetTokenExpiration = async (token: string) => {
  const [rows] = await db.query<RowDataPacket[]>(
    "SELECT reset_expires FROM users WHERE reset_token = ?",
    [token]
  );
  return rows[0] || null;
};

```

## backend\src\routes\auth\auth.routes.ts

```typescript
import { Router } from "express";
import { login, register, logout } from "@/controllers/auth/auth.controller";
import {
  confirmUser,
  resendConfirmation,
} from "@/controllers/confirm/confirm.controller";
// import { checkTokenStatus } from '../controllers/tokenStatus.controller';
import {
  sendRecovery,
  checkTokenStatus,
  resetPassword,
} from "@/controllers/recover/recover.controller"; // 👈 nuevo

import { authMiddleware } from "@/middlewares/auth/auth.middleware";
import { getDashboard } from "@/controllers/dashboard/dashboard.controller";
import { checkRole } from "@/middlewares/role/role.middleware";
import { validate } from "@/middlewares/validate/validateInput";
import { registerSchema, loginSchema } from "@/validations/auth.schema";
import { loginLimiter } from "@/config/rateLimit";
import { AuthenticatedRequest } from "@/types/express";

const router = Router();

// Auth
router.post("/register", validate(registerSchema), register);
router.post("/login", loginLimiter, validate(loginSchema), login);
router.post("/logout", logout);

// Confirmación
router.get("/confirm/:token", confirmUser);
router.post("/resend-confirmation", loginLimiter, resendConfirmation);

// Recuperación de contraseña
router.post("/send-recovery", loginLimiter, sendRecovery); // 👈 nuevo
router.post("/reset-password", resetPassword); // 👈 nuevo
router.post("/reset-password/:token", resetPassword); // 👈 importante
router.post("/check-token-status", checkTokenStatus); // 👈 nuevo

// Protegidas
router.get(
  "/dashboard",
  authMiddleware,
  (req, res) => getDashboard(req as AuthenticatedRequest, res)
);

export default router;

```

## backend\src\routes\dashboard\dashboard.routes.ts

```typescript
import { Router } from "express";
import { getDashboard } from "@/controllers/dashboard/dashboard.controller";
import { authMiddleware } from "@/middlewares/auth/auth.middleware";
import { AuthenticatedRequest } from "@/types/express";

const router = Router();

router.get("/dashboard", authMiddleware, (req, res) =>
    getDashboard(req as AuthenticatedRequest, res)
  );

export default router;

```

## backend\src\services\auth\auth.service.ts

```typescript
// src/services/auth.service.ts
import bcrypt from "bcryptjs";
import crypto from "crypto";
import { generateToken } from "@/config/jwt";
import sendConfirmationEmail from "@/utils/mailerConfirmation";
import {
  createUser,
  findUserByEmail,
  findUserByResetToken,
  updatePassword,
  updateResetToken,
} from "@/repositories/user/user.repository";
import {
  validateEmail,
  validateNewPassword,
  validatePasswordChange,
} from "@/utils/validators";
import logger from "../../utils/logger";

// ✅ REGISTRO
export const registerUser = async ({
  name,
  email,
  password,
  phone,
}: {
  name: string;
  email: string;
  password: string;
  phone: string;
}) => {
  validateEmail(email); // Validación robusta del mail
  validateNewPassword(password); // Validación Robusta del password

  const existingUser = await findUserByEmail(email);
  if (existingUser) throw new Error("El correo ya está registrado");

  const password_hash = await bcrypt.hash(password, 10);
  const confirmation_token = crypto.randomBytes(32).toString("hex");
  const confirmation_expires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 horas

  await createUser({
    name,
    email,
    password_hash,
    phone,
    role_id: 4,
    confirmation_token,
    confirmation_expires,
  });

  await sendConfirmationEmail(email, confirmation_token);
};

// ✅ LOGIN
export const loginUser = async (email: string, password: string) => {
  const user = await findUserByEmail(email);
  if (!user) throw new Error("Correo no registrado");

  if (!user.is_confirmed) {
    const tokenExpired =
      !user.confirmation_token ||
      !user.confirmation_expires ||
      new Date(user.confirmation_expires) < new Date();

    throw {
      message: "Debes confirmar tu cuenta",
      tokenExpired,
    };
  }

  const isMatch = await bcrypt.compare(password, user.password_hash);
  if (!isMatch) throw new Error("Contraseña incorrecta");

  const token = generateToken({
    id: user.id,
    email: user.email,
    name: user.name,
    role: user.role_name || "client",
  });

  return {
    token,
    user: {
      email: user.email,
      isConfirmed: Boolean(user.is_confirmed),
    },
  };
};

// ✅ ENVIAR ENLACE DE RECUPERACIÓN
export const sendResetPassword = async (email: string) => {
  const user = await findUserByEmail(email);
  if (!user) throw new Error("Correo no registrado");

  const token = crypto.randomBytes(32).toString("hex");
  const expires = new Date(Date.now() + 60 * 60 * 1000); // 1 hora

  await updateResetToken(email, token, expires);

  // Enviar el correo (solo console.log por ahora)
  logger.info(`📧 Enlace de recuperación enviado a ${email}`);
};

// ✅ RESTABLECER CONTRASEÑA
export const resetPassword = async (token: string, newPassword: string) => {
  const user = await findUserByResetToken(token);
  if (!user) throw new Error("Token inválido o expirado");

  //Validación robusta
  validatePasswordChange(newPassword, user.email, user.password_hash);

  const password_hash = await bcrypt.hash(newPassword, 10);
  await updatePassword(user.id, password_hash);
};

// ✅ VERIFICAR token de recuperación
export const checkResetToken = async (token: string) => {
  const user = await findUserByResetToken(token);
  return user && new Date(user.reset_expires) > new Date();
};

```

## backend\src\services\confirm\confirm.service.ts

```typescript
// src/services/confirm.service.ts
import crypto from "crypto";
import sendConfirmationEmail from "@/utils/mailerConfirmation";
import * as userRepo from "@/repositories/user/user.repository";

export const confirmAccountService = async (token: string, email?: string) => {
  const user = await userRepo.findUserByToken(token);

  if (!user) {
    if (email) {
      const userFromEmail = await userRepo.findUserByEmail(email);
      if (userFromEmail?.is_confirmed === 1) {
        return { code: 200, message: "La cuenta ya ha sido confirmada." };
      }
    }
    return { code: 400, message: "Token inválido o expirado" };
  }

  if (user.is_confirmed === 1) {
    return { code: 200, message: "La cuenta ya ha sido confirmada." };
  }

  if (new Date(user.confirmation_expires) < new Date()) {
    return { code: 400, message: "Token inválido o expirado" };
  }

  await userRepo.confirmUserById(user.id);
  return { code: 200, message: "Cuenta confirmada exitosamente." };
};

export const resendConfirmationService = async (email: string) => {
  const user = await userRepo.findUserByEmail(email);
  if (!user) throw new Error("Correo no encontrado");

  if (user.is_confirmed) throw new Error("La cuenta ya está confirmada");

  const token = crypto.randomBytes(32).toString("hex");
  const expires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24h

  await userRepo.updateConfirmationToken(email, token, expires);
  await sendConfirmationEmail(email, token);
};

```

## backend\src\services\recovery\recovery.service.ts

```typescript
import crypto from "crypto";
import bcrypt from "bcryptjs";
import sendRecoveryEmail from "@/utils/mailerRecovery";
import * as userRepo from "@/repositories/user/user.repository";

// ✅ 1. Enviar correo de recuperación
export const sendRecoveryService = async (email: string) => {
  const user = await userRepo.findUserBasicByEmail(email);
  if (!user) throw new Error("Correo no registrado");

  const token = crypto.randomBytes(32).toString("hex");
  const expires = new Date(Date.now() + 60 * 60 * 1000); // 1 hora

  await userRepo.updateResetToken(email, token, expires);
  await sendRecoveryEmail(email, token);
};

// ✅ 2. Verificar token
export const checkTokenStatusService = async (
  token: string
): Promise<boolean> => {
  const resetData = await userRepo.getResetTokenExpiration(token);
  if (!resetData || new Date(resetData.reset_expires) < new Date())
    return false;
  return true;
};

// ✅ 3. Cambiar contraseña
export const resetPasswordService = async (
  token: string,
  newPassword: string
) => {
  const user = await userRepo.findUserByResetToken(token);
  if (!user) throw new Error("Token inválido o expirado");

  const password_hash = await bcrypt.hash(newPassword, 10);
  await userRepo.updatePassword(user.id, password_hash);
};

```

## backend\src\types\express\index.d.ts

```typescript
import { Request } from "express";
import { TokenPayload } from "@/config/jwt";

export interface AuthenticatedRequest extends Request {
  user: TokenPayload; // 👈 Ya no es opcional
}

```

## backend\src\utils\hash.ts

```typescript
// utils/hash.ts
import bcrypt from "bcryptjs";

export const hashPassword = async (password: string) => await bcrypt.hash(password, 10);
export const verifyPassword = async (plain: string, hashed: string) => await bcrypt.compare(plain, hashed);

```

## backend\src\utils\logger.ts

```typescript
// utils/logger.ts
import winston from "winston";

const logger = winston.createLogger({
  level: "info",
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: "logs/app.log" }),
  ],
});

export default logger;

```

## backend\src\utils\mailerConfirmation.ts

```typescript
// backend/utils/mailerConfirmation.ts
import { transporter } from "@/config/mailer";
import logger from "@/utils/logger";

const sendConfirmationEmail = async (email: string, token: string) => {
  const link = `${process.env.FRONTEND_URL}/confirm/${token}?email=${encodeURIComponent(email)}`;
  logger.info(`📨 Enviando correo de confirmación a ${email}`);

  await transporter.sendMail({
    from: '"Aqua River Park" <no-reply@aquariverpark.com>',
    to: email,
    subject: "Confirma tu cuenta",
    html: `
    <div style="margin: 0; padding: 0; background-color: #e0f7fa; font-family: 'Segoe UI', sans-serif;">
      <table role="presentation" cellpadding="0" cellspacing="0" width="100%">
        <tr>
          <td align="center" style="padding: 40px 10px;">
            <table cellpadding="0" cellspacing="0" style="max-width: 600px; width: 100%; background-color: #ffffff; border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); padding: 40px;">
              <tr>
                <td align="center" style="padding-bottom: 20px;">
                  <h2 style="font-size: 26px; color: #0ea5e9; margin: 0;">🌊 ¡Bienvenido a Aqua River Park!</h2>
                </td>
              </tr>
              <tr>
                <td style="font-size: 16px; color: #444; text-align: center; padding-bottom: 20px;">
                   Gracias por registrarte. Estamos felices de tenerte en nuestra comunidad. Para completar tu registro, por favor confirma tu cuenta haciendo clic a continuación.
                </td>
              </tr>
              <tr>
                <td align="center" style="padding: 20px 0;">
                  <a href="${link}" style="background-color: #0ea5e9; color: white; text-decoration: none; padding: 14px 30px; border-radius: 8px; font-size: 16px; display: inline-block;">
                    Confirmar cuenta
                  </a>
                </td>
              </tr>
              <tr>
                <td style="font-size: 14px; color: #666; text-align: center; padding-top: 20px;">
                  Si no solicitaste este registro, puedes ignorar este mensaje.
                </td>
              </tr>
              <tr>
                <td style="border-top: 1px solid #eee; padding-top: 30px; text-align: center; font-size: 12px; color: #999;">
                  © ${new Date().getFullYear()} Aqua River Park. Todos los derechos reservados.<br><br>
                  Síguenos en nuestras redes sociales:
                  <div style="margin-top: 10px;">
                    <a href="https://www.instagram.com/aquariverpark/" target="_blank" style="margin: 0 10px;">
                      <img src="https://img.icons8.com/color/48/instagram-new.png" alt="Instagram" width="24" height="24" style="vertical-align: middle;" />
                    </a>
                    <a href="https://www.facebook.com/aquariverpark/" target="_blank" style="margin: 0 10px;">
                      <img src="https://img.icons8.com/color/48/facebook-new.png" alt="Facebook" width="24" height="24" style="vertical-align: middle;" />
                    </a>
                    <a href="https://www.tiktok.com/@aquariverpark" target="_blank" style="margin: 0 10px;">
                      <img src="https://img.icons8.com/color/48/tiktok--v1.png" alt="TikTok" width="24" height="24" style="vertical-align: middle;" />
                    </a>
                    <a href="https://www.youtube.com/@aquariverpark" target="_blank" style="margin: 0 10px;">
                      <img src="https://img.icons8.com/color/48/youtube-play.png" alt="YouTube" width="24" height="24" style="vertical-align: middle;" />
                    </a>
                  </div>
                </td>
              </tr>
            </table>
          </td>
        </tr>
      </table>
    </div>
  `,
  });
};

export default sendConfirmationEmail;

```

## backend\src\utils\mailerRecovery.ts

```typescript
// backend/utils/mailerRecovery.ts
import { transporter } from "@/config/mailer";
import logger from "@/utils/logger";

const sendRecoveryEmail = async (email: string, token: string) => {
  const link = `${process.env.FRONTEND_URL}/reset-password?token=${token}&email=${encodeURIComponent(email)}`;
  logger.info(`📨 Enviando correo de confirmación a ${email}`);

  await transporter.sendMail({
    from: '"Aqua River Park" <no-reply@aquariverpark.com>',
    to: email,
    subject: "Recupera tu contraseña - Aqua River Park",
    html: `
    <div style="margin: 0; padding: 0; background-color: #e0f7fa; font-family: 'Segoe UI', sans-serif;">
      <table role="presentation" cellpadding="0" cellspacing="0" width="100%">
        <tr>
          <td align="center" style="padding: 40px 10px;">
            <table cellpadding="0" cellspacing="0" style="max-width: 600px; width: 100%; background-color: #ffffff; border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); padding: 40px;">
              <tr>
                <td align="center" style="padding-bottom: 20px;">
                  <h2 style="font-size: 26px; color: #0ea5e9; margin: 0;">🔐 Recuperación de contraseña</h2>
                </td>
              </tr>
              <tr>
                <td style="font-size: 16px; color: #444; text-align: center; padding-bottom: 20px;">
                   Hemos recibido una solicitud para restablecer tu contraseña. Haz clic en el siguiente botón para continuar:
                </td>
              </tr>
              <tr>
                <td align="center" style="padding: 20px 0;">
                  <a href="${link}" style="background-color: #0ea5e9; color: white; text-decoration: none; padding: 14px 30px; border-radius: 8px; font-size: 16px; display: inline-block;">
                    Recuperar contraseña
                  </a>
                </td>
              </tr>
              <tr>
                <td style="font-size: 14px; color: #666; text-align: center; padding-top: 20px;">
                  Si no realizaste esta solicitud, puedes ignorar este mensaje. Este enlace caduca en 1 hora.
                </td>
              </tr>
              <tr>
                <td style="border-top: 1px solid #eee; padding-top: 30px; text-align: center; font-size: 12px; color: #999;">
                  © ${new Date().getFullYear()} Aqua River Park. Todos los derechos reservados.<br><br>
                  Síguenos en nuestras redes sociales:
                  <div style="margin-top: 10px;">
                    <a href="https://www.instagram.com/aquariverpark/" target="_blank" style="margin: 0 10px;">
                      <img src="https://img.icons8.com/color/48/instagram-new.png" alt="Instagram" width="24" height="24" />
                    </a>
                    <a href="https://www.facebook.com/aquariverpark/" target="_blank" style="margin: 0 10px;">
                      <img src="https://img.icons8.com/color/48/facebook-new.png" alt="Facebook" width="24" height="24" />
                    </a>
                    <a href="https://www.tiktok.com/@aquariverpark" target="_blank" style="margin: 0 10px;">
                      <img src="https://img.icons8.com/color/48/tiktok--v1.png" alt="TikTok" width="24" height="24" />
                    </a>
                    <a href="https://www.youtube.com/@aquariverpark" target="_blank" style="margin: 0 10px;">
                      <img src="https://img.icons8.com/color/48/youtube-play.png" alt="YouTube" width="24" height="24" />
                    </a>
                  </div>
                </td>
              </tr>
            </table>
          </td>
        </tr>
      </table>
    </div>
    `,
  });
};

export default sendRecoveryEmail;

```

## backend\src\utils\sanitize.ts

```typescript
// src/utils/sanitize.ts
import { JSDOM } from 'jsdom';
import createDOMPurify from 'dompurify';

const window = new JSDOM('').window;
const DOMPurify = createDOMPurify(window);

export const sanitize = (input: string): string => {
  return DOMPurify.sanitize(input);
};

```

## backend\src\utils\tokens.ts

```typescript
// utils/tokens.ts
import crypto from "crypto";

export const generateToken = (length = 32): string => {
  return crypto.randomBytes(length).toString("hex");
};

```

## backend\src\utils\validators.ts

```typescript
import bcrypt from "bcryptjs";

// Validación de email
export const validateEmail = (email: string) => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    throw new Error("Correo electrónico inválido.");
  }
};

// Solo valida que sea fuerte (para el registro)
export const validateNewPassword = (password: string): void => {
  const minLength = 8;
  const hasUpperCase = /[A-Z]/.test(password);
  const hasLowerCase = /[a-z]/.test(password);
  const hasNumber = /\d/.test(password);
  const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);

  if (password.length < minLength)
    throw new Error("La contraseña debe tener al menos 8 caracteres.");

  if (!hasUpperCase)
    throw new Error("La contraseña debe tener al menos una letra mayúscula.");

  if (!hasLowerCase)
    throw new Error("La contraseña debe tener al menos una letra minúscula.");

  if (!hasNumber)
    throw new Error("La contraseña debe incluir al menos un número.");

  if (!hasSpecialChar)
    throw new Error("La contraseña debe incluir un carácter especial.");
};

// Valida que no sea igual a la anterior ni al correo
export const validatePasswordChange = async (
  newPassword: string,
  email: string,
  currentPasswordHash: string
): Promise<void> => {
  validateNewPassword(newPassword);

  if (newPassword === email)
    throw new Error("La contraseña no debe ser igual al correo.");

  const isSameAsOld = await bcrypt.compare(newPassword, currentPasswordHash);
  if (isSameAsOld)
    throw new Error("La nueva contraseña no puede ser igual a la anterior.");
};


```

## backend\src\validations\auth.schema.ts

```typescript
// validations/auth.schema.ts
import { z } from "zod";

export const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
});

export const registerSchema = z.object({
  name: z.string().min(2),
  email: z.string().email(),
  phone: z.string().regex(/^\d{10}$/),
  password: z.string().min(8),
  confirmPassword: z.string(),
}).refine((data) => data.password === data.confirmPassword, {
  message: "Las contraseñas no coinciden",
  path: ["confirmPassword"],
});

```

## frontend\contenido_archivos.md

```markdown
# Contenido de Archivos

## eslint.config.js

```javascript
import js from '@eslint/js'
import globals from 'globals'
import reactHooks from 'eslint-plugin-react-hooks'
import reactRefresh from 'eslint-plugin-react-refresh'
import tseslint from 'typescript-eslint'

export default tseslint.config(
  { ignores: ['dist'] },
  {
    extends: [js.configs.recommended, ...tseslint.configs.recommended],
    files: ['**/*.{ts,tsx}'],
    languageOptions: {
      ecmaVersion: 2020,
      globals: globals.browser,
    },
    plugins: {
      'react-hooks': reactHooks,
      'react-refresh': reactRefresh,
    },
    rules: {
      ...reactHooks.configs.recommended.rules,
      'react-refresh/only-export-components': [
        'warn',
        { allowConstantExport: true },
      ],
    },
  },
)

```

## index.html

```html
<!doctype html>
<html lang="en">

<head>
  <meta charset="UTF-8" />
  <link rel="icon" type="image/svg+xml" href="/vite.svg" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Aqua River Park</title>
</head>

<body>
  <div id="root"></div>
  <script type="module" src="/src/main.tsx"></script>
</body>

</html>
```

## public\ARP logo.png

```
    ftypavif    avifmif1miafMA1B  �meta       (hdlr        pict            libavif    pitm        ,iloc    D        4  �      �     Biinf        infe      av01Color    infe      av01Alpha    iref       auxl      �iprp   �ipco   ispe       |   E   pixi       av1C�     colrnclx   �   pixi       av1C�     8auxC    urn:mpeg:mpegB:cicp:systems:auxiliary:alpha    ipma        � �  #mdat 

   7����P2� ��8�A ��3��fKn������5�??�4���X����3J�cy�.y�c=j��IMg�k���� Ą�0�����f仢�#V��pА���;.oWp��~�r�E�xdI��A��1�]u@F_�c����]�7A�Kք7�4���d�D��+��+gg2M�f�Y-	u�H���t=�]��"����
wn=tzr>R�ΝU��Î�u$E�\��|o���(?����L��&N����ש��w��%H%[�,VD�")~�Ψ'���O�d.u��(	��Ƃo.Snd�h������I�X��v3eы9^4��=E��~e�u����!#���;������T$`�DX7hM�V֜�
�����Ŷk'؍�m���A�DIxt�g~,�������u�pQ���~�l��7]*�����5�����Val�l�?��۶x�C�Y�=���pX�;�j������s�d'��H�/c��B��a��o)DL�C\����%����#�����qH�,��4�y���e����GAa�	�{�m����h����x��ߪ��H��1��=�׳�nb�o�n�S��q
>�~��z#
s/{���䞿w��q��Ԝ���߱�f�m�9�6]���%W�KLӈ�����P#$��j���`���-";��.��" %'�XF0�߄f���c8k�D3{$�Fȃ_tw1�6!��g:2/E���X�E$���/
�i�2y���jF�(��rZ�VXل�QqVNM��B]4A�{(G�UCx�� -�	2���
���\�I`�3.�oЖP�Xl�����g��jb��s��=Q[O��4�<��OS{��Q�����GS� �S��,o���Y+��1~��� 

   7����B2� � a���<J�r˾�a�w@���_�TD&����U?�^Ɂ?�PZ�n�!������|I�E��b�lL։~��(��UL-�@�2�/���fmr��ZX��^�o�n���w���x��H��;=�0V;T�^�X^.�U�[s�N����{F>5����
�[���@�!�(��Aa�Ǚ|�u�Li �p8�$��������A�T�y�µҥ?��`���>_VO'e��ƀ�ǯD�r!�W:QN�$z,~X�U.����k�c�e��-��11�/Tc�*!�{�}~����m�Q��;
Ǟ>�T��B2|P5$[�H�a����TB�!��*���6E�6a��h03h���L`_���I;���K�9��H�!Y�>��<.J�_�7w��]'�a���� ��6�O� Js��86`�뗔TZ��_~�H�j!�n@	�f�C�=+pFTZ�I��8�0"[~���\��3&�LwY����si�Lr�
�#w5��?�c�tT�4�>��ѯ/Ntβ�&U6	F-�:�<0�y��ݕ%��m�_%D���ŝ��z�����@H$-���cS�*o\�tڏ]����+��EO�^8�މ�)n���}]�����Ø�ᔹ�O����t�e$./n���W/<�3� gS>���Pv^��    O����I@Io<��m�J�#Zd8�`i�y�Fٝ��s��x�!Y�Z�EL�JB�{�a4�sZ�`ͯ�����+��v���h�W�u}UH��e6]UR!��T]E3Hd��K��`fϮu��ldakq��Y.,�1�6�Ҏ���@���1>L}��t�FI���7����jb������b�K�d�ᱠ|h�	���./k����������V�)����	D-�,/����j{�y�o�t��\':f����`��C�l����җ��Z����eT��C�ۃ�S�<�gG]iB.�7@��s�C���N}�K�U�Rb��f�ӷ�?��8�������0�[�� t�Ӿ������kw��AY{=�?j�If�Tz �0��_Rya{K�1��v�D�}�|C ���m���@Z9����q�9�ku���x@�qB#��ڲљ��`�A:�b.1Fڱٓ3i�c
�����Z�Q�r!�4�P�>�P�B� h�$����F���>j~Hw���=v1�j1�Ũ$-t~����%熍��x�ւ=A늤��g �,B6s����Nrcr��-�y�1��VW
aA��:8}���%
�Z23�����,$a�
�e��G�|dp�zU�e��&Ev��8)��h�8|��}�B}�&Ra�w�J�\æ�������Ml1.ۀb�Jۊ�l�H��~1tu_k�Ǜ|�o��>պZ�"̵Ȏ�Z@���|�}9I������K@�x���?b�x���yt3$��]u&��pm�ofo'ٷi�V��-r�Qo�c�05o���
/2��p�S�D6�k�|5��Sw�<�;UC��Hӹ�`a[���*���t���`��u�]��m[�CG|��Np����(��f�L�<�UIOq|���4�o*E ὢ������s�y���~�9�E1�Ep����"��� ��>݁%͖�ş�o�뼡���Q�l(J4zWKNo�V��;>y�_�E��x_+���I����,S�4S��$�z�t���b��k,�����E!��x|�`�i{?N�d��)�Ѫp���P���e9���{�Sb��s�,���*{�_�;7�>\�?'@R7��G~Gؗ��?iڲ.�!z;]��ݟM:��<+��f	�n����J�Qq�c�w��ۆ��~}ʣ=XK� d����Eox�q熪1��o�h�2������=#3S��%;`_1y�*�A�cV�tƮ|C�p�Z�?�w��2|sU��C���
}^Q�_��V��D=3��� g�4f�Y *=L!�Kߵ�� �,�NFF�wD 6���VYXͥC3�'9���K���>�����ێ�e��`�2s���L
nO�3F[��5�(i��_}m��\���1p��q�_�?lܩQ��1�V�h�]�*����i8�Lw,��Or�:瓞	J�8���`m/�N�
*E�v������M��3M�$��������-&�Y��.�'�d?(*{�#�Iާ��oi�y�@��KRkSe��+K<���2Z�,Fo�O5��M��&��Q�T}&�����<�#o�ۡ;em�!�%�vj��_���3#
�~0V�l' ٱ6���� �Rhn��x�-�	 �ޞگ�3��ǳK�n9f9���jsJ=�\^����!}g
��4��,�gs�}&�#-k��J2�ۡ��aI�s����ۋoG�[-F��r@��mՔ:ϘF�Wߨd����A&UT$N�t[���,�2�S'�H!��H�`
TkF�[�������,%	5Bg�6���o6��-���|0�M!��Ց.�X<{�ѣ�����@�Ma|�c3�l~S��g�K�@9�I_+(��3�0Ihfw�J���C�f�\ L��^:f؎Z��w)7�>��Ov���\�<��r2'[A�Ä�$}�{�����n���`}�./�&�}*�Ѡ�� ��JV�}H�AXT���7%�5�_�K�}�w��t��W�E�3ZL^�O��\eV�c�(!R�y��
��6���0p�Bo's�m2z��2U�q]q^4�Z�$V�l��aOZ8;�R�.�D��U܄
�ȸ`" ��$�Sa�`�\�U_p����ť�����b�H��F����y9����	�Ӹ��4����+f &��A�hX��R���	���(�ɼ��&������*�
M:�U���"TG�Tw�K񮑧�!��iS�;���q+��`+����1p���&�oA;��U�i58B����h5������a�Ca&lpٻP�{̧ɞ��R]c��:��][
```

## public\vite.svg

```
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" aria-hidden="true" role="img" class="iconify iconify--logos" width="31.88" height="32" preserveAspectRatio="xMidYMid meet" viewBox="0 0 256 257"><defs><linearGradient id="IconifyId1813088fe1fbc01fb466" x1="-.828%" x2="57.636%" y1="7.652%" y2="78.411%"><stop offset="0%" stop-color="#41D1FF"></stop><stop offset="100%" stop-color="#BD34FE"></stop></linearGradient><linearGradient id="IconifyId1813088fe1fbc01fb467" x1="43.376%" x2="50.316%" y1="2.242%" y2="89.03%"><stop offset="0%" stop-color="#FFEA83"></stop><stop offset="8.333%" stop-color="#FFDD35"></stop><stop offset="100%" stop-color="#FFA800"></stop></linearGradient></defs><path fill="url(#IconifyId1813088fe1fbc01fb466)" d="M255.153 37.938L134.897 252.976c-2.483 4.44-8.862 4.466-11.382.048L.875 37.958c-2.746-4.814 1.371-10.646 6.827-9.67l120.385 21.517a6.537 6.537 0 0 0 2.322-.004l117.867-21.483c5.438-.991 9.574 4.796 6.877 9.62Z"></path><path fill="url(#IconifyId1813088fe1fbc01fb467)" d="M185.432.063L96.44 17.501a3.268 3.268 0 0 0-2.634 3.014l-5.474 92.456a3.268 3.268 0 0 0 3.997 3.378l24.777-5.718c2.318-.535 4.413 1.507 3.936 3.838l-7.361 36.047c-.495 2.426 1.782 4.5 4.151 3.78l15.304-4.649c2.372-.72 4.652 1.36 4.15 3.788l-11.698 56.621c-.732 3.542 3.979 5.473 5.943 2.437l1.313-2.028l72.516-144.72c1.215-2.423-.88-5.186-3.54-4.672l-25.505 4.922c-2.396.462-4.435-1.77-3.759-4.114l16.646-57.705c.677-2.35-1.37-4.583-3.769-4.113Z"></path></svg>
```

## README.md

```markdown
# React + TypeScript + Vite

This template provides a minimal setup to get React working in Vite with HMR and some ESLint rules.

Currently, two official plugins are available:

- [@vitejs/plugin-react](https://github.com/vitejs/vite-plugin-react/blob/main/packages/plugin-react/README.md) uses [Babel](https://babeljs.io/) for Fast Refresh
- [@vitejs/plugin-react-swc](https://github.com/vitejs/vite-plugin-react-swc) uses [SWC](https://swc.rs/) for Fast Refresh

## Expanding the ESLint configuration

If you are developing a production application, we recommend updating the configuration to enable type-aware lint rules:

```js
export default tseslint.config({
  extends: [
    // Remove ...tseslint.configs.recommended and replace with this
    ...tseslint.configs.recommendedTypeChecked,
    // Alternatively, use this for stricter rules
    ...tseslint.configs.strictTypeChecked,
    // Optionally, add this for stylistic rules
    ...tseslint.configs.stylisticTypeChecked,
  ],
  languageOptions: {
    // other options...
    parserOptions: {
      project: ['./tsconfig.node.json', './tsconfig.app.json'],
      tsconfigRootDir: import.meta.dirname,
    },
  },
})
```

You can also install [eslint-plugin-react-x](https://github.com/Rel1cx/eslint-react/tree/main/packages/plugins/eslint-plugin-react-x) and [eslint-plugin-react-dom](https://github.com/Rel1cx/eslint-react/tree/main/packages/plugins/eslint-plugin-react-dom) for React-specific lint rules:

```js
// eslint.config.js
import reactX from 'eslint-plugin-react-x'
import reactDom from 'eslint-plugin-react-dom'

export default tseslint.config({
  plugins: {
    // Add the react-x and react-dom plugins
    'react-x': reactX,
    'react-dom': reactDom,
  },
  rules: {
    // other rules...
    // Enable its recommended typescript rules
    ...reactX.configs['recommended-typescript'].rules,
    ...reactDom.configs.recommended.rules,
  },
})
```

```

## src\api\axios.ts

```typescript
// frontend/src/api/axios.ts
import axios from 'axios';

const api = axios.create({
  baseURL: 'http://localhost:3000/api', // 👈 Este debe apuntar al backend
});

export default api;

```

## src\App.css

```css
#root {
  max-width: 1280px;
  margin: 0 auto;
  padding: 2rem;
  text-align: center;
}

.logo {
  height: 6em;
  padding: 1.5em;
  will-change: filter;
  transition: filter 300ms;
}
.logo:hover {
  filter: drop-shadow(0 0 2em #646cffaa);
}
.logo.react:hover {
  filter: drop-shadow(0 0 2em #61dafbaa);
}

@keyframes logo-spin {
  from {
    transform: rotate(0deg);
  }
  to {
    transform: rotate(360deg);
  }
}

@media (prefers-reduced-motion: no-preference) {
  a:nth-of-type(2) .logo {
    animation: logo-spin infinite 20s linear;
  }
}

.card {
  padding: 2em;
}

.read-the-docs {
  color: #888;
}

```

## src\App.tsx

```tsx
// src/App.tsx
import { BrowserRouter as Router } from "react-router-dom";
import AppRouter from "./router/AppRouter";
import { ToastContainer } from "react-toastify";
import { useAuthModal } from "./store/useAuthModal";
import AuthModal from "./components/auth/AuthModal";
import RouteModalHandler from "./components/RouteModalHandler";
import "react-toastify/dist/ReactToastify.css";

function App() {
  const { isOpen } = useAuthModal();

  return (
    <Router>
      <RouteModalHandler />
      <AppRouter />
      {isOpen && <AuthModal />}
      <ToastContainer position="top-right" autoClose={3000} />
    </Router>
  );
}

export default App;

```

## src\assets\react.svg

```
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" aria-hidden="true" role="img" class="iconify iconify--logos" width="35.93" height="32" preserveAspectRatio="xMidYMid meet" viewBox="0 0 256 228"><path fill="#00D8FF" d="M210.483 73.824a171.49 171.49 0 0 0-8.24-2.597c.465-1.9.893-3.777 1.273-5.621c6.238-30.281 2.16-54.676-11.769-62.708c-13.355-7.7-35.196.329-57.254 19.526a171.23 171.23 0 0 0-6.375 5.848a155.866 155.866 0 0 0-4.241-3.917C100.759 3.829 77.587-4.822 63.673 3.233C50.33 10.957 46.379 33.89 51.995 62.588a170.974 170.974 0 0 0 1.892 8.48c-3.28.932-6.445 1.924-9.474 2.98C17.309 83.498 0 98.307 0 113.668c0 15.865 18.582 31.778 46.812 41.427a145.52 145.52 0 0 0 6.921 2.165a167.467 167.467 0 0 0-2.01 9.138c-5.354 28.2-1.173 50.591 12.134 58.266c13.744 7.926 36.812-.22 59.273-19.855a145.567 145.567 0 0 0 5.342-4.923a168.064 168.064 0 0 0 6.92 6.314c21.758 18.722 43.246 26.282 56.54 18.586c13.731-7.949 18.194-32.003 12.4-61.268a145.016 145.016 0 0 0-1.535-6.842c1.62-.48 3.21-.974 4.76-1.488c29.348-9.723 48.443-25.443 48.443-41.52c0-15.417-17.868-30.326-45.517-39.844Zm-6.365 70.984c-1.4.463-2.836.91-4.3 1.345c-3.24-10.257-7.612-21.163-12.963-32.432c5.106-11 9.31-21.767 12.459-31.957c2.619.758 5.16 1.557 7.61 2.4c23.69 8.156 38.14 20.213 38.14 29.504c0 9.896-15.606 22.743-40.946 31.14Zm-10.514 20.834c2.562 12.94 2.927 24.64 1.23 33.787c-1.524 8.219-4.59 13.698-8.382 15.893c-8.067 4.67-25.32-1.4-43.927-17.412a156.726 156.726 0 0 1-6.437-5.87c7.214-7.889 14.423-17.06 21.459-27.246c12.376-1.098 24.068-2.894 34.671-5.345a134.17 134.17 0 0 1 1.386 6.193ZM87.276 214.515c-7.882 2.783-14.16 2.863-17.955.675c-8.075-4.657-11.432-22.636-6.853-46.752a156.923 156.923 0 0 1 1.869-8.499c10.486 2.32 22.093 3.988 34.498 4.994c7.084 9.967 14.501 19.128 21.976 27.15a134.668 134.668 0 0 1-4.877 4.492c-9.933 8.682-19.886 14.842-28.658 17.94ZM50.35 144.747c-12.483-4.267-22.792-9.812-29.858-15.863c-6.35-5.437-9.555-10.836-9.555-15.216c0-9.322 13.897-21.212 37.076-29.293c2.813-.98 5.757-1.905 8.812-2.773c3.204 10.42 7.406 21.315 12.477 32.332c-5.137 11.18-9.399 22.249-12.634 32.792a134.718 134.718 0 0 1-6.318-1.979Zm12.378-84.26c-4.811-24.587-1.616-43.134 6.425-47.789c8.564-4.958 27.502 2.111 47.463 19.835a144.318 144.318 0 0 1 3.841 3.545c-7.438 7.987-14.787 17.08-21.808 26.988c-12.04 1.116-23.565 2.908-34.161 5.309a160.342 160.342 0 0 1-1.76-7.887Zm110.427 27.268a347.8 347.8 0 0 0-7.785-12.803c8.168 1.033 15.994 2.404 23.343 4.08c-2.206 7.072-4.956 14.465-8.193 22.045a381.151 381.151 0 0 0-7.365-13.322Zm-45.032-43.861c5.044 5.465 10.096 11.566 15.065 18.186a322.04 322.04 0 0 0-30.257-.006c4.974-6.559 10.069-12.652 15.192-18.18ZM82.802 87.83a323.167 323.167 0 0 0-7.227 13.238c-3.184-7.553-5.909-14.98-8.134-22.152c7.304-1.634 15.093-2.97 23.209-3.984a321.524 321.524 0 0 0-7.848 12.897Zm8.081 65.352c-8.385-.936-16.291-2.203-23.593-3.793c2.26-7.3 5.045-14.885 8.298-22.6a321.187 321.187 0 0 0 7.257 13.246c2.594 4.48 5.28 8.868 8.038 13.147Zm37.542 31.03c-5.184-5.592-10.354-11.779-15.403-18.433c4.902.192 9.899.29 14.978.29c5.218 0 10.376-.117 15.453-.343c-4.985 6.774-10.018 12.97-15.028 18.486Zm52.198-57.817c3.422 7.8 6.306 15.345 8.596 22.52c-7.422 1.694-15.436 3.058-23.88 4.071a382.417 382.417 0 0 0 7.859-13.026a347.403 347.403 0 0 0 7.425-13.565Zm-16.898 8.101a358.557 358.557 0 0 1-12.281 19.815a329.4 329.4 0 0 1-23.444.823c-7.967 0-15.716-.248-23.178-.732a310.202 310.202 0 0 1-12.513-19.846h.001a307.41 307.41 0 0 1-10.923-20.627a310.278 310.278 0 0 1 10.89-20.637l-.001.001a307.318 307.318 0 0 1 12.413-19.761c7.613-.576 15.42-.876 23.31-.876H128c7.926 0 15.743.303 23.354.883a329.357 329.357 0 0 1 12.335 19.695a358.489 358.489 0 0 1 11.036 20.54a329.472 329.472 0 0 1-11 20.722Zm22.56-122.124c8.572 4.944 11.906 24.881 6.52 51.026c-.344 1.668-.73 3.367-1.15 5.09c-10.622-2.452-22.155-4.275-34.23-5.408c-7.034-10.017-14.323-19.124-21.64-27.008a160.789 160.789 0 0 1 5.888-5.4c18.9-16.447 36.564-22.941 44.612-18.3ZM128 90.808c12.625 0 22.86 10.235 22.86 22.86s-10.235 22.86-22.86 22.86s-22.86-10.235-22.86-22.86s10.235-22.86 22.86-22.86Z"></path></svg>
```

## src\components\auth\AuthForm.tsx

```tsx
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { AxiosError } from "axios";
import api from "../../api/axios";
import { toast } from "react-toastify";
import { useAuthModal } from "../../store/useAuthModal";
import AuthResendModal from "./AuthResendModal";
import {
  getPasswordScore,
  capitalizeName,
  validateEmailFormat,
  validatePasswordSecurity,
} from "../../utils/validationHelpersForm";

import InputWithLabel from "../common/InputWithLabel";
import PasswordWithStrengthInput from "../common/PasswordWithStrengthInputForm";

interface Props {
  modalStep: "notice" | "form" | "success";
  showModal: boolean;
  modalType: "confirm" | "recover";
  setFormEmail: React.Dispatch<React.SetStateAction<string>>;
  setModalStep: React.Dispatch<
    React.SetStateAction<"notice" | "form" | "success">
  >;
  setShowModal: React.Dispatch<React.SetStateAction<boolean>>;
  setModalType: React.Dispatch<React.SetStateAction<"confirm" | "recover">>;
}

const initialForm = {
  fullName: "",
  email: "",
  phone: "",
  password: "",
  confirmPassword: "",
};

export default function AuthForm({
  modalStep,
  showModal,
  modalType,
  setFormEmail,
  setModalStep,
  setShowModal,
  setModalType,
}: Props) {
  const { view, closeModal, toggleView } = useAuthModal();
  const isLogin = view === "login";
  const navigate = useNavigate();

  const [formData, setFormData] = useState(initialForm);
  const [errors, setErrors] = useState<{ [key: string]: string }>({});
  const [passwordStrength, setPasswordStrength] = useState(0);
  const [resendMsg, setResendMsg] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);

  const handleInput = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;

    const formattedValue = name === "fullName" ? capitalizeName(value) : value;

    if (name === "password") setPasswordStrength(getPasswordScore(value));

    setFormData((prev) => ({ ...prev, [name]: formattedValue }));
    setErrors((prev) => ({ ...prev, [name]: "" }));
  };

  const validate = () => {
    const errs: { [key: string]: string } = {};

    if (!validateEmailFormat(formData.email)) {
      errs.email = "Correo no válido";
    }

    const passwordErrors = validatePasswordSecurity(
      formData.password,
      formData.email
    );
    if (passwordErrors.length > 0) {
      errs.password = passwordErrors.join(" ");
    }

    if (!isLogin) {
      if (!formData.fullName || formData.fullName.length < 2) {
        errs.fullName = "El nombre debe tener al menos 2 caracteres.";
      }

      if (!/^[0-9]{10}$/.test(formData.phone)) {
        errs.phone = "El teléfono debe tener 10 dígitos.";
      }

      if (formData.password !== formData.confirmPassword) {
        errs.confirmPassword = "Las contraseñas no coinciden.";
      }
    }

    setErrors(errs);
    return Object.keys(errs).length === 0;
  };

  const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (isSubmitting) return; // Evita múltiples envíos
    setIsSubmitting(true);

    const isValid = validate();
    if (!isValid) {
      setIsSubmitting(false); // 🔁 Agrega esto para volver a habilitar el botón
      return;
    }

    try {
      if (isLogin) {
        const res = await api.post("/login", {
          email: formData.email,
          password: formData.password,
        });

        if (!res.data.user.isConfirmed) {
          const tokenExpired = res.data.tokenExpired;
          setModalType("confirm");
          setModalStep(tokenExpired ? "form" : "notice");
          setShowModal(true);
          return;
        }

        closeModal();
        toast.success("Login exitoso!");
        navigate("/");
      } else {
        const res = await api.post("/register", {
          name: formData.fullName,
          email: formData.email,
          phone: formData.phone,
          password: formData.password,
        });

        if (res.status === 200 || res.status === 201) {
          toast.success("Registro exitoso. Revisa tu correo.");
          toggleView();
        }
      }
    } catch (err) {
      const error = err as AxiosError<{
        message: string;
        tokenExpired?: boolean;
      }>;
      const msg = error.response?.data?.message;

      if (msg === "Debes confirmar tu cuenta") {
        const tokenExpired = error.response?.data?.tokenExpired;
        setModalType("confirm");
        setModalStep(tokenExpired ? "form" : "notice");
        setShowModal(true);
      } else if (msg) {
        toast.error(msg);
      } else {
        toast.error("Ocurrió un error inesperado.");
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleResend = async (e: React.FormEvent) => {
    e.preventDefault();
    if (isSubmitting) return; // Evita múltiples envíos
    setIsSubmitting(true);
    setResendMsg("");

    const endpoint =
      modalType === "recover" ? "/send-recovery" : "/resend-confirmation";

    try {
      const res = await api.post(endpoint, {
        email: formData.email,
      });

      setResendMsg(res.data.message);
      setModalStep("success");

      setTimeout(() => {
        toast.success(
          modalType === "recover"
            ? "¡Enlace de recuperación enviado!"
            : "¡Correo de confirmación reenviado!"
        );
        setShowModal(false);
        setResendMsg("");
        setFormData((prev) => ({ ...prev, email: "", password: "" }));
      }, 5000);
    } catch (err) {
      const error = err as AxiosError<{ message: string }>;
      const msg = error.response?.data?.message;

      if (msg === "La cuenta ya está confirmada") {
        toast.info("La cuenta ya ha sido confirmada.");
        setShowModal(false);
      } else {
        setResendMsg("Error al enviar el enlace.");
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <>
      <form onSubmit={handleSubmit} className="space-y-4">
        {!isLogin && (
          <>
            <InputWithLabel
              label=""
              name="fullName"
              value={formData.fullName}
              onChange={handleInput}
              placeholder="Tu nombre completo"
              error={errors.fullName}
            />

            <InputWithLabel
              label=""
              name="phone"
              value={formData.phone}
              onChange={handleInput}
              placeholder="Teléfono"
              error={errors.phone}
            />
          </>
        )}

        <InputWithLabel
          label=""
          name="email"
          type="email"
          value={formData.email}
          onChange={handleInput}
          placeholder="Mail"
          error={errors.email}
          autoFocus
        />

        <PasswordWithStrengthInput
          value={formData.password}
          onChange={handleInput}
          error={errors.password}
          showTooltip={!isLogin}
          showStrengthBar={!isLogin}
        />

        {!isLogin && (
          <InputWithLabel
            label=""
            name="confirmPassword"
            type="password"
            value={formData.confirmPassword}
            onChange={handleInput}
            placeholder="Confirma tu contraseña"
            error={errors.confirmPassword}
          />
        )}

        {isLogin && (
          <div className="flex justify-end text-sm text-blue-600">
            <button
              type="button"
              className="hover:underline"
              onClick={() => {
                setModalType("recover");
                setModalStep("form");
                setShowModal(true);
                setFormEmail(formData.email); // importante para usar en el modal
              }}
            >
              Forgot Password?
            </button>
          </div>
        )}

        <button
          type="submit"
          disabled={isSubmitting || (!isLogin && passwordStrength < 3)}
          className={`w-full bg-gradient-to-r from-indigo-500 via-purple-500 to-pink-500 text-white py-2 rounded-lg hover:opacity-90 transition-all ${
            isSubmitting ? "opacity-50 cursor-not-allowed" : ""
          }`}
        >
          {isSubmitting ? "Conectando..." : isLogin ? "Sign In" : "Sign Up"}
        </button>

        <p className="text-center text-sm text-gray-600 mt-4">
          {isLogin ? "Don’t have an account?" : "Already have an account?"}{" "}
          <button
            type="button"
            onClick={toggleView}
            className="text-blue-600 font-semibold hover:underline"
          >
            {isLogin ? "Sign Up" : "Sign In"}
          </button>
        </p>
      </form>

      <AuthResendModal
        modalStep={modalStep}
        showModal={showModal}
        email={formData.email}
        resendMsg={resendMsg}
        onClose={() => setShowModal(false)}
        onEmailChange={(email) => setFormData((prev) => ({ ...prev, email }))}
        onResend={handleResend}
        type={modalType}
      />
    </>
  );
}

```

## src\components\auth\AuthModal.tsx

```tsx
import { motion, AnimatePresence } from "framer-motion";
import { FaTimes } from "react-icons/fa";
import { useAuthModal } from "../../store/useAuthModal";
import AuthForm from "./AuthForm";
import AuthSidePanel from "./AuthSidePanel";
import AuthResendModal from "./AuthResendModal";
import { useEffect, useRef, useState } from "react";
import api from "../../api/axios";
import { AxiosError } from "axios";
import { toast } from "react-toastify";

const messages = {
  login: {
    title: "Welcome Back! 👋",
    description: "We're so excited to see you again! Enter your details to access your account.",
    sideTitle: "New Here? 🌟",
    sideDescription: "Join our community and discover amazing features!",
    sideButton: "Create Account",
    submit: "Sign In",
  },
  register: {
    title: "Join Our Community! 🎉",
    description: "Create an account and start your journey with us today.",
    sideTitle: "One of Us? 🎈",
    sideDescription: "Already have an account? Sign in and continue your journey!",
    sideButton: "Sign In",
    submit: "Sign Up",
  },
};

export default function AuthModal() {
  const { isOpen, closeModal, view, toggleView } = useAuthModal();
  const isLogin = view === "login";
  const modalRef = useRef<HTMLDivElement>(null);

  const [formEmail, setFormEmail] = useState("");
  const [resendMsg, setResendMsg] = useState("");
  const [modalStep, setModalStep] = useState<"notice" | "form" | "success">("notice");
  const [modalType, setModalType] = useState<"confirm" | "recover">("confirm");
  const [showModal, setShowModal] = useState(false);

  useEffect(() => {
    const closeOnOutside = (e: MouseEvent) => {
      if (modalRef.current && !modalRef.current.contains(e.target as Node)) closeModal();
    };
    const closeOnEsc = (e: KeyboardEvent) => {
      if (e.key === "Escape") closeModal();
    };
    document.addEventListener("mousedown", closeOnOutside);
    document.addEventListener("keydown", closeOnEsc);
    return () => {
      document.removeEventListener("mousedown", closeOnOutside);
      document.removeEventListener("keydown", closeOnEsc);
    };
  }, [closeModal]);

  const handleResend = async (e: React.FormEvent) => {
    e.preventDefault();
    setResendMsg("");

    const endpoint =
      modalType === "recover" ? "/send-recovery" : "/resend-confirmation";

    try {
      const res = await api.post(endpoint, { email: formEmail });
      setResendMsg(res.data.message);
      setModalStep("success");

      setTimeout(() => {
        toast.success(
          modalType === "recover"
            ? "¡Correo de recuperación enviado!"
            : "¡Correo reenviado!, Revisa tu bandeja..."
        );
        setShowModal(false);
        setResendMsg("");
        setFormEmail("");
      }, 5000);
    } catch (err) {
      const error = err as AxiosError<{ message: string }>;
      const msg = error.response?.data?.message;

      if (msg === "La cuenta ya está confirmada") {
        toast.info("La cuenta ya ha sido confirmada.");
        setShowModal(false);
      } else {
        setResendMsg("Error al reenviar el enlace.");
      }
    }
  };

  if (!isOpen) return null;

  const isDesktop = typeof window !== "undefined" && window.innerWidth >= 768;

  return (
    <>
      <motion.div
        className="fixed inset-0 bg-black/40 backdrop-blur-sm z-[999] flex items-center justify-center p-4 overflow-y-auto"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
      >
        <button
          onClick={closeModal}
          className="absolute top-4 right-4 z-[1000] text-white text-2xl bg-black/50 hover:bg-black/70 p-2 rounded-full"
        >
          <FaTimes />
        </button>

        <motion.div
          ref={modalRef}
          initial={{ scale: 0.95, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          exit={{ scale: 0.9, opacity: 0 }}
          transition={{ duration: 0.3 }}
          className={`bg-bgLight dark:bg-gray-900 text-gray-800 dark:text-gray-100 backdrop-blur-md rounded-3xl shadow-2xl shadow-bgLight w-full max-w-4xl flex flex-col md:flex-row overflow-hidden transition-all ease-in-out duration-700 ${
            isLogin ? "md:flex-row-reverse" : "md:flex-row"
          }`}
        >
          {isDesktop && (
            <AnimatePresence mode="wait">
              <motion.div
                key={view}
                initial={{ x: isLogin ? 300 : -300, opacity: 0 }}
                animate={{ x: 0, opacity: 1 }}
                exit={{ x: isLogin ? -300 : 300, opacity: 0 }}
                transition={{ duration: 0.5, ease: "easeInOut" }}
                className="hidden md:flex w-full md:w-1/2 p-6 md:p-8 flex-col justify-center text-center space-y-6 bg-white dark:bg-gray-800"
              >
                <AuthSidePanel
                  title={messages[view].sideTitle}
                  description={messages[view].sideDescription}
                  buttonText={messages[view].sideButton}
                  onToggle={toggleView}
                />
              </motion.div>
            </AnimatePresence>
          )}

          <AnimatePresence mode="wait">
            <motion.div
              key={`${view}-form`}
              initial={{ x: isLogin ? -300 : 300, opacity: 0 }}
              animate={{ x: 0, opacity: 1 }}
              exit={{ x: isLogin ? 300 : -300, opacity: 0 }}
              transition={{ duration: 0.5, ease: "easeInOut" }}
              className={`w-full md:w-1/2 p-6 md:p-8 bg-gray-50 dark:bg-gray-900 flex flex-col justify-center`}
            >
              <h2 className="text-3xl font-bold text-center mb-2 bg-gradient-to-r from-indigo-500 via-purple-500 to-pink-500 text-transparent bg-clip-text">
                {messages[view].title}
              </h2>
              <p className="text-center text-sm text-gray-600 dark:text-gray-300 mb-4">
                {messages[view].description}
              </p>

              <AuthForm
                modalStep={modalStep}
                showModal={showModal}
                modalType={modalType}
                setFormEmail={setFormEmail}
                setModalStep={setModalStep}
                setShowModal={setShowModal}
                setModalType={setModalType}
              />
            </motion.div>
          </AnimatePresence>
        </motion.div>
      </motion.div>

      <AuthResendModal
        modalStep={modalStep}
        showModal={showModal}
        email={formEmail}
        resendMsg={resendMsg}
        onClose={() => setShowModal(false)}
        onEmailChange={setFormEmail}
        onResend={handleResend}
        type={modalType}
      />
    </>
  );
}

```

## src\components\auth\AuthResendModal.tsx

```tsx
import { useState, FormEvent } from "react";
import { FaCheckCircle, FaInfoCircle } from "react-icons/fa";

interface Props {
  showModal: boolean;
  modalStep: "notice" | "form" | "success";
  email: string;
  resendMsg: string;
  onClose: () => void;
  onEmailChange: (email: string) => void;
  onResend: (e: React.FormEvent) => void;
  type: "confirm" | "recover";
}

export default function AuthResendModal({
  showModal,
  modalStep,
  email,
  resendMsg,
  onClose,
  onEmailChange,
  onResend,
  type,
}: Props) {

  const [isSending, setIsSending] = useState(false);

  const handleLocalResend = async (e: FormEvent) => {
    if (isSending) return;
    setIsSending(true);
    await onResend(e);
    setIsSending(false);
  };

  if (!showModal) return null;

  const isRecover = type === "recover";
  const title = isRecover ? "Recuperar Contraseña" : "Verifica tu cuenta";
  const formTitle = isRecover ? "¿Necesitas un nuevo enlace?" : "Reenviar Enlace";
  const formDescription = isRecover ? "Ingresa tu correo para recuperar tu contraseña." : "Ingresa tu correo para recibir un nuevo enlace de confirmación:";
  const successMsg =
    resendMsg ||
    (isRecover
      ? "Enlace de recuperación enviado con éxito. Revisa tu correo."
      : "Enlace de confirmación reenviado con éxito. Revisa tu correo.");

  return (
    <div
      className="fixed inset-0 bg-black/40 z-[1000] flex items-center justify-center"
      onMouseDown={onClose}
    >
      <div
        className="bg-white rounded-lg shadow-lg p-6 w-full max-w-md relative text-center"
        onMouseDown={(e) => e.stopPropagation()} // Esto evita que el click cierre el modal
      >
        <button
          onClick={onClose}
          className="absolute top-2 right-3 text-gray-500 hover:text-red-500 text-lg font-bold"
        >
          &times;
        </button>

        {modalStep === "notice" && (
          <>
            <FaInfoCircle className="text-yellow-500 text-4xl mx-auto mb-2" />
            <h2 className="text-xl font-bold mb-2 text-sky-600">{title}</h2>
            <p className="text-sm text-gray-600 mb-4">
              {isRecover
                ? "Ingresa tu correo para recuperar tu contraseña."
                : "Aún no has confirmado tu cuenta. Revisa tu correo para activarla."}
            </p>
          </>
        )}

        {modalStep === "form" && (
          <>
            <h2 className="text-xl font-bold mb-2 text-sky-600">{formTitle}</h2>
            <p className="text-sm text-gray-600 mb-4">{formDescription}</p>
            <form onSubmit={handleLocalResend} className="space-y-4">
              <input
                type="email"
                placeholder="Tu correo"
                className="w-full px-4 py-2 border rounded-md"
                value={email}
                onChange={(e) => onEmailChange(e.target.value)}
                required
              />
              <button
                type="submit"
                disabled={isSending}
                className={`w-full bg-sky-600 text-white py-2 rounded hover:bg-sky-700 transition ${
                  isSending ? "opacity-50 cursor-not-allowed" : ""
                }`}
              >
                {isSending ? "Enviando..." : "Reenviar enlace"}
              </button>
              {resendMsg && <p className="text-sm text-red-500">{resendMsg}</p>}
            </form>
          </>
        )}

        {modalStep === "success" && (
          <>
            <FaCheckCircle className="text-green-500 text-4xl mx-auto mb-2" />
            <p className="text-green-600 text-sm font-medium">{successMsg}</p>
            <p className="text-sm text-gray-500 mt-2">
              Serás redirigido al login...
            </p>
          </>
        )}
      </div>
    </div>
  );
}

```

## src\components\auth\AuthSidePanel.tsx

```tsx
// src/components/auth/AuthSidePanel.tsx
import { motion } from "framer-motion";

interface Props {
  title: string;
  description: string;
  buttonText: string;
  onToggle: () => void;
}

export default function AuthSidePanel({ title, description, buttonText, onToggle }: Props) {
  return (
    <motion.div
      key={title}
      initial={{ x: 300, opacity: 0 }}
      animate={{ x: 0, opacity: 1 }}
      exit={{ x: -300, opacity: 0 }}
      transition={{ duration: 0.5, ease: "easeInOut" }}
      className="w-full md:w-fit p-6 md:p-8 flex flex-col justify-center text-center space-y-6 bg-white"
    >
      <h2 className="text-3xl md:text-4xl font-bold bg-gradient-to-r from-indigo-500 via-purple-500 to-pink-500 text-transparent bg-clip-text">
        {title}
      </h2>
      <p className="text-gray-600">{description}</p>
      <button
        onClick={onToggle}
        className="px-6 py-3 rounded-full bg-gradient-to-r from-indigo-500 via-purple-500 to-pink-500 text-white font-semibold hover:scale-105 transition-all"
      >
        {buttonText}
      </button>
    </motion.div>
  );
}

```

## src\components\common\Alert.tsx

```tsx
import React from "react";
import classNames from "classnames";
import {
  FaCheckCircle,
  FaExclamationTriangle,
  FaInfoCircle,
  FaTimesCircle,
} from "react-icons/fa";

interface AlertProps {
  type?: "success" | "error" | "warning" | "info";
  message: string;
  className?: string;
}

const iconMap = {
  success: <FaCheckCircle className="text-green-600 text-xl mr-2" />,
  error: <FaTimesCircle className="text-red-600 text-xl mr-2" />,
  warning: <FaExclamationTriangle className="text-yellow-600 text-xl mr-2" />,
  info: <FaInfoCircle className="text-blue-600 text-xl mr-2" />,
};

const Alert: React.FC<AlertProps> = ({
  type = "info",
  message,
  className = "",
}) => {
  const baseStyles =
    "flex items-start gap-2 px-4 py-3 rounded-md shadow-sm text-sm font-medium";

  const typeStyles = {
    success: "bg-green-100 text-green-800 dark:bg-green-900/20 dark:text-green-200",
    error: "bg-red-100 text-red-800 dark:bg-red-900/20 dark:text-red-200",
    warning: "bg-yellow-100 text-yellow-800 dark:bg-yellow-900/20 dark:text-yellow-200",
    info: "bg-blue-100 text-blue-800 dark:bg-blue-900/20 dark:text-blue-200",
  };

  return (
    <div className={classNames(baseStyles, typeStyles[type], className)}>
      {iconMap[type]}
      <span>{message}</span>
    </div>
  );
};

export default Alert;

```

## src\components\common\Avatar.tsx

```tsx
import React from "react";
import classNames from "classnames";

interface AvatarProps {
  name?: string;
  imageUrl?: string;
  size?: "sm" | "md" | "lg";
  status?: "online" | "offline" | "busy";
  className?: string;
}

const sizeClasses = {
  sm: "w-8 h-8 text-sm",
  md: "w-10 h-10 text-base",
  lg: "w-14 h-14 text-lg",
};

const statusColors = {
  online: "bg-green-500",
  offline: "bg-gray-400",
  busy: "bg-red-500",
};

export const Avatar: React.FC<AvatarProps> = ({
  name,
  imageUrl,
  size = "md",
  status,
  className = "",
}) => {
  const initials = name
    ? name
        .split(" ")
        .map((n) => n[0])
        .join("")
        .toUpperCase()
        .slice(0, 2)
    : "?";

  return (
    <div className={classNames("relative inline-block", className)}>
      <div
        className={classNames(
          "rounded-full bg-gray-200 dark:bg-gray-700 flex items-center justify-center overflow-hidden text-white font-semibold",
          sizeClasses[size]
        )}
      >
        {imageUrl ? (
          <img
            src={imageUrl}
            alt={name}
            className="w-full h-full object-cover"
          />
        ) : (
          <span>{initials}</span>
        )}
      </div>

      {status && (
        <span
          className={classNames(
            "absolute bottom-0 right-0 w-3 h-3 rounded-full ring-2 ring-white dark:ring-gray-900",
            statusColors[status]
          )}
        />
      )}
    </div>
  );
};

export default Avatar;

```

## src\components\common\Breadcrumb.tsx

```tsx
import React from "react";
import { Link } from "react-router-dom";
import { FaChevronRight } from "react-icons/fa";

interface BreadcrumbItem {
  label: string;
  path?: string;
  isCurrent?: boolean;
}

interface BreadcrumbProps {
  items: BreadcrumbItem[];
  className?: string;
}

const Breadcrumb: React.FC<BreadcrumbProps> = ({ items, className = "" }) => {
  return (
    <nav
      className={`text-sm text-gray-600 dark:text-gray-300 ${className}`}
      aria-label="breadcrumb"
    >
      <ol className="flex flex-wrap items-center space-x-2">
        {items.map((item, idx) => (
          <li key={idx} className="flex items-center">
            {item.path && !item.isCurrent ? (
              <Link
                to={item.path}
                className="hover:underline text-blue-600 dark:text-blue-400"
              >
                {item.label}
              </Link>
            ) : (
              <span className="font-semibold text-gray-900 dark:text-white">
                {item.label}
              </span>
            )}
            {idx < items.length - 1 && (
              <FaChevronRight className="mx-2 text-xs text-gray-400" />
            )}
          </li>
        ))}
      </ol>
    </nav>
  );
};

export default Breadcrumb;

```

## src\components\common\Button.tsx

```tsx
import React from "react";
import { Spinner } from "./Spinner";
import classNames from "classnames";

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: "primary" | "secondary" | "danger" | "outline";
  isLoading?: boolean;
  fullWidth?: boolean;
}

const Button: React.FC<ButtonProps> = ({
  children,
  variant = "primary",
  isLoading = false,
  fullWidth = false,
  className,
  ...props
}) => {
  const baseStyles =
    "inline-flex items-center justify-center px-4 py-2 rounded-md font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-offset-2";

  const variantStyles = {
    primary:
      "bg-blue-600 text-white hover:bg-blue-700 focus:ring-blue-500 dark:bg-blue-500 dark:hover:bg-blue-600",
    secondary:
      "bg-gray-200 text-gray-900 hover:bg-gray-300 focus:ring-gray-400 dark:bg-gray-700 dark:text-white dark:hover:bg-gray-600",
    danger:
      "bg-red-600 text-white hover:bg-red-700 focus:ring-red-500 dark:bg-red-500 dark:hover:bg-red-600",
    outline:
      "border border-gray-300 text-gray-700 hover:bg-gray-100 focus:ring-gray-400 dark:border-gray-600 dark:text-white dark:hover:bg-gray-700",
  };

  const computedClasses = classNames(
    baseStyles,
    variantStyles[variant],
    {
      "w-full": fullWidth,
      "opacity-50 cursor-not-allowed": props.disabled || isLoading,
    },
    className
  );

  return (
    <button className={computedClasses} disabled={props.disabled || isLoading} {...props}>
      {isLoading && <Spinner className="mr-2 h-4 w-4 animate-spin" />}
      {children}
    </button>
  );
};

export default Button;

```

## src\components\common\Card.tsx

```tsx
import React from "react";
import classNames from "classnames";

interface CardProps extends React.HTMLAttributes<HTMLDivElement> {
  title?: string;
  subtitle?: string;
  footer?: React.ReactNode;
  children: React.ReactNode;
  shadow?: boolean;
  hoverable?: boolean;
  rounded?: boolean;
  bordered?: boolean;
}

const Card: React.FC<CardProps> = ({
  title,
  subtitle,
  footer,
  children,
  className,
  shadow = true,
  hoverable = false,
  rounded = true,
  bordered = false,
  ...props
}) => {
  return (
    <div
      className={classNames(
        "bg-white dark:bg-bgDark text-textDark dark:text-textLight transition-all duration-300",
        {
          "shadow-md": shadow,
          "hover:shadow-lg hover:scale-[1.01] transform transition-all":
            hoverable,
          "rounded-lg": rounded,
          "border border-gray-200 dark:border-gray-700": bordered,
        },
        className
      )}
      {...props}
    >
      {(title || subtitle) && (
        <div className="p-4 border-b border-gray-100 dark:border-gray-700">
          {title && <h2 className="text-lg font-semibold">{title}</h2>}
          {subtitle && (
            <p className="text-sm text-gray-500 dark:text-gray-400">
              {subtitle}
            </p>
          )}
        </div>
      )}

      <div className="p-4">{children}</div>

      {footer && (
        <div className="px-4 py-3 border-t border-gray-100 dark:border-gray-700">
          {footer}
        </div>
      )}
    </div>
  );
};

export default Card;

```

## src\components\common\CardGrid.tsx

```tsx
import React from "react";
import classNames from "classnames";

interface CardGridProps {
  children: React.ReactNode;
  columns?: number; // número de columnas base (por defecto 1 en móvil, luego responsive)
  gap?: string; // espacio entre tarjetas (por defecto 'gap-6')
  className?: string;
}

const CardGrid: React.FC<CardGridProps> = ({
  children,
  columns = 1,
  gap = "gap-6",
  className = "",
}) => {
  const gridCols = {
    1: "grid-cols-1",
    2: "sm:grid-cols-2",
    3: "sm:grid-cols-2 md:grid-cols-3",
    4: "sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4",
  };

  return (
    <div
      className={classNames(
        "grid w-full",
        gap,
        gridCols[columns as keyof typeof gridCols],
        className
      )}
    >
      {children}
    </div>
  );
};

export default CardGrid;

```

## src\components\common\CustomToast.tsx

```tsx
import { toast, ToastOptions } from "react-toastify";

const baseOptions: ToastOptions = {
  position: "top-right",
  autoClose: 4000,
  pauseOnHover: true,
  draggable: true,
  closeOnClick: true,
};

export const showSuccess = (message: string, options?: ToastOptions) => {
  toast.success(message, { ...baseOptions, ...options });
};

export const showError = (message: string, options?: ToastOptions) => {
  toast.error(message, { ...baseOptions, ...options });
};

export const showInfo = (message: string, options?: ToastOptions) => {
  toast.info(message, { ...baseOptions, ...options });
};

export const showWarning = (message: string, options?: ToastOptions) => {
  toast.warn(message, { ...baseOptions, ...options });
};

```

## src\components\common\DropdownMenu.tsx

```tsx
import { Link } from "react-router-dom";
import { AnimatePresence, motion } from "framer-motion";

interface Props {
  visible: boolean;
  menuKey: string;
  labels: string[];
  onLinkClick: () => void;
}

export const DropdownMenu: React.FC<Props> = ({
  visible,
  menuKey,
  labels,
  onLinkClick,
}) => {
  return (
    <AnimatePresence>
      {visible && (
        <motion.div
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          exit={{ opacity: 0, scale: 0.95 }}
          transition={{ duration: 0.2, ease: "easeOut" }}
          className="absolute left-1/2 transform -translate-x-1/2 top-full mt-2 w-56 max-h-[70vh] overflow-y-auto backdrop-blur-md bg-bgLight/30 dark:bg-bgDark/40 text-textDark dark:text-textLight rounded-xl shadow-xl ring-1 ring-bgLight/25 z-50"
        >
          {labels.map((label, idx) => (
            <Link
              key={idx}
              to={`/${menuKey}#${label.toLowerCase().replace(/\s+/g, "-")}`}
              onClick={onLinkClick}
              className="block px-4 py-2 text-sm font-semibold hover:bg-accent2/80 hover:text-white dark:hover:bg-bgLight/80 dark:hover:text-textDark/90 transition-all duration-200"
            >
              {label}
            </Link>
          ))}
        </motion.div>
      )}
    </AnimatePresence>
  );
};

```

## src\components\common\FormField.tsx

```tsx
import React from "react";
import classNames from "classnames";

interface FormFieldProps {
  label: string;
  name: string;
  type?: string;
  value: string;
  onChange: (e: React.ChangeEvent<HTMLInputElement>) => void;
  placeholder?: string;
  icon?: React.ReactNode;
  error?: string;
  required?: boolean;
  disabled?: boolean;
  autoComplete?: string;
}

const FormField: React.FC<FormFieldProps> = ({
  label,
  name,
  type = "text",
  value,
  onChange,
  placeholder = "",
  icon,
  error,
  required = false,
  disabled = false,
  autoComplete,
}) => {
  return (
    <div className="mb-4">
      <label
        htmlFor={name}
        className="block text-sm font-medium text-gray-700 dark:text-gray-200 mb-1"
      >
        {label} {required && <span className="text-red-500">*</span>}
      </label>

      <div className="relative">
        {icon && (
          <div className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 pointer-events-none">
            {icon}
          </div>
        )}

        <input
          type={type}
          name={name}
          id={name}
          value={value}
          onChange={onChange}
          placeholder={placeholder}
          disabled={disabled}
          autoComplete={autoComplete}
          className={classNames(
            "w-full border rounded-md py-2 px-3 focus:outline-none focus:ring-2",
            {
              "pl-10": icon,
              "border-gray-300 focus:ring-blue-500":
                !error && !disabled,
              "border-red-500 focus:ring-red-500": error,
              "bg-gray-100 cursor-not-allowed": disabled,
              "dark:bg-gray-800 dark:text-white dark:border-gray-600": true,
            }
          )}
        />
      </div>

      {error && (
        <p className="text-red-500 text-sm mt-1 font-medium">{error}</p>
      )}
    </div>
  );
};

export default FormField;

```

## src\components\common\Input.tsx

```tsx
import React from "react";
import { twMerge } from "tailwind-merge";

interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  label?: string;
  error?: string;
  icon?: React.ReactNode;
  fullWidth?: boolean;
}

const Input: React.FC<InputProps> = ({
  label,
  error,
  icon,
  fullWidth = true,
  className,
  ...props
}) => {
  return (
    <div className={twMerge("mb-4", fullWidth ? "w-full" : "", className)}>
      {label && (
        <label className="block text-sm font-medium text-gray-700 dark:text-textLight mb-1">
          {label}
        </label>
      )}

      <div className="relative">
        {icon && (
          <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-gray-500 dark:text-gray-300">
            {icon}
          </div>
        )}
        <input
          {...props}
          className={twMerge(
            "appearance-none block w-full px-3 py-2 border rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent text-sm",
            icon ? "pl-10" : "",
            error
              ? "border-red-500 focus:ring-red-500"
              : "border-gray-300 dark:border-gray-600 dark:bg-bgDark dark:text-textLight",
            props.disabled ? "opacity-50 cursor-not-allowed" : ""
          )}
        />
      </div>

      {error && (
        <p className="text-sm text-red-600 mt-1 font-medium">{error}</p>
      )}
    </div>
  );
};

export default Input;

```

## src\components\common\InputWithLabel.tsx

```tsx
import React from "react";

interface Props extends React.InputHTMLAttributes<HTMLInputElement> {
  label: string;
  name: string;
  error?: string;
}

const InputWithLabel: React.FC<Props> = ({
  label,
  name,
  error,
  ...props
}) => {
  return (
    <div className="mb-4">
      <label
        htmlFor={name}
        className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-1 flex items-center gap-2"
      >
        {label}
      </label>

      <input
        id={name}
        name={name}
        className="input-style outline-none dark:bg-gray-900 dark:text-white dark:border-gray-700"
        {...props}
      />

      {error && <p className="text-red-500 text-sm mt-1">{error}</p>}
    </div>
  );
};

export default InputWithLabel;

```

## src\components\common\Modal.tsx

```tsx
import React from "react";
import { motion, AnimatePresence } from "framer-motion";
import { FaTimes } from "react-icons/fa";

interface ModalProps {
  isOpen: boolean;
  onClose: () => void;
  title?: string;
  children: React.ReactNode;
  size?: "sm" | "md" | "lg";
  hideCloseButton?: boolean;
}

const sizeClasses = {
  sm: "max-w-sm",
  md: "max-w-md",
  lg: "max-w-2xl",
};

const Modal: React.FC<ModalProps> = ({
  isOpen,
  onClose,
  title,
  children,
  size = "md",
  hideCloseButton = false,
}) => {
  return (
    <AnimatePresence>
      {isOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <motion.div
            initial={{ opacity: 0, y: -30 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: 20 }}
            transition={{ duration: 0.3 }}
            className={`bg-white dark:bg-bgDark text-textDark dark:text-textLight rounded-lg shadow-lg w-full ${sizeClasses[size]} relative px-6 py-5`}
          >
            {!hideCloseButton && (
              <button
                className="absolute top-3 right-4 text-gray-400 hover:text-red-500 transition"
                onClick={onClose}
                aria-label="Cerrar modal"
              >
                <FaTimes />
              </button>
            )}

            {title && (
              <h2 className="text-xl font-semibold mb-4 text-center">
                {title}
              </h2>
            )}

            <div>{children}</div>
          </motion.div>
        </div>
      )}
    </AnimatePresence>
  );
};

export default Modal;

```

## src\components\common\PasswordField.tsx

```tsx
import React, { useState } from "react";
import classNames from "classnames";
import { FaEye, FaEyeSlash } from "react-icons/fa";

interface PasswordFieldProps {
  label: string;
  name: string;
  value: string;
  onChange: (e: React.ChangeEvent<HTMLInputElement>) => void;
  placeholder?: string;
  error?: string;
  required?: boolean;
  autoComplete?: string;
}

const PasswordField: React.FC<PasswordFieldProps> = ({
  label,
  name,
  value,
  onChange,
  placeholder = "••••••••",
  error,
  required = false,
  autoComplete = "current-password",
}) => {
  const [showPassword, setShowPassword] = useState(false);

  return (
    <div className="mb-4">
      <label
        htmlFor={name}
        className="block text-sm font-medium text-gray-700 dark:text-gray-200 mb-1"
      >
        {label} {required && <span className="text-red-500">*</span>}
      </label>

      <div className="relative">
        <input
          id={name}
          name={name}
          type={showPassword ? "text" : "password"}
          value={value}
          onChange={onChange}
          placeholder={placeholder}
          autoComplete={autoComplete}
          className={classNames(
            "w-full border rounded-md py-2 px-3 pr-10 focus:outline-none focus:ring-2",
            {
              "border-gray-300 focus:ring-blue-500": !error,
              "border-red-500 focus:ring-red-500": !!error,
              "dark:bg-gray-800 dark:text-white dark:border-gray-600": true,
            }
          )}
        />

        <button
          type="button"
          onClick={() => setShowPassword((prev) => !prev)}
          className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-500 hover:text-gray-700 dark:text-gray-300"
          aria-label="Mostrar u ocultar contraseña"
        >
          {showPassword ? <FaEyeSlash /> : <FaEye />}
        </button>
      </div>

      {error && (
        <p className="text-red-500 text-sm mt-1 font-medium">{error}</p>
      )}
    </div>
  );
};

export default PasswordField;

```

## src\components\common\PasswordWithStrengthInputForm.tsx

```tsx
import { useState } from "react";
import { FaEye, FaEyeSlash, FaInfoCircle } from "react-icons/fa";
import {
  getPasswordScore,
  getStrengthLabel,
} from "../../utils/validationHelpersForm";

interface Props {
  value: string;
  onChange: (e: React.ChangeEvent<HTMLInputElement>) => void;
  error?: string;
  showTooltip?: boolean;
  showStrengthBar?: boolean;
  autoFocus?: boolean;
  name?: string;
  placeholder?: string;
}

export default function PasswordWithStrengthInput({
  value,
  onChange,
  error,
  showTooltip = true,
  showStrengthBar = true,
  autoFocus = false,
  name = "password",
  placeholder = "Password",
}: Props) {
  const [showPassword, setShowPassword] = useState(false);
  const score = getPasswordScore(value);
  const label = getStrengthLabel(score);

  return (
    <div className="relative mb-4">
      <div className="absolute flex justify-start mb-1 top-[-14px] left-[4px]">
        {showTooltip && (
          <div className="relative group inline-block">
            <FaInfoCircle
              className="text-blue-500 dark:text-blue-400 cursor-pointer p-0.5"
              tabIndex={0} // para accesibilidad en teclado
            />
            <div className="absolute z-30 top-full right-[-260px] mt-2 w-72 md:w-64 text-xs bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 text-gray-800 dark:text-gray-200 p-2 rounded shadow-md opacity-0 invisible group-hover:opacity-100 group-hover:visible group-focus-within:opacity-100 group-focus-within:visible transition-opacity duration-200 pointer-events-none">
              Usa mínimo 8 caracteres, una mayúscula, un número y un símbolo especial. No uses tu correo ni contraseñas anteriores.
            </div>
          </div>
        )}
      </div>

      <input
        type={showPassword ? "text" : "password"}
        name={name}
        value={value}
        onChange={onChange}
        placeholder={placeholder}
        autoFocus={autoFocus}
        className="input-style pr-10 outline-none dark:bg-gray-900 dark:text-white dark:border-gray-700"
      />

      <button
        type="button"
        onClick={() => setShowPassword(!showPassword)}
        className="absolute right-3 top-[20px] text-gray-600 dark:text-gray-300 hover:text-blue-600 dark:hover:text-blue-400 transition"
        tabIndex={-1}
      >
        {showPassword ? <FaEyeSlash /> : <FaEye />}
      </button>

      {error && <p className="text-red-500 text-sm mt-1">{error}</p>}

      {showStrengthBar && (
        <div className="mt-2">
          <div className="flex gap-1">
            {[...Array(4)].map((_, i) => (
              <div
                key={i}
                className={`h-2 flex-1 rounded ${
                  i < score ? label.bar : "bg-gray-200 dark:bg-gray-600"
                }`}
              />
            ))}
          </div>
          {score > 0 && (
            <p className={`text-sm mt-1 ${label.color}`}>Fuerza: {label.text}</p>
          )}
        </div>
      )}
    </div>
  );
}

```

## src\components\common\Spinner.tsx

```tsx
import React from "react";

interface SpinnerProps {
  size?: number;
  className?: string;
  color?: string;
}

export const Spinner: React.FC<SpinnerProps> = ({
  size = 24,
  className = "",
  color = "var(--color-primary)", // Puedes usar cualquier variable de tu theme
}) => {
  return (
    <svg
      className={`animate-spin ${className}`}
      width={size}
      height={size}
      viewBox="0 0 24 24"
      style={{ color }}
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
    >
      <circle
        className="opacity-25"
        cx="12"
        cy="12"
        r="10"
        stroke="currentColor"
        strokeWidth="4"
      ></circle>
      <path
        className="opacity-75"
        fill="currentColor"
        d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"
      ></path>
    </svg>
  );
};

```

## src\components\common\ToastNotification.tsx

```tsx
import { ToastContainer } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";

const ToastNotification = () => {
  return (
    <ToastContainer
      position="top-right"
      autoClose={5000}
      hideProgressBar={false}
      newestOnTop={false}
      closeOnClick
      rtl={false}
      pauseOnFocusLoss
      draggable
      pauseOnHover
      theme="colored" // Puedes cambiar a "light" o "dark"
      toastClassName={() =>
        "bg-white dark:bg-bgDark text-textDark dark:text-textLight rounded shadow-md px-4 py-3"
      }
      className="text-sm font-medium"
      progressClassName={() => "bg-[var(--color-primary)]"}
    />
  );
};

export default ToastNotification;

```

## src\components\NavMenu.tsx

```tsx
import { Link } from "react-router-dom";
import { AnimatePresence, motion } from "framer-motion";
import {
  ChevronDownIcon,
  PlusIcon,
  MinusIcon,
} from "@heroicons/react/20/solid";
import { useState, useRef, useEffect } from "react";

interface Props {
  isLoggedIn: boolean;
  userRole: string;
  mobileMenuOpen: boolean;
  handleLinkClick: () => void;
}

export const NavMenu: React.FC<Props> = ({
  isLoggedIn,
  userRole,
  mobileMenuOpen,
  handleLinkClick,
}) => {
  const [hoveredMenu, setHoveredMenu] = useState<string | null>(null);
  const menuRef = useRef<HTMLDivElement>(null);

  const menus = [
    { label: "Inicio", to: "/" },
    { label: "Precios", to: "/precios" },
  ];

  const dropdowns = {
    mas: ["Galeria", "Horarios", "Eventos", "Blog", "Reserva"],
    servicios: [
      "Piscinas y Tobogán",
      "Bosque Perdido de los Dinosaurios",
      "Botes y Juegos de Mesa",
      "Zona VIP",
      "Restaurantes",
    ],
  };

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (
        mobileMenuOpen &&
        menuRef.current &&
        !menuRef.current.contains(event.target as Node)
      ) {
        setHoveredMenu(null);
      }
    };

    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, [mobileMenuOpen]);

  return (
    <div
      ref={menuRef}
      className={`flex transition-all duration-300 ${
        mobileMenuOpen
          ? "flex-col items-center space-y-2 mt-4 text-center"
          : "flex-row items-center gap-6"
      } w-full md:w-auto justify-center`}
    >
      {/* Enlaces simples */}
      {menus.map((item, idx) => (
        <Link
          key={idx}
          to={item.to}
          onClick={handleLinkClick}
          className="hover:text-accent1 font-medium transition-colors duration-200"
        >
          {item.label}
        </Link>
      ))}

      {/* Menús desplegables */}
      {(Object.keys(dropdowns) as Array<keyof typeof dropdowns>).map((key) => (
        <div
          key={key}
          className={`relative group ${mobileMenuOpen ? "w-full" : "w-auto"}`}
          onMouseEnter={() => !mobileMenuOpen && setHoveredMenu(key)}
          onMouseLeave={() => !mobileMenuOpen && setHoveredMenu(null)}
        >
          <button
            onClick={() =>
              mobileMenuOpen
                ? setHoveredMenu((prev) => (prev === key ? null : key))
                : null
            }
            className="flex items-center justify-between gap-1 w-full font-medium capitalize hover:text-accent1 transition duration-200"
          >
            {key}
            {mobileMenuOpen ? (
              hoveredMenu === key ? (
                <MinusIcon className="h-5 w-5 transition-all duration-300 text-accent1" />
              ) : (
                <PlusIcon className="h-5 w-5 transition-all duration-300" />
              )
            ) : (
              <motion.div
                animate={{
                  rotate: hoveredMenu === key ? 180 : 0,
                }}
                style={{
                  color:
                    hoveredMenu === key
                      ? "var(--color-accent1)"
                      : "var(--color-textLight)",
                }}
                transition={{ duration: 0.3 }}
              >
                <ChevronDownIcon className="h-5 w-5 text-current transition-all duration-300" />
              </motion.div>
            )}
          </button>

          <AnimatePresence initial={false}>
            {hoveredMenu === key && (
              <motion.div
                key={key}
                initial={{ height: 0, opacity: 0 }}
                animate={{ height: "auto", opacity: 1 }}
                exit={{ height: 0, opacity: 0 }}
                transition={{ duration: 0.3, ease: "easeInOut" }}
                className={`overflow-hidden ${
                  mobileMenuOpen
                    ? "w-full mt-1"
                    : "absolute left-1/2 -translate-x-1/2 top-full mt-2 w-56"
                } backdrop-blur-md bg-bgLight/30 dark:bg-bgDark/40 text-textDark dark:text-textLight rounded-xl shadow-xl ring-1 ring-bgLight/25 z-50`}
              >
                {dropdowns[key].map((label, idx) => (
                  <Link
                    key={idx}
                    to={`/${key}#${label.toLowerCase().replace(/\s+/g, "-")}`}
                    onClick={handleLinkClick}
                    className="block px-4 py-2 text-sm font-semibold hover:bg-accent2/80 hover:text-textLight/90 dark:hover:bg-bgLight/80 dark:hover:text-textDark/90 transition-all duration-200"
                  >
                    {label}
                  </Link>
                ))}
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      ))}

      {/* Links para cliente logueado */}
      {isLoggedIn && userRole === "client" && (
        <>
          <Link
            to="/compras"
            onClick={handleLinkClick}
            className="hover:text-accent1 transition font-medium"
          >
            Mis Compras
          </Link>
          <Link
            to="/perfil"
            onClick={handleLinkClick}
            className="hover:text-accent1 transition font-medium"
          >
            Mi Perfil
          </Link>
        </>
      )}
    </div>
  );
};

```

## src\components\RouteModalHandler.tsx

```tsx
// src/components/RouteModalHandler.tsx
import { useEffect } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { useAuthModal } from "../store/useAuthModal";

const RouteModalHandler = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const { openModal, isOpen } = useAuthModal();

  // Abre el modal cuando entra a /login o /register
  useEffect(() => {
    if (location.pathname === "/login") {
      openModal("login");
    } else if (location.pathname === "/register") {
      openModal("register");
    }
  }, [location.pathname, openModal]);

  // Si se cierra el modal estando en /login o /register, redirige al home
  useEffect(() => {
    if (
      !isOpen &&
      (location.pathname === "/login" || location.pathname === "/register")
    ) {
      navigate("/");
    }
  }, [isOpen, location.pathname, navigate]);

  return null;
};

export default RouteModalHandler;

```

## src\components\ThemeToggle.tsx

```tsx
import { useTheme } from '../hooks/useTheme';
import { FaSun, FaMoon } from 'react-icons/fa';

export const ThemeToggle = () => {
  const { darkMode, toggleDarkMode } = useTheme();

  return (
    <button
      onClick={toggleDarkMode}
      className="p-2 rounded-lg bg-gray-200 dark:bg-gray-700 transition-colors"
      aria-label={darkMode ? 'Activar modo claro' : 'Activar modo oscuro'}
    >
      {darkMode ? <FaSun className="text-yellow-400" /> : <FaMoon className="text-gray-700" />}
    </button>
  );
};

```

## src\context\AuthContext.tsx

```tsx
// AuthContext.tsx
import { createContext } from 'react';
export const AuthContext = createContext(null);
```

## src\context\ThemeContext.tsx

```tsx
import { createContext } from 'react';

// Definir tipos
export interface ThemeContextType {
  darkMode: boolean;
  toggleDarkMode: () => void;
}

// Crear y exportar el contexto
export const ThemeContext = createContext<ThemeContextType>({
  darkMode: false,
  toggleDarkMode: () => {},
});

```

## src\context\ThemeProvider.tsx

```tsx
import { useState, useEffect, ReactNode } from 'react';
import { ThemeContext } from './ThemeContext';

interface ThemeProviderProps {
  children: ReactNode;
}

export function ThemeProvider({ children }: ThemeProviderProps) {
  const [darkMode, setDarkMode] = useState<boolean>(() => {
    const savedTheme = localStorage.getItem('theme');
    return savedTheme === 'dark';
  });

  useEffect(() => {
    document.documentElement.classList.toggle('dark', darkMode);
    localStorage.setItem('theme', darkMode ? 'dark' : 'light');
  }, [darkMode]);

  const toggleDarkMode = () => {
    setDarkMode(prev => !prev);
  };

  return (
    <ThemeContext.Provider value={{ darkMode, toggleDarkMode }}>
      {children}
    </ThemeContext.Provider>
  );
}

```

## src\hooks\useAuth.ts

```typescript
import { useEffect, useState } from "react";

export const useAuth = () => {
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [userRole, setUserRole] = useState<"admin" | "client">("client");

  useEffect(() => {
    const token = localStorage.getItem("token");
    setIsLoggedIn(!!token);

    // Puedes agregar lógica real aquí con JWT decode, etc.
    if (token) {
      const payload = JSON.parse(atob(token.split(".")[1]));
      setUserRole(payload.role || "client");
    }
  }, []);

  const logout = () => {
    localStorage.removeItem("token");
    window.location.href = "/login";
  };

  return { isLoggedIn, userRole, logout };
};

```

## src\hooks\useTheme.ts

```typescript
import { useContext } from 'react';
import { ThemeContext } from '../context/ThemeContext';

export const useTheme = () => {
  return useContext(ThemeContext);
};
```

## src\index.css

```css
@import "tailwindcss";

@layer theme, base, components, utilities;

/* Ignorar alertas de error, ya que es una versión reciente de TailwindCSS */
@custom-variant dark (&:where(.dark, .dark *));

@theme {
    --color-primary: #00b1e8;
    --color-secondary: #f26c1d;
    --color-hoverSecondary:#fc843d;
    --color-accent1: #ffda00;
    --color-accent2: #4c2882;
    --color-textDark: #333333;
    --color-textLight: #f5f5f5;
    --color-bgLight: #f5f5f5;
    --color-bgDark: #333333;
    --color-facebook: #1877f2;
    --color-instagram: #e1306c;
    --color-whatsapp: #25d366;
    --color-tiktok: #f5f5f5;
    --color-youtube: #ff0000;
}

.input-style {
    @apply mt-1 w-full px-4 py-2 border-2 border-gray-200 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent transition-all duration-300;
}
  
```

## src\layout\Container.tsx

```tsx
const Container = ({ children }: { children: React.ReactNode }) => {
    return <div className="max-w-7xl mx-auto px-4">{children}</div>;
  };
  
  export default Container;
  
```

## src\layout\DashboardLayout.tsx

```tsx
import Sidebar from "../layout/navigation/Sidebar";
import HeaderMobile from "../layout/navigation/HeaderMobile";
import { ReactNode, useState } from "react";
interface Props {
  children: ReactNode;
}

const DashboardLayout = ({ children }: Props) => {
  const [isSidebarOpen, setSidebarOpen] = useState(true);

  return (
    <div className="flex h-screen bg-bgLight dark:bg-bgDark transition-colors">
      <Sidebar isOpen={isSidebarOpen} />
      <div className="flex flex-col flex-1">
        <HeaderMobile onToggleSidebar={() => setSidebarOpen(!isSidebarOpen)} />
        <main className="flex-1 overflow-y-auto p-4">{children}</main>
      </div>
    </div>
  );
};

export default DashboardLayout;
```

## src\layout\navigation\Footer.tsx

```tsx
import {
    FaMapMarkerAlt,
    FaClock,
    FaFacebook,
    FaInstagram,
    FaWhatsapp,
    FaTiktok,
    FaYoutube,
  } from "react-icons/fa";
  import { Link } from "react-router-dom";
  
  const Footer = () => {
    return (
      <footer className="bg-accent2 text-white py-16 mt-8">
        <div className="container mx-auto px-4 grid grid-cols-1 md:grid-cols-4 gap-8 text-center md:text-left transition-all duration-300">
          {/* Logo + Descripción */}
          <div className="flex flex-col items-center md:items-start">
            <Link to="/" className="flex items-center gap-2">
              <img
                src="../../../public/ARP logo.png"
                alt="Logo de Aqua River Park"
                className="h-20 mb-4 drop-shadow-xl"
              />
            </Link>
            <p className="text-sm opacity-90 max-w-xs">
              Un parque acuático temático con diversión para toda la familia.
            </p>
          </div>
  
          {/* Enlaces rápidos */}
          <div>
            <h3 className="text-xl font-bold mb-4 text-accent1">Enlaces Rápidos</h3>
            <ul className="space-y-2">
              {[
                { href: "#inicio", text: "Inicio" },
                { href: "#atracciones", text: "Atracciones" },
                { href: "#horarios", text: "Horarios" },
                { href: "#promociones", text: "Promociones" },
              ].map((item, index) => (
                <li key={index}>
                  <a
                    href={item.href}
                    className="hover:text-primary transition-colors"
                  >
                    {item.text}
                  </a>
                </li>
              ))}
            </ul>
          </div>
  
          {/* Información de contacto */}
          <div>
            <h3 className="text-xl font-bold mb-4 text-accent1">Contacto</h3>
            <ul className="space-y-2 text-sm">
              <li className="flex items-center justify-center md:justify-start">
                <FaMapMarkerAlt className="mr-2 text-secondary" />
                Calle Principal 123, Ciudad
              </li>
              <li className="flex items-center justify-center md:justify-start">
                <FaClock className="mr-2 text-secondary" />
                9:00 AM - 5:00 PM
              </li>
            </ul>
          </div>
  
          {/* Redes Sociales */}
          <div>
            <h3 className="text-xl font-bold mb-4 text-accent1">Redes Sociales</h3>
            <div className="flex justify-center md:justify-start space-x-4">
              {[
                { icon: FaFacebook, color: "facebook", title: "Facebook" },
                { icon: FaInstagram, color: "instagram", title: "Instagram" },
                { icon: FaWhatsapp, color: "whatsapp", title: "Whatsapp" },
                { icon: FaTiktok, color: "tiktok", title: "TikTok" },
                { icon: FaYoutube, color: "youtube", title: "YouTube" },
              ].map(({ icon: Icon, color, title }, index) => (
                <a
                  key={index}
                  href="#"
                  className="transition-all transform hover:scale-110"
                  title={title}
                  style={{
                    color: `var(--color-${color})`,
                    textShadow: `0 0 6px var(--color-${color})`,
                  }}
                >
                  <Icon size={24} />
                </a>
              ))}
            </div>
          </div>
        </div>
  
        {/* Pie de página */}
        <div className="mt-10 text-center text-xs text-white/70">
          © {new Date().getFullYear()} Aqua River Park. Todos los derechos reservados.
        </div>
      </footer>
    );
  };
  
  export default Footer;
  
```

## src\layout\navigation\Header.tsx

```tsx
import { Link, useLocation, useNavigate } from "react-router-dom";
import { FaUserCircle, FaBars, FaTimes } from "react-icons/fa";
import { Menu, MenuButton, MenuItem } from "@headlessui/react";
import { AnimatePresence, motion } from "framer-motion";
import { ThemeToggle } from "../../components/ThemeToggle";
import { useAuth } from "../../hooks/useAuth";
import { useEffect, useState, useRef } from "react";
import { NavMenu } from "../../components/NavMenu";
import { useAuthModal } from "../../store/useAuthModal"; // <-- store Zustand

const Header: React.FC = () => {
  const { isLoggedIn, logout, userRole } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);
  const { openModal } = useAuthModal(); // <-- usar Zustand

  const dropdownItems = {
    client: [
      { label: "Perfil", path: "/perfil" },
      { label: "Ajustes", path: "/ajustes" },
      { label: "Compras", path: "/compras" },
    ],
    admin: [
      { label: "Dashboard", path: "/admin" },
      { label: "Perfil", path: "/perfil" },
      { label: "Ajustes", path: "/ajustes" },
    ],
  };

  useEffect(() => {
    setMobileMenuOpen(false);
  }, [location]);

  useEffect(() => {
    if (isLoggedIn && userRole === "admin") {
      navigate("/admin");
    }
  }, [isLoggedIn, userRole, navigate]);

  const handleLinkClick = () => setMobileMenuOpen(false);

  return (
    <header className="bg-primary dark:bg-bgDark text-white shadow-md sticky top-0 z-50 transition-colors duration-300 ease-in-out">
      <div className="max-w-[1400px] mx-auto px-4 md:px-8">
        <div className="flex items-center justify-between h-16 md:h-20">
          {/* Logo y Toggle */}
          <div className="flex items-center gap-3">
            <button
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              className="md:hidden text-2xl transition-transform hover:scale-110"
              aria-label="Abrir menú"
            >
              {mobileMenuOpen ? <FaTimes /> : <FaBars />}
            </button>

            <Link
              to="/"
              className="flex items-center gap-2 transition-transform hover:scale-105"
            >
              <img
                src="/ARP logo.png"
                alt="Logo"
                className="h-10 w-auto drop-shadow"
              />
              <span className="font-bold text-lg">Aqua River Park</span>
            </Link>
          </div>

          {/* Menú de navegación (desktop) */}
          <nav className="hidden md:flex items-center gap-6 justify-center">
            <NavMenu
              isLoggedIn={isLoggedIn}
              userRole={userRole}
              mobileMenuOpen={false}
              handleLinkClick={handleLinkClick}
            />
          </nav>

          {/* Iconos a la derecha */}
          <div className="flex items-center gap-4">
            <ThemeToggle />
            {isLoggedIn ? (
              <Menu as="div" className="relative">
                <MenuButton className="flex items-center transition-transform hover:scale-110">
                  <FaUserCircle className="text-3xl" />
                </MenuButton>
                <AnimatePresence>
                  <motion.div
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: 10 }}
                    transition={{ duration: 0.2 }}
                    className="absolute right-0 mt-2 w-48 bg-white dark:bg-bgDark rounded-md shadow-lg z-50 ring-1 ring-black/10 divide-y divide-gray-200 dark:divide-gray-700"
                  >
                    <div className="py-1">
                      {(dropdownItems[userRole] || []).map((item, idx) => (
                        <MenuItem key={idx}>
                          {({ active }) => (
                            <Link
                              to={item.path}
                              className={`block px-4 py-2 text-sm transition-all duration-200 ${
                                active
                                  ? "bg-gray-100 dark:bg-gray-700 text-primary"
                                  : "text-gray-700 dark:text-white"
                              }`}
                            >
                              {item.label}
                            </Link>
                          )}
                        </MenuItem>
                      ))}
                    </div>
                    <div className="py-1">
                      <MenuItem>
                        {({ active }) => (
                          <button
                            onClick={logout}
                            className={`block w-full text-left px-4 py-2 text-sm transition-all duration-200 ${
                              active
                                ? "bg-red-100 dark:bg-red-600 text-red-700"
                                : "text-red-500"
                            }`}
                          >
                            Cerrar sesión
                          </button>
                        )}
                      </MenuItem>
                    </div>
                  </motion.div>
                </AnimatePresence>
              </Menu>
            ) : (
              <>
                {/* Mobile icon */}
                <button
                  onClick={() => openModal("login")}
                  aria-label="Iniciar sesión"
                  className="md:hidden text-2xl hover:text-accent1 transition-transform"
                >
                  <FaUserCircle />
                </button>

                {/* Desktop button */}
                <button
                  onClick={() => openModal("login")}
                  className="hidden md:inline-block bg-secondary hover:bg-hoverSecondary px-4 py-2 rounded-md text-white transition-colors duration-300 text-sm"
                >
                  Iniciar sesión
                </button>
              </>
            )}
          </div>
        </div>
      </div>

      {/* Menú móvil deslizable */}
      <AnimatePresence>
        {mobileMenuOpen && (
          <motion.div
            ref={menuRef}
            initial={{ y: -20, opacity: 0 }}
            animate={{ y: 0, opacity: 1 }}
            exit={{ y: -20, opacity: 0 }}
            transition={{ duration: 0.3 }}
            className="md:hidden px-6 py-4 bg-primary dark:bg-bgDark space-y-3 shadow-md"
          >
            <NavMenu
              isLoggedIn={isLoggedIn}
              userRole={userRole}
              mobileMenuOpen={true}
              handleLinkClick={handleLinkClick}
            />
          </motion.div>
        )}
      </AnimatePresence>
    </header>
  );
};

export default Header;

```

## src\layout\navigation\HeaderMobile.tsx

```tsx
import { useEffect } from "react";
import { Link, useLocation } from "react-router-dom";
import { FaBars, FaSun, FaMoon, FaUserCircle } from "react-icons/fa";
import { Menu, MenuButton, MenuItem } from "@headlessui/react";
import { motion, AnimatePresence } from "framer-motion";
import { useAuth } from "../../hooks/useAuth";
import { useTheme } from "../../hooks/useTheme";

interface HeaderMobileProps {
  onToggleSidebar?: () => void;
}

const HeaderMobile: React.FC<HeaderMobileProps> = ({ onToggleSidebar }) => {
  const { darkMode, toggleDarkMode } = useTheme();
  const { isLoggedIn, logout, userRole } = useAuth();
  const location = useLocation();

  const dropdownItems: Record<string, { label: string; path: string }[]> = {
    client: [
      { label: "Perfil", path: "/perfil" },
      { label: "Ajustes", path: "/ajustes" },
    ],
    admin: [
      { label: "Dashboard", path: "/admin" },
      { label: "Perfil", path: "/perfil" },
    ],
  };

  useEffect(() => {
    // Podrías cerrar modales o limpiar algún estado aquí si lo deseas
  }, [location]);

  return (
    <header className="bg-primary dark:bg-bgDark text-white px-4 py-3 flex items-center justify-between shadow-md sticky top-0 z-50">
      {/* Sidebar toggle + Logo */}
      <div className="flex items-center gap-3">
        {onToggleSidebar && (
          <button onClick={onToggleSidebar} className="text-white text-xl">
            <FaBars />
          </button>
        )}
        <Link to="/" className="flex items-center gap-2">
          <img src="/ARP logo.png" alt="Logo" className="h-8" />
          <span className="font-semibold text-base">Aqua River Park</span>
        </Link>
      </div>

      {/* Dark mode + Auth */}
      <div className="flex items-center gap-4">
        <button
          onClick={toggleDarkMode}
          className="p-2 rounded-full bg-white/20 hover:bg-white/30 transition"
          title={darkMode ? "Modo claro" : "Modo oscuro"}
        >
          {darkMode ? <FaSun /> : <FaMoon />}
        </button>

        {isLoggedIn ? (
          <Menu as="div" className="relative">
            <MenuButton className="flex items-center">
              <FaUserCircle className="text-2xl" />
            </MenuButton>
            <AnimatePresence>
              <motion.div
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: 10 }}
                transition={{ duration: 0.2 }}
                className="absolute right-0 mt-2 w-44 bg-white dark:bg-bgDark rounded-md shadow-lg z-50 ring-1 ring-black/10"
              >
                <div className="py-1">
                  {(dropdownItems[userRole] || []).map(
                    (item, idx: number) => (
                      <MenuItem key={idx}>
                        {({ active }: { active: boolean }) => (
                          <Link
                            to={item.path}
                            className={`block px-4 py-2 text-sm ${
                              active
                                ? "bg-gray-100 dark:bg-gray-700 text-primary"
                                : "text-gray-800 dark:text-white"
                            }`}
                          >
                            {item.label}
                          </Link>
                        )}
                      </MenuItem>
                    )
                  )}
                </div>
                <div className="py-1">
                  <MenuItem>
                    {({ active }: { active: boolean }) => (
                      <button
                        onClick={logout}
                        className={`block w-full text-left px-4 py-2 text-sm ${
                          active
                            ? "bg-red-100 dark:bg-red-600 text-red-700"
                            : "text-red-500"
                        }`}
                      >
                        Cerrar sesión
                      </button>
                    )}
                  </MenuItem>
                </div>
              </motion.div>
            </AnimatePresence>
          </Menu>
        ) : (
          <Link
            to="/login"
            className="bg-secondary hover:bg-hoverSecondary px-3 py-1.5 rounded-md text-white text-sm transition"
          >
            Acceder
          </Link>
        )}
      </div>
    </header>
  );
};

export default HeaderMobile;

```

## src\layout\navigation\MiniFooter.tsx

```tsx
// src/components/navigation/MiniFooter.tsx

const MiniFooter = () => {
    return (
      <footer className="bg-accent2 text-white text-xs py-3 px-4 text-center shadow-md">
        <span className="block md:inline">
          © {new Date().getFullYear()} Aqua River Park
        </span>
        <span className="hidden md:inline mx-2">|</span>
        <span className="block md:inline text-white/80">
          Todos los derechos reservados
        </span>
      </footer>
    );
  };
  
  export default MiniFooter;
  
```

## src\layout\navigation\Sidebar.tsx

```tsx
// src/layout/navigation/Sidebar.tsx
import { Link, useLocation } from "react-router-dom";
import { FaHome, FaUser, FaCog } from "react-icons/fa";
import classNames from "classnames";

interface SidebarProps {
  isOpen: boolean;
}

const menuItems = [
  { label: "Inicio", path: "/", icon: <FaHome /> },
  { label: "Perfil", path: "/perfil", icon: <FaUser /> },
  { label: "Configuración", path: "/ajustes", icon: <FaCog /> },
];

const Sidebar = ({ isOpen }: SidebarProps) => {
  const location = useLocation();

  return (
    <aside
      className={classNames(
        "h-screen bg-accent2 text-white transition-all duration-300 flex flex-col",
        isOpen ? "w-64" : "w-16"
      )}
    >
      {/* Header */}
      <div className="flex items-center justify-center md:justify-between px-4 py-4 border-b border-white/10">
        {isOpen && <h1 className="text-lg font-bold">Aqua River</h1>}
      </div>

      {/* Menu */}
      <nav className="flex-1 overflow-y-auto mt-4 space-y-2">
        {menuItems.map((item, index) => (
          <Link
            to={item.path}
            key={index}
            className={classNames(
              "flex items-center gap-3 px-4 py-2 rounded-md mx-2 transition-colors",
              location.pathname === item.path
                ? "bg-accent1 text-textDark font-semibold"
                : "hover:bg-white/10"
            )}
          >
            <span className="text-lg">{item.icon}</span>
            {isOpen && <span className="text-sm">{item.label}</span>}
          </Link>
        ))}
      </nav>

      {/* Footer */}
      {isOpen && (
        <div className="px-4 py-4 text-xs text-gray-300 border-t border-white/10">
          © {new Date().getFullYear()} Aqua River Park
        </div>
      )}
    </aside>
  );
};

export default Sidebar;

```

## src\layout\PublicLayout.tsx

```tsx
import Header from "../layout/navigation/Header";
import Footer from "../layout/navigation/Footer";
// import { ReactNode } from "react";

// interface Props {
//   children: ReactNode;
// }

const PublicLayout = ({ children }: { children: React.ReactNode }) => {
  return (
    <div className="flex flex-col min-h-screen bg-bgLight dark:bg-bgDark transition-colors">
      <Header />
      <main className="flex-grow">{children}</main>
      <Footer />
    </div>
  );
};

export default PublicLayout;

```

## src\main.tsx

```tsx
// frontend/src/main.tsx
import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import "./index.css";
import { ThemeProvider } from "./context/ThemeProvider";

ReactDOM.createRoot(document.getElementById("root")!).render(
<ThemeProvider>
  <React.StrictMode>
    <App />
  </React.StrictMode>
    </ThemeProvider>
);

```

## src\pages\ConfirmAccount.tsx

```tsx

```

## src\pages\ConfirmationMail.tsx

```tsx
import { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import api from "../api/axios";
import { AxiosError } from "axios";
import { FaCheckCircle, FaTimesCircle, FaInfoCircle } from "react-icons/fa";
import { useAuthModal } from "../store/useAuthModal";
import { toast } from "react-toastify";

const ConfirmationMail = () => {
  const { token } = useParams();
  const navigate = useNavigate();
  const { openModal } = useAuthModal();

  const queryParams = new URLSearchParams(window.location.search);
  const emailFromQuery = queryParams.get("email");

  const [message, setMessage] = useState("Confirmando...");
  const [type, setType] = useState<"success" | "info" | "error">("info");
  const [showModal, setShowModal] = useState(false);
  const [email, setEmail] = useState(emailFromQuery || "");
  const [resendMsg, setResendMsg] = useState("");
  const [resendSuccess, setResendSuccess] = useState(false);
  const [isSending, setIsSending] = useState(false); // ✅ Bloqueo de clics

  useEffect(() => {
    const confirmAccount = async () => {
      try {
        const res = await api.get(`/confirm/${token}?email=${emailFromQuery}`);
        const { message } = res.data;

        setMessage(message);
        setType("success");

        if (
          message === "Cuenta confirmada exitosamente." ||
          message === "La cuenta ya ha sido confirmada."
        ) {
          toast.success(message);
          setTimeout(() => {
            navigate("/");
            openModal("login");
          }, 2500);
        }
      } catch (err) {
        const error = err as AxiosError<{ message: string }>;
        const msg = error.response?.data?.message;

        if (msg === "Token inválido o expirado") {
          setMessage("El enlace ya fue utilizado o ha expirado.");
          setType("info");
          setShowModal(true);
        } else {
          setMessage("Ocurrió un error al confirmar tu cuenta.");
          setType("error");
        }
      }
    };

    confirmAccount();
  }, [token, emailFromQuery, navigate, openModal]);

  const handleResend = async (e: React.FormEvent) => {
    e.preventDefault();
    if (isSending) return;

    setIsSending(true);
    setResendMsg("");

    try {
      const res = await api.post("/resend-confirmation", { email });
      toast.success("¡Correo reenviado correctamente!");
      setResendMsg(res.data.message);
      setResendSuccess(true);

      setTimeout(() => {
        setShowModal(false);
        setResendMsg("");
        setEmail("");
        setResendSuccess(false);
        navigate("/");
        openModal("login");
      }, 3000);
    } catch (err) {
      const error = err as AxiosError<{ message: string }>;
      const msg =
        error.response?.data?.message || "Error al reenviar el correo";
      setResendMsg(msg);
      toast.error(msg);
    } finally {
      setIsSending(false);
    }
  };

  const renderIcon = () => {
    if (type === "success")
      return <FaCheckCircle className="text-green-500 text-4xl mb-4 mx-auto" />;
    if (type === "error")
      return <FaTimesCircle className="text-red-500 text-4xl mb-4 mx-auto" />;
    return <FaInfoCircle className="text-yellow-500 text-4xl mb-4 mx-auto" />;
  };

  return (
    <>
      <div className="min-h-screen flex items-center justify-center bg-gray-100 px-4">
        <div className="bg-white shadow-md rounded-lg p-6 w-full max-w-md text-center">
          {renderIcon()}
          <h1 className="text-2xl font-bold mb-2">Confirmación de Cuenta</h1>
          <p
            className={`text-base ${
              type === "success"
                ? "text-green-600"
                : type === "error"
                ? "text-red-500"
                : "text-yellow-600"
            }`}
          >
            {message}
          </p>
        </div>
      </div>

      {showModal && (
        <div className="fixed inset-0 bg-black/70 bg-opacity-40 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg shadow-lg p-8 w-full max-w-md relative">
            {!resendSuccess && (
              <button
                onClick={() => setShowModal(false)}
                className="absolute top-2 right-3 text-gray-500 hover:text-red-500 text-lg font-bold"
              >
                &times;
              </button>
            )}
            <h2 className="text-xl font-bold text-center mb-4 text-sky-600">
              ¿Necesitas un nuevo enlace?
            </h2>
            {!resendSuccess ? (
              <>
                <p className="text-sm text-gray-600 text-center mb-4">
                  Ingresa tu correo para recibir un nuevo enlace de
                  confirmación:
                </p>
                <form onSubmit={handleResend} className="space-y-4">
                  <input
                    type="email"
                    placeholder="Tu correo"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    className="w-full px-4 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-sky-500"
                    required
                  />
                  <button
                    type="submit"
                    disabled={isSending}
                    className={`w-full bg-sky-600 text-white py-2 rounded-md hover:bg-sky-700 transition ${
                      isSending ? "opacity-50 cursor-not-allowed" : ""
                    }`}
                  >
                    {isSending ? "Enviando..." : "Reenviar enlace"}
                  </button>
                  {resendMsg && (
                    <p className="text-sm text-center text-red-500 mt-2">
                      {resendMsg}
                    </p>
                  )}
                </form>
              </>
            ) : (
              <div className="text-center">
                <FaCheckCircle className="text-green-500 text-4xl mx-auto mb-2" />
                <p className="text-green-600 text-sm font-medium">
                  {resendMsg}
                </p>
                <p className="text-sm text-gray-500 mt-2">
                  Redirigiendo al inicio de sesión...
                </p>
              </div>
            )}
          </div>
        </div>
      )}
    </>
  );
};

export default ConfirmationMail;

```

## src\pages\Dashboard.tsx

```tsx
import { useEffect, useState } from "react";
import api from "../api/axios";
import { useNavigate } from "react-router-dom";

const Dashboard = () => {
  const [user, setUser] = useState<{ name: string; role: string } | null>(null);
  const [error, setError] = useState("");
  const navigate = useNavigate();

  useEffect(() => {
    const fetchData = async () => {
      try {
        const token = localStorage.getItem("token");
        if (!token) {
          navigate("/login");
          return;
        }

        const res = await api.get("/dashboard", {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        });

        setUser({ name: res.data.message.split(" ")[1], role: res.data.role });
      } catch (err: unknown) {
        if (err instanceof Error && (err as { response?: { status: number } }).response?.status === 403) {
          setError("No tienes permisos para acceder al dashboard.");
        } else {
          setError("Acceso no autorizado. Redirigiendo...");
          setTimeout(() => navigate("/login"), 2000);
        }
      }
    };

    fetchData();
  }, [navigate]);

  const handleLogout = () => {
    localStorage.removeItem("token");
    navigate("/login");
  };

  return (
    <div className="max-w-lg mx-auto mt-20">
      <h1 className="text-3xl font-bold mb-4">Dashboard</h1>
      {error && <p className="text-red-500">{error}</p>}
      {user && (
        <>
          <p className="text-lg mb-4">
            Bienvenido <strong>{user.name}</strong>. Tu rol es:{" "}
            <strong>{user.role}</strong>
          </p>
          <button
            onClick={handleLogout}
            className="bg-red-500 text-white px-4 py-2 rounded"
          >
            Cerrar sesión
          </button>
        </>
      )}
    </div>
  );
};

export default Dashboard;

```

## src\pages\Home.tsx

```tsx
// src/pages/Home.tsx
const Home = () => {
    return (
      <div className="text-center">
        <h1 className="text-3xl font-bold text-primary mt-8">Bienvenido a Aqua River Park</h1>
        <p className="mt-4 text-gray-700 dark:text-gray-300">Tu aventura acuática comienza aquí.</p>
      </div>
    );
  };
  
  export default Home;
  
```

## src\pages\Login.tsx

```tsx
// import { useEffect, useState } from "react";
// import api from "../api/axios";
// import { useNavigate } from "react-router-dom";
// import { FaEye, FaEyeSlash, FaCheckCircle, FaInfoCircle } from "react-icons/fa";
// import { toast } from "react-toastify";
// import { AxiosError } from "axios";

// const Login = () => {
//   const [email, setEmail] = useState("");
//   const [password, setPassword] = useState("");
//   const [error, setError] = useState("");
//   const [showPassword, setShowPassword] = useState(false);
//   const [showModal, setShowModal] = useState(false);
//   const [modalStep, setModalStep] = useState<"notice" | "form" | "success">(
//     "notice"
//   );
//   const [resendMsg, setResendMsg] = useState("");
//   const navigate = useNavigate();

//   useEffect(() => {
//     const confirmed = sessionStorage.getItem("confirmationSuccess");
//     if (confirmed) {
//       toast.success(
//         "¡Cuenta confirmada con éxito! Ahora puedes iniciar sesión."
//       );
//       sessionStorage.removeItem("confirmationSuccess");
//     }
//   }, []);

//   useEffect(() => {
//     const successMsg = sessionStorage.getItem("toastSuccess");
//     if (successMsg) {
//       toast.success(successMsg);
//       sessionStorage.removeItem("toastSuccess");
//     }
//   }, []);

//   const handleSubmit = async (e: React.FormEvent) => {
//     e.preventDefault();
//     setError("");

//     try {
//       const res = await api.post("/login", { email, password });
//       localStorage.setItem("token", res.data.token);
//       navigate("/dashboard");
//     } catch (err) {
//       const error = err as AxiosError<{
//         message: string;
//         tokenExpired?: boolean;
//       }>;
//       const msg = error.response?.data?.message;

//       if (msg === "Debes confirmar tu cuenta") {
//         const expired = error.response?.data?.tokenExpired;
//         setModalStep(expired ? "form" : "notice");
//         setShowModal(true);
//       } else {
//         setError("Credenciales incorrectas");
//       }
//     }
//   };

//   const handleResend = async (e: React.FormEvent) => {
//     e.preventDefault();
//     setResendMsg("");

//     try {
//       const res = await api.post("/resend-confirmation", { email });
//       setResendMsg(res.data.message);
//       setModalStep("success");

//       setTimeout(() => {
//         toast.success("¡Correo reenviado!, Revisa tu bandeja...");
//         setShowModal(false);
//         setResendMsg("");
//         setEmail("");
//         setPassword("");
//       }, 5000);
//     } catch (err) {
//       const error = err as AxiosError<{ message: string }>;
//       const msg = error.response?.data?.message;

//       if (msg === "La cuenta ya está confirmada") {
//         toast.info("La cuenta ya ha sido confirmada.");
//         setShowModal(false);
//       } else {
//         setResendMsg("Error al reenviar el enlace.");
//       }
//     }
//   };

//   return (
//     <>
//       <div className="max-w-sm mx-auto mt-8">
//         <h1 className="text-2xl font-bold mb-4">Iniciar sesión</h1>
//         <form onSubmit={handleSubmit} className="space-y-4">
//           <input
//             type="email"
//             placeholder="Correo"
//             className="w-full border p-2"
//             value={email}
//             onChange={(e) => setEmail(e.target.value)}
//             required
//           />
//           <div className="relative">
//             <input
//               type={showPassword ? "text" : "password"}
//               placeholder="Contraseña"
//               className="w-full border p-2 pr-10"
//               value={password}
//               onChange={(e) => setPassword(e.target.value)}
//               required
//             />
//             <button
//               type="button"
//               onClick={() => setShowPassword(!showPassword)}
//               className="absolute top-1/2 right-3 transform -translate-y-1/2 text-gray-500"
//             >
//               {showPassword ? <FaEyeSlash /> : <FaEye />}
//             </button>
//           </div>
//           <button
//             type="submit"
//             className="w-full bg-blue-500 text-white p-2 rounded"
//           >
//             Entrar
//           </button>
//           {error && <p className="text-red-500 text-sm">{error}</p>}
//           <p className="text-sm mt-2">
//             ¿No tienes una cuenta?{" "}
//             <a href="/register" className="text-blue-500 underline">
//               Regístrate aquí
//             </a>
//           </p>
//         </form>
//       </div>

//       {showModal && (
//         <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50">
//           <div className="bg-white rounded-lg shadow-lg p-6 w-full max-w-md relative text-center">
//             <button
//               onClick={() => setShowModal(false)}
//               className="absolute top-2 right-3 text-gray-500 hover:text-red-500 text-lg font-bold"
//             >
//               &times;
//             </button>

//             {modalStep === "notice" && (
//               <>
//                 <FaInfoCircle className="text-yellow-500 text-4xl mx-auto mb-2" />
//                 <h2 className="text-xl font-bold mb-2 text-sky-600">
//                   Verifica tu cuenta
//                 </h2>
//                 <p className="text-sm text-gray-600 mb-4">
//                   Aún no has confirmado tu cuenta. Revisa tu correo para
//                   activarla.
//                 </p>
//               </>
//             )}

//             {modalStep === "form" && (
//               <>
//                 <h2 className="text-xl font-bold mb-2 text-sky-600">
//                   Reenviar Enlace
//                 </h2>
//                 <form onSubmit={handleResend} className="space-y-4">
//                   <input
//                     type="email"
//                     placeholder="Tu correo"
//                     className="w-full px-4 py-2 border rounded-md"
//                     value={email}
//                     onChange={(e) => setEmail(e.target.value)}
//                     required
//                   />
//                   <button
//                     type="submit"
//                     className="w-full bg-sky-600 text-white py-2 rounded-md hover:bg-sky-700"
//                   >
//                     Reenviar
//                   </button>
//                   {resendMsg && (
//                     <p className="text-sm text-red-500">{resendMsg}</p>
//                   )}
//                 </form>
//               </>
//             )}

//             {modalStep === "success" && (
//               <>
//                 <FaCheckCircle className="text-green-500 text-4xl mx-auto mb-2" />
//                 <p className="text-green-600 text-sm font-medium">
//                   {resendMsg}
//                 </p>
//                 <p className="text-sm text-gray-500 mt-2">
//                   Serás redirigido al login...
//                 </p>
//               </>
//             )}
//           </div>
//         </div>
//       )}
//     </>
//   );
// };

// export default Login;

```

## src\pages\NotFound.tsx

```tsx
import { Link } from "react-router-dom";
import { motion } from "framer-motion";
import { useCallback, useEffect, useState } from "react";
import Particles from "react-tsparticles";
import { loadSlim } from "tsparticles-slim"; // ✅ MÁS LIVIANO Y FUNCIONAL
import type { Engine } from "tsparticles-engine";

const NotFound = () => {
  const [isDark, setIsDark] = useState(false);

  useEffect(() => {
    const match = window.matchMedia("(prefers-color-scheme: dark)");
    setIsDark(match.matches);
    const listener = (e: MediaQueryListEvent) => setIsDark(e.matches);
    match.addEventListener("change", listener);
    return () => match.removeEventListener("change", listener);
  }, []);

  const particlesInit = useCallback(async (engine: Engine) => {
    await loadSlim(engine); // ✅ Ya no usamos loadFull
  }, []);

  return (
    <div className="relative h-screen w-full flex items-center justify-center px-4 bg-white dark:bg-gray-900 text-gray-800 dark:text-white overflow-hidden">
      <Particles
        id="tsparticles"
        init={particlesInit}
        className="absolute inset-0 z-0"
        options={{
          fullScreen: false,
          background: { color: { value: "transparent" } },
          particles: {
            number: { value: 60 },
            color: { value: isDark ? "#ffffff" : "#0ea5e9" },
            shape: { type: "circle" },
            opacity: { value: 0.4 },
            size: { value: 3 },
            move: {
              enable: true,
              speed: 1.5,
              direction: "none",
              outModes: "out",
            },
          },
        }}
      />

      <div className="z-10 text-center mt-2">
        <motion.h1
          className="text-[8rem] sm:text-[10rem] font-black tracking-tight leading-none"
          initial={{ scale: 0 }}
          animate={{ scale: 1 }}
          transition={{ duration: 0.6 }}
        >
          404
        </motion.h1>

        <motion.h2
          className="text-3xl sm:text-4xl font-semibold mt-2"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
        >
          ¡Ups! Página no encontrada 😢
        </motion.h2>

        <motion.p
          className="mt-4 max-w-md mx-auto text-gray-600 dark:text-gray-300 text-base sm:text-lg"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.5 }}
        >
          Tal vez escribiste mal la dirección o esta página ya no existe.
        </motion.p>

        <motion.div
          className="mt-6 flex gap-4 justify-center flex-col sm:flex-row"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.8 }}
        >
          <Link
            to="/"
            className="px-6 py-3 bg-gradient-to-r from-blue-600 to-purple-600 text-white font-semibold rounded-md hover:scale-105 transition-transform"
          >
            Ir al inicio
          </Link>
          <Link
            to="/dashboard"
            className="px-6 py-3 border border-gray-400 text-gray-700 dark:text-gray-200 dark:border-gray-500 rounded-md hover:bg-gray-200 dark:hover:bg-gray-700 transition-all"
          >
            Ir al panel
          </Link>
        </motion.div>

        <motion.div
          className="mt-4"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 1.2 }}
        >
          <img
            src="https://illustrations.popsy.co/violet/crashed-error.svg"
            alt="Ilustración de error"
            className="w-64 sm:w-96 mx-auto fill-indigo-500 drop-shadow-2xl drop-shadow-indigo-500/50"
          />
        </motion.div>
      </div>
    </div>
  );
};

export default NotFound;

```

## src\pages\Register.tsx

```tsx
// import { useState } from "react";
// import api from "../api/axios";
// import { useNavigate } from "react-router-dom";

// const Register = () => {
//   const [name, setName] = useState("");
//   const [email, setEmail] = useState("");
//   const [password, setPassword] = useState("");
//   const [phone, setPhone] = useState("");
//   const [error, setError] = useState("");
//   const navigate = useNavigate();

//   const handleSubmit = async (e: React.FormEvent) => {
//     e.preventDefault();
//     try {
//       await api.post("/register", { name, email, password, phone });
//       alert("Registro exitoso. Revisa tu correo para confirmar tu cuenta.");
//       navigate("/login");
//     } catch (err) {
//       console.error(err);
//       setError("Error al registrarse. Puede que el correo ya exista.");
//     }
//   };

//   return (
//     <div className="max-w-sm mx-auto mt-8">
//       <h1 className="text-2xl font-bold mb-4">Registro</h1>
//       <form onSubmit={handleSubmit} className="space-y-4">
//         <input
//           type="text"
//           placeholder="Nombre"
//           className="w-full border p-2"
//           value={name}
//           onChange={(e) => setName(e.target.value)}
//         />
//         <input
//           type="email"
//           placeholder="Correo"
//           className="w-full border p-2"
//           value={email}
//           onChange={(e) => setEmail(e.target.value)}
//         />
//         <input
//           type="tel"
//           placeholder="Teléfono"
//           className="w-full border p-2"
//           value={phone}
//           onChange={(e) => setPhone(e.target.value)}
//         />
//         <input
//           type="password"
//           placeholder="Contraseña"
//           className="w-full border p-2"
//           value={password}
//           onChange={(e) => setPassword(e.target.value)}
//         />
//         <button
//           type="submit"
//           className="w-full bg-green-600 text-white p-2 rounded"
//         >
//           Registrarse
//         </button>
//         {error && <p className="text-red-500 text-sm">{error}</p>}
//         <p className="text-sm mt-2">
//           ¿Ya tienes una cuenta?{" "}
//           <a href="/login" className="text-blue-500 underline">
//             Inicia sesión aquí
//           </a>
//         </p>
//       </form>
//     </div>
//   );
// };

// export default Register;

```

## src\pages\ResetPassword.tsx

```tsx
import { useEffect, useState } from "react";
import { useSearchParams, useNavigate } from "react-router-dom";
import { toast } from "react-toastify";
import api from "../api/axios";
import { useAuthModal } from "../store/useAuthModal";
import {
  validatePasswordSecurity,
} from "../utils/validationHelpersForm";
import PasswordWithStrengthInput from "../components/common/PasswordWithStrengthInputForm";
import InputWithLabel from "../components/common/InputWithLabel";

export default function ResetPassword() {
  const [searchParams] = useSearchParams();
  const token = searchParams.get("token") || "";
  const email = searchParams.get("email") || "";
  const navigate = useNavigate();
  const { openModal } = useAuthModal();

  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [passwordError, setPasswordError] = useState("");
  const [confirmPasswordError, setConfirmPasswordError] = useState("");
  const [loading, setLoading] = useState(true);
  const [valid, setValid] = useState(false);
  const [error, setError] = useState("");
  const [resend, setResend] = useState(false);
  const [isSending, setIsSending] = useState(false);

  useEffect(() => {
    const validateToken = async () => {
      try {
        const res = await api.post("/check-token-status", { token });
        setValid(res.data.valid);
        if (!res.data.valid) setError("El enlace ha expirado o es inválido.");
      } catch {
        setError("Error al validar el enlace.");
      } finally {
        setLoading(false);
      }
    };

    if (token) validateToken();
    else {
      setError("Token no proporcionado.");
      setLoading(false);
    }
  }, [token]);

  const handlePasswordChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const newPassword = e.target.value;
    setPassword(newPassword);

    const errors = validatePasswordSecurity(newPassword, email);
    setPasswordError(errors.length > 0 ? errors.join(" ") : "");

    if (confirmPassword && confirmPassword !== newPassword) {
      setConfirmPasswordError("Las contraseñas no coinciden.");
    } else {
      setConfirmPasswordError("");
    }
  };

  const handleConfirmPasswordChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const newConfirm = e.target.value;
    setConfirmPassword(newConfirm);
    if (password !== newConfirm) {
      setConfirmPasswordError("Las contraseñas no coinciden.");
    } else {
      setConfirmPasswordError("");
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (isSending) return;
    setIsSending(true);

    const passwordErrors = validatePasswordSecurity(password, email);
    if (passwordErrors.length > 0) {
      toast.warning(passwordErrors.join(" "));
      setIsSending(false);
      return;
    }

    if (password !== confirmPassword) {
      toast.error("Las contraseñas no coinciden");
      setIsSending(false);
      return;
    }

    try {
      await api.post(`/reset-password/${token}`, { password });
      toast.success("Contraseña actualizada correctamente");

      setTimeout(() => {
        navigate("/");
        openModal("login");
      }, 2000);
    } catch {
      toast.error("Error al actualizar la contraseña");
    } finally {
      setIsSending(false);
    }
  };

  const handleResend = async () => {
    if (isSending) return;
    setIsSending(true);

    try {
      await api.post("/send-recovery", { email });
      toast.success("Se envió un nuevo enlace de recuperación");
      setResend(true);
    } catch {
      toast.error("No se pudo reenviar el correo");
    } finally {
      setIsSending(false);
    }
  };

  if (loading) return <p className="text-center mt-8 dark:text-white">Cargando...</p>;

  if (!valid) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-100 dark:bg-bgDark px-4">
        <div className="bg-white dark:bg-bgLight/10 shadow-md rounded-lg p-6 w-full max-w-md text-center">
          <h2 className="text-xl font-semibold text-red-600 dark:text-red-400 mb-4">{error}</h2>
          {!resend && email ? (
            <>
              <p className="text-sm text-gray-600 dark:text-gray-300 mb-4">
                Puedes reenviar el enlace a: <strong>{email}</strong>
              </p>
              <button
                onClick={handleResend}
                disabled={isSending}
                className={`bg-sky-600 text-white px-4 py-2 rounded hover:bg-sky-700 transition ${
                  isSending ? "opacity-50 cursor-not-allowed" : ""
                }`}
              >
                {isSending ? "Enviando..." : "Reenviar enlace"}
              </button>
            </>
          ) : resend ? (
            <p className="text-green-600 dark:text-green-400">
              Enlace reenviado. Revisa tu correo.
            </p>
          ) : (
            <p className="text-sm text-gray-500 dark:text-gray-300">
              Solicita un nuevo enlace desde "Olvidé mi contraseña".
            </p>
          )}
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-100 dark:bg-bgDark px-4">
      <form
        onSubmit={handleSubmit}
        className="bg-white dark:bg-bgLight/10 shadow-md rounded-lg p-6 w-full max-w-md"
      >
        <h2 className="text-2xl font-bold mb-4 text-center text-sky-600 dark:text-textLight">
          Nueva Contraseña
        </h2>
        <p className="text-sm text-gray-600 dark:text-gray-300 mb-4 text-center">
          Ingresa una nueva contraseña para tu cuenta.
        </p>

        <PasswordWithStrengthInput
          value={password}
          onChange={handlePasswordChange}
          error={passwordError}
          showTooltip={true}
          showStrengthBar={true}
        />

        <InputWithLabel
          label="Confirmar contraseña"
          name="confirmPassword"
          type="password"
          value={confirmPassword}
          onChange={handleConfirmPasswordChange}
          placeholder="Confirma tu contraseña"
          error={confirmPasswordError}
        />

        <button
          type="submit"
          disabled={isSending || passwordError !== "" || confirmPasswordError !== ""}
          className={`w-full bg-sky-600 text-white py-2 rounded hover:bg-sky-700 transition ${
            isSending ? "opacity-50 cursor-not-allowed" : ""
          }`}
        >
          {isSending ? "Actualizando..." : "Actualizar contraseña"}
        </button>
      </form>
    </div>
  );
}

```

## src\router\AppRouter.tsx

```tsx
// src/router/AppRouter.tsx
import { Routes, Route } from "react-router-dom";
import Home from "../pages/Home";
import Dashboard from "../pages/Dashboard";
import ConfirmationMail from "../pages/ConfirmationMail";
import ResetPassword from "../pages/ResetPassword";
import NotFound from "../pages/NotFound";
import PublicLayout from "../layout/PublicLayout";
import DashboardLayout from "../layout/DashboardLayout";
import PrivateRoute from "../utils/PrivateRoute";

const AppRouter = () => (
  <Routes>
    <Route
      path="/"
      element={
        <PublicLayout>
          <Home />
        </PublicLayout>
      }
    />
    <Route
      path="/login"
      element={
        <PublicLayout>
          <Home />
        </PublicLayout>
      }
    />
    <Route
      path="/register"
      element={
        <PublicLayout>
          <Home />
        </PublicLayout>
      }
    />
    <Route
      path="/confirm/:token"
      element={
        <PublicLayout>
          <ConfirmationMail />
        </PublicLayout>
      }
    />
    <Route
      path="/reset-password"
      element={
        <PublicLayout>
          <ResetPassword />
        </PublicLayout>
      }
    />

    <Route
      path="/dashboard"
      element={
        <PrivateRoute>
          <DashboardLayout>
            <Dashboard />
          </DashboardLayout>
        </PrivateRoute>
      }
    />

    <Route path="*" element={<NotFound />} />
  </Routes>
);

export default AppRouter;

```

## src\store\useAuthModal.ts

```typescript
import { create } from "zustand";

interface AuthModalState {
  isOpen: boolean;
  view: "login" | "register";
  openModal: (view?: "login" | "register") => void;
  closeModal: () => void;
  toggleView: () => void;
}

export const useAuthModal = create<AuthModalState>((set) => ({
  isOpen: false,
  view: "login",
  openModal: (view = "login") => set({ isOpen: true, view }),
  closeModal: () => set({ isOpen: false }),
  toggleView: () =>
    set((state) => ({
      view: state.view === "login" ? "register" : "login",
    })),
}));

```

## src\utils\auth.ts

```typescript
export const isAuthenticated = () => true;

```

## src\utils\PrivateRoute.tsx

```tsx
import { Navigate } from 'react-router-dom';

import { ReactNode } from 'react';

const PrivateRoute = ({ children }: { children: ReactNode }) => {
  const token = localStorage.getItem('token');
  return token ? children : <Navigate to="/login" replace />;
};

export default PrivateRoute;
```

## src\utils\validationHelpersForm.ts

```typescript
// Capitaliza cada palabra
export const capitalizeName = (name: string) => {
    return name
        .toLowerCase()
        .split(" ")
        .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
        .join(" ");
};


// Devuelve el puntaje de seguridad de la contraseña
export const getPasswordScore = (password: string) => {
    let score = 0;
    if (password.length >= 8) score++;
    if (/[A-Z]/.test(password)) score++;
    if (/[0-9]/.test(password)) score++;
    if (/[^A-Za-z0-9]/.test(password)) score++;
    return score;
};


// Valida el formato de la dirección de correo electrónico
export const validateEmailFormat = (email: string): boolean => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
};

// Valida la seguridad de la contraseña
export const validatePasswordSecurity = (password: string, email: string): string[] => {
    const errors: string[] = [];

    if (password.length < 8) {
        errors.push("Debe tener al menos 8 caracteres.");
    }
    if (!/[A-Z]/.test(password)) {
        errors.push("Debe incluir al menos una letra mayúscula.");
    }
    if (!/[a-z]/.test(password)) {
        errors.push("Debe incluir al menos una letra minúscula.");
    }
    if (!/[0-9]/.test(password)) {
        errors.push("Debe incluir al menos un número.");
    }
    if (!/[^A-Za-z0-9]/.test(password)) {
        errors.push("Debe incluir al menos un símbolo.");
    }
    if (password.toLowerCase() === email.toLowerCase()) {
        errors.push("La contraseña no puede ser igual al correo electrónico.");
    }

    return errors;
};

// Devuelve el texto, color y clase CSS según el puntaje de la contraseña
export const getStrengthLabel = (score: number) => {
    switch (score) {
      case 0:
      case 1:
        return {
          text: "Débil",
          color: "text-red-500 dark:text-red-400",
          bar: "bg-red-500 dark:bg-red-400",
        };
      case 2:
        return {
          text: "Media",
          color: "text-yellow-500 dark:text-yellow-400",
          bar: "bg-yellow-400 dark:bg-yellow-300",
        };
      case 3:
        return {
          text: "Fuerte",
          color: "text-blue-500 dark:text-blue-400",
          bar: "bg-blue-500 dark:bg-blue-400",
        };
      case 4:
        return {
          text: "Muy fuerte",
          color: "text-green-600 dark:text-green-400",
          bar: "bg-green-500 dark:bg-green-400",
        };
      default:
        return {
          text: "",
          color: "",
          bar: "bg-gray-200 dark:bg-gray-600",
        };
    }
  };
  


```




```

## frontend\eslint.config.js

```javascript
import js from '@eslint/js'
import globals from 'globals'
import reactHooks from 'eslint-plugin-react-hooks'
import reactRefresh from 'eslint-plugin-react-refresh'
import tseslint from 'typescript-eslint'

export default tseslint.config(
  { ignores: ['dist'] },
  {
    extends: [js.configs.recommended, ...tseslint.configs.recommended],
    files: ['**/*.{ts,tsx}'],
    languageOptions: {
      ecmaVersion: 2020,
      globals: globals.browser,
    },
    plugins: {
      'react-hooks': reactHooks,
      'react-refresh': reactRefresh,
    },
    rules: {
      ...reactHooks.configs.recommended.rules,
      'react-refresh/only-export-components': [
        'warn',
        { allowConstantExport: true },
      ],
    },
  },
)

```

## frontend\index.html

```html
<!doctype html>
<html lang="en">

<head>
  <meta charset="UTF-8" />
  <link rel="icon" type="image/svg+xml" href="/vite.svg" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Aqua River Park</title>
</head>

<body>
  <div id="root"></div>
  <script type="module" src="/src/main.tsx"></script>
</body>

</html>
```

## frontend\public\ARP logo.png

```
    ftypavif    avifmif1miafMA1B  �meta       (hdlr        pict            libavif    pitm        ,iloc    D        4  �      �     Biinf        infe      av01Color    infe      av01Alpha    iref       auxl      �iprp   �ipco   ispe       |   E   pixi       av1C�     colrnclx   �   pixi       av1C�     8auxC    urn:mpeg:mpegB:cicp:systems:auxiliary:alpha    ipma        � �  #mdat 

   7����P2� ��8�A ��3��fKn������5�??�4���X����3J�cy�.y�c=j��IMg�k���� Ą�0�����f仢�#V��pА���;.oWp��~�r�E�xdI��A��1�]u@F_�c����]�7A�Kք7�4���d�D��+��+gg2M�f�Y-	u�H���t=�]��"����wn=tzr>R�ΝU��Î�u$E�\��|o���(?����L��&N����ש��w��%H%[�,VD�")~�Ψ'���O�d.u��(	��Ƃo.Snd�h������I�X��v3eы9^4��=E��~e�u����!#���;������T$`�DX7hM�V֜�
�����Ŷk'؍�m���A�DIxt�g~,�������u�pQ���~�l��7]*�����5�����Val�l�?��۶x�C�Y�=���pX�;�j������s�d'��H�/c��B��a��o)DL�C\����%����#�����qH�,��4�y���e����GAa�	�{�m����h����x��ߪ��H��1��=�׳�nb�o�n�S��q
>�~��z#s/{���䞿w��q��Ԝ���߱�f�m�9�6]���%W�KLӈ�����P#$��j���`���-";��.��" %'�XF0�߄f���c8k�D3{$�Fȃ_tw1�6!��g:2/E���X�E$���/�i�2y���jF�(��rZ�VXل�QqVNM��B]4A�{(G�UCx�� -�	2������\�I`�3.�oЖP�Xl�����g��jb��s��=Q[O��4�<��OS{��Q�����GS� �S��,o���Y+��1~��� 

   7����B2� � a���<J�r˾�a�w@���_�TD&����U?�^Ɂ?�PZ�n�!������|I�E��b�lL։~��(��UL-�@�2�/���fmr��ZX��^�o�n���w���x��H��;=�0V;T�^�X^.�U�[s�N����{F>5�����[���@�!�(��Aa�Ǚ|�u�Li �p8�$��������A�T�y�µҥ?��`���>_VO'e��ƀ�ǯD�r!�W:QN�$z,~X�U.����k�c�e��-��11�/Tc�*!�{�}~����m�Q��;
Ǟ>�T��B2|P5$[�H�a����TB�!��*���6E�6a��h03h���L`_���I;���K�9��H�!Y�>��<.J�_�7w��]'�a���� ��6�O� Js��86`�뗔TZ��_~�H�j!�n@	�f�C�=+pFTZ�I��8�0"[~���\��3&�LwY����si�Lr��#w5��?�c�tT�4�>��ѯ/Ntβ�&U6	F-�:�<0�y��ݕ%��m�_%D���ŝ��z�����@H$-���cS�*o\�tڏ]����+��EO�^8�މ�)n���}]�����Ø�ᔹ�O����t�e$./n���W/<�3� gS>���Pv^��    O����I@Io<��m�J�#Zd8�`i�y�Fٝ��s��x�!Y�Z�EL�JB�{�a4�sZ�`ͯ�����+��v���h�W�u}UH��e6]UR!��T]E3Hd��K��`fϮu��ldakq��Y.,�1�6�Ҏ���@���1>L}��t�FI���7����jb������b�K�d�ᱠ|h�	���./k����������V�)����	D-�,/����j{�y�o�t��\':f����`��C�l����җ��Z����eT��C�ۃ�S�<�gG]iB.�7@��s�C���N}�K�U�Rb��f�ӷ�?��8�������0�[�� t�Ӿ������kw��AY{=�?j�If�Tz �0��_Rya{K�1��v�D�}�|C ���m���@Z9����q�9�ku���x@�qB#��ڲљ��`�A:�b.1Fڱٓ3i�c�����Z�Q�r!�4�P�>�P�B� h�$����F���>j~Hw���=v1�j1�Ũ$-t~����%熍��x�ւ=A늤��g �,B6s����Nrcr��-�y�1��VWaA��:8}���%
�Z23�����,$a�
�e��G�|dp�zU�e��&Ev��8)��h�8|��}�B}�&Ra�w�J�\æ�������Ml1.ۀb�Jۊ�l�H��~1tu_k�Ǜ|�o��>պZ�"̵Ȏ�Z@���|�}9I������K@�x���?b�x���yt3$��]u&��pm�ofo'ٷi�V��-r�Qo�c�05o���/2��p�S�D6�k�|5��Sw�<�;UC��Hӹ�`a[���*���t���`��u�]��m[�CG|��Np����(��f�L�<�UIOq|���4�o*E ὢ������s�y���~�9�E1�Ep����"��� ��>݁%͖�ş�o�뼡���Q�l(J4zWKNo�V��;>y�_�E��x_+���I����,S�4S��$�z�t���b��k,�����E!��x|�`�i{?N�d��)�Ѫp���P���e9���{�Sb��s�,���*{�_�;7�>\�?'@R7��G~Gؗ��?iڲ.�!z;]��ݟM:��<+��f	�n����J�Qq�c�w��ۆ��~}ʣ=XK� d����Eox�q熪1��o�h�2������=#3S��%;`_1y�*�A�cV�tƮ|C�p�Z�?�w��2|sU��C���
}^Q�_��V��D=3��� g�4f�Y *=L!�Kߵ�� �,�NFF�wD 6���VYXͥC3�'9���K���>�����ێ�e��`�2s���LnO�3F[��5�(i��_}m��\���1p��q�_�?lܩQ��1�V�h�]�*����i8�Lw,��Or�:瓞	J�8���`m/�N�*E�v������M��3M�$��������-&�Y��.�'�d?(*{�#�Iާ��oi�y�@��KRkSe��+K<���2Z�,Fo�O5��M��&��Q�T}&�����<�#o�ۡ;em�!�%�vj��_���3#
�~0V�l' ٱ6���� �Rhn��x�-�	 �ޞگ�3��ǳK�n9f9���jsJ=�\^����!}g��4��,�gs�}&�#-k��J2�ۡ��aI�s����ۋoG�[-F��r@��mՔ:ϘF�Wߨd����A&UT$N�t[���,�2�S'�H!��H�`
TkF�[�������,%	5Bg�6���o6��-���|0�M!��Ց.�X<{�ѣ�����@�Ma|�c3�l~S��g�K�@9�I_+(��3�0Ihfw�J���C�f�\ L��^:f؎Z��w)7�>��Ov���\�<��r2'[A�Ä�$}�{�����n���`}�./�&�}*�Ѡ�� ��JV�}H�AXT���7%�5�_�K�}�w��t��W�E�3ZL^�O��\eV�c�(!R�y����6���0p�Bo's�m2z��2U�q]q^4�Z�$V�l��aOZ8;�R�.�D��U܄�ȸ`" ��$�Sa�`�\�U_p����ť�����b�H��F����y9����	�Ӹ��4����+f &��A�hX��R���	���(�ɼ��&������*�
M:�U���"TG�Tw�K񮑧�!��iS�;���q+��`+����1p���&�oA;��U�i58B����h5������a�Ca&lpٻP�{̧ɞ��R]c��:��][
```

## frontend\public\vite.svg

```
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" aria-hidden="true" role="img" class="iconify iconify--logos" width="31.88" height="32" preserveAspectRatio="xMidYMid meet" viewBox="0 0 256 257"><defs><linearGradient id="IconifyId1813088fe1fbc01fb466" x1="-.828%" x2="57.636%" y1="7.652%" y2="78.411%"><stop offset="0%" stop-color="#41D1FF"></stop><stop offset="100%" stop-color="#BD34FE"></stop></linearGradient><linearGradient id="IconifyId1813088fe1fbc01fb467" x1="43.376%" x2="50.316%" y1="2.242%" y2="89.03%"><stop offset="0%" stop-color="#FFEA83"></stop><stop offset="8.333%" stop-color="#FFDD35"></stop><stop offset="100%" stop-color="#FFA800"></stop></linearGradient></defs><path fill="url(#IconifyId1813088fe1fbc01fb466)" d="M255.153 37.938L134.897 252.976c-2.483 4.44-8.862 4.466-11.382.048L.875 37.958c-2.746-4.814 1.371-10.646 6.827-9.67l120.385 21.517a6.537 6.537 0 0 0 2.322-.004l117.867-21.483c5.438-.991 9.574 4.796 6.877 9.62Z"></path><path fill="url(#IconifyId1813088fe1fbc01fb467)" d="M185.432.063L96.44 17.501a3.268 3.268 0 0 0-2.634 3.014l-5.474 92.456a3.268 3.268 0 0 0 3.997 3.378l24.777-5.718c2.318-.535 4.413 1.507 3.936 3.838l-7.361 36.047c-.495 2.426 1.782 4.5 4.151 3.78l15.304-4.649c2.372-.72 4.652 1.36 4.15 3.788l-11.698 56.621c-.732 3.542 3.979 5.473 5.943 2.437l1.313-2.028l72.516-144.72c1.215-2.423-.88-5.186-3.54-4.672l-25.505 4.922c-2.396.462-4.435-1.77-3.759-4.114l16.646-57.705c.677-2.35-1.37-4.583-3.769-4.113Z"></path></svg>
```

## frontend\README.md

```markdown
# React + TypeScript + Vite

This template provides a minimal setup to get React working in Vite with HMR and some ESLint rules.

Currently, two official plugins are available:

- [@vitejs/plugin-react](https://github.com/vitejs/vite-plugin-react/blob/main/packages/plugin-react/README.md) uses [Babel](https://babeljs.io/) for Fast Refresh
- [@vitejs/plugin-react-swc](https://github.com/vitejs/vite-plugin-react-swc) uses [SWC](https://swc.rs/) for Fast Refresh

## Expanding the ESLint configuration

If you are developing a production application, we recommend updating the configuration to enable type-aware lint rules:

```js
export default tseslint.config({
  extends: [
    // Remove ...tseslint.configs.recommended and replace with this
    ...tseslint.configs.recommendedTypeChecked,
    // Alternatively, use this for stricter rules
    ...tseslint.configs.strictTypeChecked,
    // Optionally, add this for stylistic rules
    ...tseslint.configs.stylisticTypeChecked,
  ],
  languageOptions: {
    // other options...
    parserOptions: {
      project: ['./tsconfig.node.json', './tsconfig.app.json'],
      tsconfigRootDir: import.meta.dirname,
    },
  },
})
```

You can also install [eslint-plugin-react-x](https://github.com/Rel1cx/eslint-react/tree/main/packages/plugins/eslint-plugin-react-x) and [eslint-plugin-react-dom](https://github.com/Rel1cx/eslint-react/tree/main/packages/plugins/eslint-plugin-react-dom) for React-specific lint rules:

```js
// eslint.config.js
import reactX from 'eslint-plugin-react-x'
import reactDom from 'eslint-plugin-react-dom'

export default tseslint.config({
  plugins: {
    // Add the react-x and react-dom plugins
    'react-x': reactX,
    'react-dom': reactDom,
  },
  rules: {
    // other rules...
    // Enable its recommended typescript rules
    ...reactX.configs['recommended-typescript'].rules,
    ...reactDom.configs.recommended.rules,
  },
})
```

```

## frontend\src\api\axios.ts

```typescript
// frontend/src/api/axios.ts
import axios from 'axios';

const api = axios.create({
  baseURL: 'http://localhost:3000/api', // 👈 Este debe apuntar al backend
});

export default api;

```

## frontend\src\App.css

```css
#root {
  max-width: 1280px;
  margin: 0 auto;
  padding: 2rem;
  text-align: center;
}

.logo {
  height: 6em;
  padding: 1.5em;
  will-change: filter;
  transition: filter 300ms;
}
.logo:hover {
  filter: drop-shadow(0 0 2em #646cffaa);
}
.logo.react:hover {
  filter: drop-shadow(0 0 2em #61dafbaa);
}

@keyframes logo-spin {
  from {
    transform: rotate(0deg);
  }
  to {
    transform: rotate(360deg);
  }
}

@media (prefers-reduced-motion: no-preference) {
  a:nth-of-type(2) .logo {
    animation: logo-spin infinite 20s linear;
  }
}

.card {
  padding: 2em;
}

.read-the-docs {
  color: #888;
}

```

## frontend\src\App.tsx

```tsx
// src/App.tsx
import { BrowserRouter as Router } from "react-router-dom";
import AppRouter from "./router/AppRouter";
import { ToastContainer } from "react-toastify";
import { useAuthModal } from "./store/useAuthModal";
import AuthModal from "./components/auth/AuthModal";
import RouteModalHandler from "./components/RouteModalHandler";
import "react-toastify/dist/ReactToastify.css";

function App() {
  const { isOpen } = useAuthModal();

  return (
    <Router>
      <RouteModalHandler />
      <AppRouter />
      {isOpen && <AuthModal />}
      <ToastContainer position="top-right" autoClose={3000} />
    </Router>
  );
}

export default App;

```

## frontend\src\assets\react.svg

```
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" aria-hidden="true" role="img" class="iconify iconify--logos" width="35.93" height="32" preserveAspectRatio="xMidYMid meet" viewBox="0 0 256 228"><path fill="#00D8FF" d="M210.483 73.824a171.49 171.49 0 0 0-8.24-2.597c.465-1.9.893-3.777 1.273-5.621c6.238-30.281 2.16-54.676-11.769-62.708c-13.355-7.7-35.196.329-57.254 19.526a171.23 171.23 0 0 0-6.375 5.848a155.866 155.866 0 0 0-4.241-3.917C100.759 3.829 77.587-4.822 63.673 3.233C50.33 10.957 46.379 33.89 51.995 62.588a170.974 170.974 0 0 0 1.892 8.48c-3.28.932-6.445 1.924-9.474 2.98C17.309 83.498 0 98.307 0 113.668c0 15.865 18.582 31.778 46.812 41.427a145.52 145.52 0 0 0 6.921 2.165a167.467 167.467 0 0 0-2.01 9.138c-5.354 28.2-1.173 50.591 12.134 58.266c13.744 7.926 36.812-.22 59.273-19.855a145.567 145.567 0 0 0 5.342-4.923a168.064 168.064 0 0 0 6.92 6.314c21.758 18.722 43.246 26.282 56.54 18.586c13.731-7.949 18.194-32.003 12.4-61.268a145.016 145.016 0 0 0-1.535-6.842c1.62-.48 3.21-.974 4.76-1.488c29.348-9.723 48.443-25.443 48.443-41.52c0-15.417-17.868-30.326-45.517-39.844Zm-6.365 70.984c-1.4.463-2.836.91-4.3 1.345c-3.24-10.257-7.612-21.163-12.963-32.432c5.106-11 9.31-21.767 12.459-31.957c2.619.758 5.16 1.557 7.61 2.4c23.69 8.156 38.14 20.213 38.14 29.504c0 9.896-15.606 22.743-40.946 31.14Zm-10.514 20.834c2.562 12.94 2.927 24.64 1.23 33.787c-1.524 8.219-4.59 13.698-8.382 15.893c-8.067 4.67-25.32-1.4-43.927-17.412a156.726 156.726 0 0 1-6.437-5.87c7.214-7.889 14.423-17.06 21.459-27.246c12.376-1.098 24.068-2.894 34.671-5.345a134.17 134.17 0 0 1 1.386 6.193ZM87.276 214.515c-7.882 2.783-14.16 2.863-17.955.675c-8.075-4.657-11.432-22.636-6.853-46.752a156.923 156.923 0 0 1 1.869-8.499c10.486 2.32 22.093 3.988 34.498 4.994c7.084 9.967 14.501 19.128 21.976 27.15a134.668 134.668 0 0 1-4.877 4.492c-9.933 8.682-19.886 14.842-28.658 17.94ZM50.35 144.747c-12.483-4.267-22.792-9.812-29.858-15.863c-6.35-5.437-9.555-10.836-9.555-15.216c0-9.322 13.897-21.212 37.076-29.293c2.813-.98 5.757-1.905 8.812-2.773c3.204 10.42 7.406 21.315 12.477 32.332c-5.137 11.18-9.399 22.249-12.634 32.792a134.718 134.718 0 0 1-6.318-1.979Zm12.378-84.26c-4.811-24.587-1.616-43.134 6.425-47.789c8.564-4.958 27.502 2.111 47.463 19.835a144.318 144.318 0 0 1 3.841 3.545c-7.438 7.987-14.787 17.08-21.808 26.988c-12.04 1.116-23.565 2.908-34.161 5.309a160.342 160.342 0 0 1-1.76-7.887Zm110.427 27.268a347.8 347.8 0 0 0-7.785-12.803c8.168 1.033 15.994 2.404 23.343 4.08c-2.206 7.072-4.956 14.465-8.193 22.045a381.151 381.151 0 0 0-7.365-13.322Zm-45.032-43.861c5.044 5.465 10.096 11.566 15.065 18.186a322.04 322.04 0 0 0-30.257-.006c4.974-6.559 10.069-12.652 15.192-18.18ZM82.802 87.83a323.167 323.167 0 0 0-7.227 13.238c-3.184-7.553-5.909-14.98-8.134-22.152c7.304-1.634 15.093-2.97 23.209-3.984a321.524 321.524 0 0 0-7.848 12.897Zm8.081 65.352c-8.385-.936-16.291-2.203-23.593-3.793c2.26-7.3 5.045-14.885 8.298-22.6a321.187 321.187 0 0 0 7.257 13.246c2.594 4.48 5.28 8.868 8.038 13.147Zm37.542 31.03c-5.184-5.592-10.354-11.779-15.403-18.433c4.902.192 9.899.29 14.978.29c5.218 0 10.376-.117 15.453-.343c-4.985 6.774-10.018 12.97-15.028 18.486Zm52.198-57.817c3.422 7.8 6.306 15.345 8.596 22.52c-7.422 1.694-15.436 3.058-23.88 4.071a382.417 382.417 0 0 0 7.859-13.026a347.403 347.403 0 0 0 7.425-13.565Zm-16.898 8.101a358.557 358.557 0 0 1-12.281 19.815a329.4 329.4 0 0 1-23.444.823c-7.967 0-15.716-.248-23.178-.732a310.202 310.202 0 0 1-12.513-19.846h.001a307.41 307.41 0 0 1-10.923-20.627a310.278 310.278 0 0 1 10.89-20.637l-.001.001a307.318 307.318 0 0 1 12.413-19.761c7.613-.576 15.42-.876 23.31-.876H128c7.926 0 15.743.303 23.354.883a329.357 329.357 0 0 1 12.335 19.695a358.489 358.489 0 0 1 11.036 20.54a329.472 329.472 0 0 1-11 20.722Zm22.56-122.124c8.572 4.944 11.906 24.881 6.52 51.026c-.344 1.668-.73 3.367-1.15 5.09c-10.622-2.452-22.155-4.275-34.23-5.408c-7.034-10.017-14.323-19.124-21.64-27.008a160.789 160.789 0 0 1 5.888-5.4c18.9-16.447 36.564-22.941 44.612-18.3ZM128 90.808c12.625 0 22.86 10.235 22.86 22.86s-10.235 22.86-22.86 22.86s-22.86-10.235-22.86-22.86s10.235-22.86 22.86-22.86Z"></path></svg>
```

## frontend\src\components\auth\AuthForm.tsx

```tsx
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { AxiosError } from "axios";
import api from "../../api/axios";
import { toast } from "react-toastify";
import { useAuthModal } from "../../store/useAuthModal";
import AuthResendModal from "./AuthResendModal";
import {
  getPasswordScore,
  capitalizeName,
  validateEmailFormat,
  validatePasswordSecurity,
} from "../../utils/validationHelpersForm";

import InputWithLabel from "../common/InputWithLabel";
import PasswordWithStrengthInput from "../common/PasswordWithStrengthInputForm";

interface Props {
  modalStep: "notice" | "form" | "success";
  showModal: boolean;
  modalType: "confirm" | "recover";
  setFormEmail: React.Dispatch<React.SetStateAction<string>>;
  setModalStep: React.Dispatch<
    React.SetStateAction<"notice" | "form" | "success">
  >;
  setShowModal: React.Dispatch<React.SetStateAction<boolean>>;
  setModalType: React.Dispatch<React.SetStateAction<"confirm" | "recover">>;
}

const initialForm = {
  fullName: "",
  email: "",
  phone: "",
  password: "",
  confirmPassword: "",
};

export default function AuthForm({
  modalStep,
  showModal,
  modalType,
  setFormEmail,
  setModalStep,
  setShowModal,
  setModalType,
}: Props) {
  const { view, closeModal, toggleView } = useAuthModal();
  const isLogin = view === "login";
  const navigate = useNavigate();

  const [formData, setFormData] = useState(initialForm);
  const [errors, setErrors] = useState<{ [key: string]: string }>({});
  const [passwordStrength, setPasswordStrength] = useState(0);
  const [resendMsg, setResendMsg] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);

  const handleInput = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;

    const formattedValue = name === "fullName" ? capitalizeName(value) : value;

    if (name === "password") setPasswordStrength(getPasswordScore(value));

    setFormData((prev) => ({ ...prev, [name]: formattedValue }));
    setErrors((prev) => ({ ...prev, [name]: "" }));
  };

  const validate = () => {
    const errs: { [key: string]: string } = {};

    if (!validateEmailFormat(formData.email)) {
      errs.email = "Correo no válido";
    }

    const passwordErrors = validatePasswordSecurity(
      formData.password,
      formData.email
    );
    if (passwordErrors.length > 0) {
      errs.password = passwordErrors.join(" ");
    }

    if (!isLogin) {
      if (!formData.fullName || formData.fullName.length < 2) {
        errs.fullName = "El nombre debe tener al menos 2 caracteres.";
      }

      if (!/^[0-9]{10}$/.test(formData.phone)) {
        errs.phone = "El teléfono debe tener 10 dígitos.";
      }

      if (formData.password !== formData.confirmPassword) {
        errs.confirmPassword = "Las contraseñas no coinciden.";
      }
    }

    setErrors(errs);
    return Object.keys(errs).length === 0;
  };

  const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (isSubmitting) return; // Evita múltiples envíos
    setIsSubmitting(true);

    const isValid = validate();
    if (!isValid) {
      setIsSubmitting(false); // 🔁 Agrega esto para volver a habilitar el botón
      return;
    }

    try {
      if (isLogin) {
        const res = await api.post("/login", {
          email: formData.email,
          password: formData.password,
        });

        if (!res.data.user.isConfirmed) {
          const tokenExpired = res.data.tokenExpired;
          setModalType("confirm");
          setModalStep(tokenExpired ? "form" : "notice");
          setShowModal(true);
          return;
        }

        closeModal();
        toast.success("Login exitoso!");
        navigate("/");
      } else {
        const res = await api.post("/register", {
          name: formData.fullName,
          email: formData.email,
          phone: formData.phone,
          password: formData.password,
        });

        if (res.status === 200 || res.status === 201) {
          toast.success("Registro exitoso. Revisa tu correo.");
          toggleView();
        }
      }
    } catch (err) {
      const error = err as AxiosError<{
        message: string;
        tokenExpired?: boolean;
      }>;
      const msg = error.response?.data?.message;

      if (msg === "Debes confirmar tu cuenta") {
        const tokenExpired = error.response?.data?.tokenExpired;
        setModalType("confirm");
        setModalStep(tokenExpired ? "form" : "notice");
        setShowModal(true);
      } else if (msg) {
        toast.error(msg);
      } else {
        toast.error("Ocurrió un error inesperado.");
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleResend = async (e: React.FormEvent) => {
    e.preventDefault();
    if (isSubmitting) return; // Evita múltiples envíos
    setIsSubmitting(true);
    setResendMsg("");

    const endpoint =
      modalType === "recover" ? "/send-recovery" : "/resend-confirmation";

    try {
      const res = await api.post(endpoint, {
        email: formData.email,
      });

      setResendMsg(res.data.message);
      setModalStep("success");

      setTimeout(() => {
        toast.success(
          modalType === "recover"
            ? "¡Enlace de recuperación enviado!"
            : "¡Correo de confirmación reenviado!"
        );
        setShowModal(false);
        setResendMsg("");
        setFormData((prev) => ({ ...prev, email: "", password: "" }));
      }, 5000);
    } catch (err) {
      const error = err as AxiosError<{ message: string }>;
      const msg = error.response?.data?.message;

      if (msg === "La cuenta ya está confirmada") {
        toast.info("La cuenta ya ha sido confirmada.");
        setShowModal(false);
      } else {
        setResendMsg("Error al enviar el enlace.");
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <>
      <form onSubmit={handleSubmit} className="space-y-4">
        {!isLogin && (
          <>
            <InputWithLabel
              label=""
              name="fullName"
              value={formData.fullName}
              onChange={handleInput}
              placeholder="Tu nombre completo"
              error={errors.fullName}
            />

            <InputWithLabel
              label=""
              name="phone"
              value={formData.phone}
              onChange={handleInput}
              placeholder="Teléfono"
              error={errors.phone}
            />
          </>
        )}

        <InputWithLabel
          label=""
          name="email"
          type="email"
          value={formData.email}
          onChange={handleInput}
          placeholder="Mail"
          error={errors.email}
          autoFocus
        />

        <PasswordWithStrengthInput
          value={formData.password}
          onChange={handleInput}
          error={errors.password}
          showTooltip={!isLogin}
          showStrengthBar={!isLogin}
        />

        {!isLogin && (
          <InputWithLabel
            label=""
            name="confirmPassword"
            type="password"
            value={formData.confirmPassword}
            onChange={handleInput}
            placeholder="Confirma tu contraseña"
            error={errors.confirmPassword}
          />
        )}

        {isLogin && (
          <div className="flex justify-end text-sm text-blue-600">
            <button
              type="button"
              className="hover:underline"
              onClick={() => {
                setModalType("recover");
                setModalStep("form");
                setShowModal(true);
                setFormEmail(formData.email); // importante para usar en el modal
              }}
            >
              Forgot Password?
            </button>
          </div>
        )}

        <button
          type="submit"
          disabled={isSubmitting || (!isLogin && passwordStrength < 3)}
          className={`w-full bg-gradient-to-r from-indigo-500 via-purple-500 to-pink-500 text-white py-2 rounded-lg hover:opacity-90 transition-all ${
            isSubmitting ? "opacity-50 cursor-not-allowed" : ""
          }`}
        >
          {isSubmitting ? "Conectando..." : isLogin ? "Sign In" : "Sign Up"}
        </button>

        <p className="text-center text-sm text-gray-600 mt-4">
          {isLogin ? "Don’t have an account?" : "Already have an account?"}{" "}
          <button
            type="button"
            onClick={toggleView}
            className="text-blue-600 font-semibold hover:underline"
          >
            {isLogin ? "Sign Up" : "Sign In"}
          </button>
        </p>
      </form>

      <AuthResendModal
        modalStep={modalStep}
        showModal={showModal}
        email={formData.email}
        resendMsg={resendMsg}
        onClose={() => setShowModal(false)}
        onEmailChange={(email) => setFormData((prev) => ({ ...prev, email }))}
        onResend={handleResend}
        type={modalType}
      />
    </>
  );
}

```

## frontend\src\components\auth\AuthModal.tsx

```tsx
import { motion, AnimatePresence } from "framer-motion";
import { FaTimes } from "react-icons/fa";
import { useAuthModal } from "../../store/useAuthModal";
import AuthForm from "./AuthForm";
import AuthSidePanel from "./AuthSidePanel";
import AuthResendModal from "./AuthResendModal";
import { useEffect, useRef, useState } from "react";
import api from "../../api/axios";
import { AxiosError } from "axios";
import { toast } from "react-toastify";

const messages = {
  login: {
    title: "Welcome Back! 👋",
    description: "We're so excited to see you again! Enter your details to access your account.",
    sideTitle: "New Here? 🌟",
    sideDescription: "Join our community and discover amazing features!",
    sideButton: "Create Account",
    submit: "Sign In",
  },
  register: {
    title: "Join Our Community! 🎉",
    description: "Create an account and start your journey with us today.",
    sideTitle: "One of Us? 🎈",
    sideDescription: "Already have an account? Sign in and continue your journey!",
    sideButton: "Sign In",
    submit: "Sign Up",
  },
};

export default function AuthModal() {
  const { isOpen, closeModal, view, toggleView } = useAuthModal();
  const isLogin = view === "login";
  const modalRef = useRef<HTMLDivElement>(null);

  const [formEmail, setFormEmail] = useState("");
  const [resendMsg, setResendMsg] = useState("");
  const [modalStep, setModalStep] = useState<"notice" | "form" | "success">("notice");
  const [modalType, setModalType] = useState<"confirm" | "recover">("confirm");
  const [showModal, setShowModal] = useState(false);

  useEffect(() => {
    const closeOnOutside = (e: MouseEvent) => {
      if (modalRef.current && !modalRef.current.contains(e.target as Node)) closeModal();
    };
    const closeOnEsc = (e: KeyboardEvent) => {
      if (e.key === "Escape") closeModal();
    };
    document.addEventListener("mousedown", closeOnOutside);
    document.addEventListener("keydown", closeOnEsc);
    return () => {
      document.removeEventListener("mousedown", closeOnOutside);
      document.removeEventListener("keydown", closeOnEsc);
    };
  }, [closeModal]);

  const handleResend = async (e: React.FormEvent) => {
    e.preventDefault();
    setResendMsg("");

    const endpoint =
      modalType === "recover" ? "/send-recovery" : "/resend-confirmation";

    try {
      const res = await api.post(endpoint, { email: formEmail });
      setResendMsg(res.data.message);
      setModalStep("success");

      setTimeout(() => {
        toast.success(
          modalType === "recover"
            ? "¡Correo de recuperación enviado!"
            : "¡Correo reenviado!, Revisa tu bandeja..."
        );
        setShowModal(false);
        setResendMsg("");
        setFormEmail("");
      }, 5000);
    } catch (err) {
      const error = err as AxiosError<{ message: string }>;
      const msg = error.response?.data?.message;

      if (msg === "La cuenta ya está confirmada") {
        toast.info("La cuenta ya ha sido confirmada.");
        setShowModal(false);
      } else {
        setResendMsg("Error al reenviar el enlace.");
      }
    }
  };

  if (!isOpen) return null;

  const isDesktop = typeof window !== "undefined" && window.innerWidth >= 768;

  return (
    <>
      <motion.div
        className="fixed inset-0 bg-black/40 backdrop-blur-sm z-[999] flex items-center justify-center p-4 overflow-y-auto"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
      >
        <button
          onClick={closeModal}
          className="absolute top-4 right-4 z-[1000] text-white text-2xl bg-black/50 hover:bg-black/70 p-2 rounded-full"
        >
          <FaTimes />
        </button>

        <motion.div
          ref={modalRef}
          initial={{ scale: 0.95, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          exit={{ scale: 0.9, opacity: 0 }}
          transition={{ duration: 0.3 }}
          className={`bg-bgLight dark:bg-gray-900 text-gray-800 dark:text-gray-100 backdrop-blur-md rounded-3xl shadow-2xl shadow-bgLight w-full max-w-4xl flex flex-col md:flex-row overflow-hidden transition-all ease-in-out duration-700 ${
            isLogin ? "md:flex-row-reverse" : "md:flex-row"
          }`}
        >
          {isDesktop && (
            <AnimatePresence mode="wait">
              <motion.div
                key={view}
                initial={{ x: isLogin ? 300 : -300, opacity: 0 }}
                animate={{ x: 0, opacity: 1 }}
                exit={{ x: isLogin ? -300 : 300, opacity: 0 }}
                transition={{ duration: 0.5, ease: "easeInOut" }}
                className="hidden md:flex w-full md:w-1/2 p-6 md:p-8 flex-col justify-center text-center space-y-6 bg-white dark:bg-gray-800"
              >
                <AuthSidePanel
                  title={messages[view].sideTitle}
                  description={messages[view].sideDescription}
                  buttonText={messages[view].sideButton}
                  onToggle={toggleView}
                />
              </motion.div>
            </AnimatePresence>
          )}

          <AnimatePresence mode="wait">
            <motion.div
              key={`${view}-form`}
              initial={{ x: isLogin ? -300 : 300, opacity: 0 }}
              animate={{ x: 0, opacity: 1 }}
              exit={{ x: isLogin ? 300 : -300, opacity: 0 }}
              transition={{ duration: 0.5, ease: "easeInOut" }}
              className={`w-full md:w-1/2 p-6 md:p-8 bg-gray-50 dark:bg-gray-900 flex flex-col justify-center`}
            >
              <h2 className="text-3xl font-bold text-center mb-2 bg-gradient-to-r from-indigo-500 via-purple-500 to-pink-500 text-transparent bg-clip-text">
                {messages[view].title}
              </h2>
              <p className="text-center text-sm text-gray-600 dark:text-gray-300 mb-4">
                {messages[view].description}
              </p>

              <AuthForm
                modalStep={modalStep}
                showModal={showModal}
                modalType={modalType}
                setFormEmail={setFormEmail}
                setModalStep={setModalStep}
                setShowModal={setShowModal}
                setModalType={setModalType}
              />
            </motion.div>
          </AnimatePresence>
        </motion.div>
      </motion.div>

      <AuthResendModal
        modalStep={modalStep}
        showModal={showModal}
        email={formEmail}
        resendMsg={resendMsg}
        onClose={() => setShowModal(false)}
        onEmailChange={setFormEmail}
        onResend={handleResend}
        type={modalType}
      />
    </>
  );
}

```

## frontend\src\components\auth\AuthResendModal.tsx

```tsx
import { useState, FormEvent } from "react";
import { FaCheckCircle, FaInfoCircle } from "react-icons/fa";

interface Props {
  showModal: boolean;
  modalStep: "notice" | "form" | "success";
  email: string;
  resendMsg: string;
  onClose: () => void;
  onEmailChange: (email: string) => void;
  onResend: (e: React.FormEvent) => void;
  type: "confirm" | "recover";
}

export default function AuthResendModal({
  showModal,
  modalStep,
  email,
  resendMsg,
  onClose,
  onEmailChange,
  onResend,
  type,
}: Props) {

  const [isSending, setIsSending] = useState(false);

  const handleLocalResend = async (e: FormEvent) => {
    if (isSending) return;
    setIsSending(true);
    await onResend(e);
    setIsSending(false);
  };

  if (!showModal) return null;

  const isRecover = type === "recover";
  const title = isRecover ? "Recuperar Contraseña" : "Verifica tu cuenta";
  const formTitle = isRecover ? "¿Necesitas un nuevo enlace?" : "Reenviar Enlace";
  const formDescription = isRecover ? "Ingresa tu correo para recuperar tu contraseña." : "Verificación de usuario expirada, ingresa tu correo para recibir un nuevo enlace de confirmación:";
  const successMsg =
    resendMsg ||
    (isRecover
      ? "Enlace de recuperación enviado con éxito. Revisa tu correo."
      : "Enlace de confirmación reenviado con éxito. Revisa tu correo.");

  return (
    <div
      className="fixed inset-0 bg-black/40 z-[1000] flex items-center justify-center"
      onMouseDown={onClose}
    >
      <div
        className="bg-white rounded-lg shadow-lg p-6 w-full max-w-md relative text-center"
        onMouseDown={(e) => e.stopPropagation()} // Esto evita que el click cierre el modal
      >
        <button
          onClick={onClose}
          className="absolute top-2 right-3 text-gray-500 hover:text-red-500 text-lg font-bold"
        >
          &times;
        </button>

        {modalStep === "notice" && (
          <>
            <FaInfoCircle className="text-yellow-500 text-4xl mx-auto mb-2" />
            <h2 className="text-xl font-bold mb-2 text-sky-600">{title}</h2>
            <p className="text-sm text-gray-600 mb-4">
              {isRecover
                ? "Ingresa tu correo para recuperar tu contraseña."
                : "Aún no has confirmado tu cuenta. Revisa tu correo para activarla."}
            </p>
          </>
        )}

        {modalStep === "form" && (
          <>
            <h2 className="text-xl font-bold mb-2 text-sky-600">{formTitle}</h2>
            <p className="text-sm text-gray-600 mb-4">{formDescription}</p>
            <form onSubmit={handleLocalResend} className="space-y-4">
              <input
                type="email"
                placeholder="Tu correo"
                className="w-full px-4 py-2 border rounded-md"
                value={email}
                onChange={(e) => onEmailChange(e.target.value)}
                required
              />
              <button
                type="submit"
                disabled={isSending}
                className={`w-full bg-sky-600 text-white py-2 rounded hover:bg-sky-700 transition ${
                  isSending ? "opacity-50 cursor-not-allowed" : ""
                }`}
              >
                {isSending ? "Enviando..." : "Reenviar enlace"}
              </button>
              {resendMsg && <p className="text-sm text-red-500">{resendMsg}</p>}
            </form>
          </>
        )}

        {modalStep === "success" && (
          <>
            <FaCheckCircle className="text-green-500 text-4xl mx-auto mb-2" />
            <p className="text-green-600 text-sm font-medium">{successMsg}</p>
            <p className="text-sm text-gray-500 mt-2">
              Serás redirigido al login...
            </p>
          </>
        )}
      </div>
    </div>
  );
}

```

## frontend\src\components\auth\AuthSidePanel.tsx

```tsx
// src/components/auth/AuthSidePanel.tsx
import { motion } from "framer-motion";

interface Props {
  title: string;
  description: string;
  buttonText: string;
  onToggle: () => void;
}

export default function AuthSidePanel({ title, description, buttonText, onToggle }: Props) {
  return (
    <motion.div
      key={title}
      initial={{ x: 300, opacity: 0 }}
      animate={{ x: 0, opacity: 1 }}
      exit={{ x: -300, opacity: 0 }}
      transition={{ duration: 0.5, ease: "easeInOut" }}
      className="w-full md:w-fit p-6 md:p-8 flex flex-col justify-center text-center space-y-6 bg-white"
    >
      <h2 className="text-3xl md:text-4xl font-bold bg-gradient-to-r from-indigo-500 via-purple-500 to-pink-500 text-transparent bg-clip-text">
        {title}
      </h2>
      <p className="text-gray-600">{description}</p>
      <button
        onClick={onToggle}
        className="px-6 py-3 rounded-full bg-gradient-to-r from-indigo-500 via-purple-500 to-pink-500 text-white font-semibold hover:scale-105 transition-all"
      >
        {buttonText}
      </button>
    </motion.div>
  );
}

```

## frontend\src\components\common\Alert.tsx

```tsx
import React from "react";
import classNames from "classnames";
import {
  FaCheckCircle,
  FaExclamationTriangle,
  FaInfoCircle,
  FaTimesCircle,
} from "react-icons/fa";

interface AlertProps {
  type?: "success" | "error" | "warning" | "info";
  message: string;
  className?: string;
}

const iconMap = {
  success: <FaCheckCircle className="text-green-600 text-xl mr-2" />,
  error: <FaTimesCircle className="text-red-600 text-xl mr-2" />,
  warning: <FaExclamationTriangle className="text-yellow-600 text-xl mr-2" />,
  info: <FaInfoCircle className="text-blue-600 text-xl mr-2" />,
};

const Alert: React.FC<AlertProps> = ({
  type = "info",
  message,
  className = "",
}) => {
  const baseStyles =
    "flex items-start gap-2 px-4 py-3 rounded-md shadow-sm text-sm font-medium";

  const typeStyles = {
    success: "bg-green-100 text-green-800 dark:bg-green-900/20 dark:text-green-200",
    error: "bg-red-100 text-red-800 dark:bg-red-900/20 dark:text-red-200",
    warning: "bg-yellow-100 text-yellow-800 dark:bg-yellow-900/20 dark:text-yellow-200",
    info: "bg-blue-100 text-blue-800 dark:bg-blue-900/20 dark:text-blue-200",
  };

  return (
    <div className={classNames(baseStyles, typeStyles[type], className)}>
      {iconMap[type]}
      <span>{message}</span>
    </div>
  );
};

export default Alert;

```

## frontend\src\components\common\Avatar.tsx

```tsx
import React from "react";
import classNames from "classnames";

interface AvatarProps {
  name?: string;
  imageUrl?: string;
  size?: "sm" | "md" | "lg";
  status?: "online" | "offline" | "busy";
  className?: string;
}

const sizeClasses = {
  sm: "w-8 h-8 text-sm",
  md: "w-10 h-10 text-base",
  lg: "w-14 h-14 text-lg",
};

const statusColors = {
  online: "bg-green-500",
  offline: "bg-gray-400",
  busy: "bg-red-500",
};

export const Avatar: React.FC<AvatarProps> = ({
  name,
  imageUrl,
  size = "md",
  status,
  className = "",
}) => {
  const initials = name
    ? name
        .split(" ")
        .map((n) => n[0])
        .join("")
        .toUpperCase()
        .slice(0, 2)
    : "?";

  return (
    <div className={classNames("relative inline-block", className)}>
      <div
        className={classNames(
          "rounded-full bg-gray-200 dark:bg-gray-700 flex items-center justify-center overflow-hidden text-white font-semibold",
          sizeClasses[size]
        )}
      >
        {imageUrl ? (
          <img
            src={imageUrl}
            alt={name}
            className="w-full h-full object-cover"
          />
        ) : (
          <span>{initials}</span>
        )}
      </div>

      {status && (
        <span
          className={classNames(
            "absolute bottom-0 right-0 w-3 h-3 rounded-full ring-2 ring-white dark:ring-gray-900",
            statusColors[status]
          )}
        />
      )}
    </div>
  );
};

export default Avatar;

```

## frontend\src\components\common\Breadcrumb.tsx

```tsx
import React from "react";
import { Link } from "react-router-dom";
import { FaChevronRight } from "react-icons/fa";

interface BreadcrumbItem {
  label: string;
  path?: string;
  isCurrent?: boolean;
}

interface BreadcrumbProps {
  items: BreadcrumbItem[];
  className?: string;
}

const Breadcrumb: React.FC<BreadcrumbProps> = ({ items, className = "" }) => {
  return (
    <nav
      className={`text-sm text-gray-600 dark:text-gray-300 ${className}`}
      aria-label="breadcrumb"
    >
      <ol className="flex flex-wrap items-center space-x-2">
        {items.map((item, idx) => (
          <li key={idx} className="flex items-center">
            {item.path && !item.isCurrent ? (
              <Link
                to={item.path}
                className="hover:underline text-blue-600 dark:text-blue-400"
              >
                {item.label}
              </Link>
            ) : (
              <span className="font-semibold text-gray-900 dark:text-white">
                {item.label}
              </span>
            )}
            {idx < items.length - 1 && (
              <FaChevronRight className="mx-2 text-xs text-gray-400" />
            )}
          </li>
        ))}
      </ol>
    </nav>
  );
};

export default Breadcrumb;

```

## frontend\src\components\common\Button.tsx

```tsx
import React from "react";
import { Spinner } from "./Spinner";
import classNames from "classnames";

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: "primary" | "secondary" | "danger" | "outline";
  isLoading?: boolean;
  fullWidth?: boolean;
}

const Button: React.FC<ButtonProps> = ({
  children,
  variant = "primary",
  isLoading = false,
  fullWidth = false,
  className,
  ...props
}) => {
  const baseStyles =
    "inline-flex items-center justify-center px-4 py-2 rounded-md font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-offset-2";

  const variantStyles = {
    primary:
      "bg-blue-600 text-white hover:bg-blue-700 focus:ring-blue-500 dark:bg-blue-500 dark:hover:bg-blue-600",
    secondary:
      "bg-gray-200 text-gray-900 hover:bg-gray-300 focus:ring-gray-400 dark:bg-gray-700 dark:text-white dark:hover:bg-gray-600",
    danger:
      "bg-red-600 text-white hover:bg-red-700 focus:ring-red-500 dark:bg-red-500 dark:hover:bg-red-600",
    outline:
      "border border-gray-300 text-gray-700 hover:bg-gray-100 focus:ring-gray-400 dark:border-gray-600 dark:text-white dark:hover:bg-gray-700",
  };

  const computedClasses = classNames(
    baseStyles,
    variantStyles[variant],
    {
      "w-full": fullWidth,
      "opacity-50 cursor-not-allowed": props.disabled || isLoading,
    },
    className
  );

  return (
    <button className={computedClasses} disabled={props.disabled || isLoading} {...props}>
      {isLoading && <Spinner className="mr-2 h-4 w-4 animate-spin" />}
      {children}
    </button>
  );
};

export default Button;

```

## frontend\src\components\common\Card.tsx

```tsx
import React from "react";
import classNames from "classnames";

interface CardProps extends React.HTMLAttributes<HTMLDivElement> {
  title?: string;
  subtitle?: string;
  footer?: React.ReactNode;
  children: React.ReactNode;
  shadow?: boolean;
  hoverable?: boolean;
  rounded?: boolean;
  bordered?: boolean;
}

const Card: React.FC<CardProps> = ({
  title,
  subtitle,
  footer,
  children,
  className,
  shadow = true,
  hoverable = false,
  rounded = true,
  bordered = false,
  ...props
}) => {
  return (
    <div
      className={classNames(
        "bg-white dark:bg-bgDark text-textDark dark:text-textLight transition-all duration-300",
        {
          "shadow-md": shadow,
          "hover:shadow-lg hover:scale-[1.01] transform transition-all":
            hoverable,
          "rounded-lg": rounded,
          "border border-gray-200 dark:border-gray-700": bordered,
        },
        className
      )}
      {...props}
    >
      {(title || subtitle) && (
        <div className="p-4 border-b border-gray-100 dark:border-gray-700">
          {title && <h2 className="text-lg font-semibold">{title}</h2>}
          {subtitle && (
            <p className="text-sm text-gray-500 dark:text-gray-400">
              {subtitle}
            </p>
          )}
        </div>
      )}

      <div className="p-4">{children}</div>

      {footer && (
        <div className="px-4 py-3 border-t border-gray-100 dark:border-gray-700">
          {footer}
        </div>
      )}
    </div>
  );
};

export default Card;

```

## frontend\src\components\common\CardGrid.tsx

```tsx
import React from "react";
import classNames from "classnames";

interface CardGridProps {
  children: React.ReactNode;
  columns?: number; // número de columnas base (por defecto 1 en móvil, luego responsive)
  gap?: string; // espacio entre tarjetas (por defecto 'gap-6')
  className?: string;
}

const CardGrid: React.FC<CardGridProps> = ({
  children,
  columns = 1,
  gap = "gap-6",
  className = "",
}) => {
  const gridCols = {
    1: "grid-cols-1",
    2: "sm:grid-cols-2",
    3: "sm:grid-cols-2 md:grid-cols-3",
    4: "sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4",
  };

  return (
    <div
      className={classNames(
        "grid w-full",
        gap,
        gridCols[columns as keyof typeof gridCols],
        className
      )}
    >
      {children}
    </div>
  );
};

export default CardGrid;

```

## frontend\src\components\common\CustomToast.tsx

```tsx
import { toast, ToastOptions } from "react-toastify";

const baseOptions: ToastOptions = {
  position: "top-right",
  autoClose: 4000,
  pauseOnHover: true,
  draggable: true,
  closeOnClick: true,
};

export const showSuccess = (message: string, options?: ToastOptions) => {
  toast.success(message, { ...baseOptions, ...options });
};

export const showError = (message: string, options?: ToastOptions) => {
  toast.error(message, { ...baseOptions, ...options });
};

export const showInfo = (message: string, options?: ToastOptions) => {
  toast.info(message, { ...baseOptions, ...options });
};

export const showWarning = (message: string, options?: ToastOptions) => {
  toast.warn(message, { ...baseOptions, ...options });
};

```

## frontend\src\components\common\DropdownMenu.tsx

```tsx
import { Link } from "react-router-dom";
import { AnimatePresence, motion } from "framer-motion";

interface Props {
  visible: boolean;
  menuKey: string;
  labels: string[];
  onLinkClick: () => void;
}

export const DropdownMenu: React.FC<Props> = ({
  visible,
  menuKey,
  labels,
  onLinkClick,
}) => {
  return (
    <AnimatePresence>
      {visible && (
        <motion.div
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          exit={{ opacity: 0, scale: 0.95 }}
          transition={{ duration: 0.2, ease: "easeOut" }}
          className="absolute left-1/2 transform -translate-x-1/2 top-full mt-2 w-56 max-h-[70vh] overflow-y-auto backdrop-blur-md bg-bgLight/30 dark:bg-bgDark/40 text-textDark dark:text-textLight rounded-xl shadow-xl ring-1 ring-bgLight/25 z-50"
        >
          {labels.map((label, idx) => (
            <Link
              key={idx}
              to={`/${menuKey}#${label.toLowerCase().replace(/\s+/g, "-")}`}
              onClick={onLinkClick}
              className="block px-4 py-2 text-sm font-semibold hover:bg-accent2/80 hover:text-white dark:hover:bg-bgLight/80 dark:hover:text-textDark/90 transition-all duration-200"
            >
              {label}
            </Link>
          ))}
        </motion.div>
      )}
    </AnimatePresence>
  );
};

```

## frontend\src\components\common\FormField.tsx

```tsx
import React from "react";
import classNames from "classnames";

interface FormFieldProps {
  label: string;
  name: string;
  type?: string;
  value: string;
  onChange: (e: React.ChangeEvent<HTMLInputElement>) => void;
  placeholder?: string;
  icon?: React.ReactNode;
  error?: string;
  required?: boolean;
  disabled?: boolean;
  autoComplete?: string;
}

const FormField: React.FC<FormFieldProps> = ({
  label,
  name,
  type = "text",
  value,
  onChange,
  placeholder = "",
  icon,
  error,
  required = false,
  disabled = false,
  autoComplete,
}) => {
  return (
    <div className="mb-4">
      <label
        htmlFor={name}
        className="block text-sm font-medium text-gray-700 dark:text-gray-200 mb-1"
      >
        {label} {required && <span className="text-red-500">*</span>}
      </label>

      <div className="relative">
        {icon && (
          <div className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 pointer-events-none">
            {icon}
          </div>
        )}

        <input
          type={type}
          name={name}
          id={name}
          value={value}
          onChange={onChange}
          placeholder={placeholder}
          disabled={disabled}
          autoComplete={autoComplete}
          className={classNames(
            "w-full border rounded-md py-2 px-3 focus:outline-none focus:ring-2",
            {
              "pl-10": icon,
              "border-gray-300 focus:ring-blue-500":
                !error && !disabled,
              "border-red-500 focus:ring-red-500": error,
              "bg-gray-100 cursor-not-allowed": disabled,
              "dark:bg-gray-800 dark:text-white dark:border-gray-600": true,
            }
          )}
        />
      </div>

      {error && (
        <p className="text-red-500 text-sm mt-1 font-medium">{error}</p>
      )}
    </div>
  );
};

export default FormField;

```

## frontend\src\components\common\Input.tsx

```tsx
import React from "react";
import { twMerge } from "tailwind-merge";

interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  label?: string;
  error?: string;
  icon?: React.ReactNode;
  fullWidth?: boolean;
}

const Input: React.FC<InputProps> = ({
  label,
  error,
  icon,
  fullWidth = true,
  className,
  ...props
}) => {
  return (
    <div className={twMerge("mb-4", fullWidth ? "w-full" : "", className)}>
      {label && (
        <label className="block text-sm font-medium text-gray-700 dark:text-textLight mb-1">
          {label}
        </label>
      )}

      <div className="relative">
        {icon && (
          <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-gray-500 dark:text-gray-300">
            {icon}
          </div>
        )}
        <input
          {...props}
          className={twMerge(
            "appearance-none block w-full px-3 py-2 border rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent text-sm",
            icon ? "pl-10" : "",
            error
              ? "border-red-500 focus:ring-red-500"
              : "border-gray-300 dark:border-gray-600 dark:bg-bgDark dark:text-textLight",
            props.disabled ? "opacity-50 cursor-not-allowed" : ""
          )}
        />
      </div>

      {error && (
        <p className="text-sm text-red-600 mt-1 font-medium">{error}</p>
      )}
    </div>
  );
};

export default Input;

```

## frontend\src\components\common\InputWithLabel.tsx

```tsx
import React from "react";

interface Props extends React.InputHTMLAttributes<HTMLInputElement> {
  label: string;
  name: string;
  error?: string;
}

const InputWithLabel: React.FC<Props> = ({
  label,
  name,
  error,
  ...props
}) => {
  return (
    <div className="mb-4">
      <label
        htmlFor={name}
        className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-1 flex items-center gap-2"
      >
        {label}
      </label>

      <input
        id={name}
        name={name}
        className="input-style outline-none dark:bg-gray-900 dark:text-white dark:border-gray-700"
        {...props}
      />

      {error && <p className="text-red-500 text-sm mt-1">{error}</p>}
    </div>
  );
};

export default InputWithLabel;

```

## frontend\src\components\common\Modal.tsx

```tsx
import React from "react";
import { motion, AnimatePresence } from "framer-motion";
import { FaTimes } from "react-icons/fa";

interface ModalProps {
  isOpen: boolean;
  onClose: () => void;
  title?: string;
  children: React.ReactNode;
  size?: "sm" | "md" | "lg";
  hideCloseButton?: boolean;
}

const sizeClasses = {
  sm: "max-w-sm",
  md: "max-w-md",
  lg: "max-w-2xl",
};

const Modal: React.FC<ModalProps> = ({
  isOpen,
  onClose,
  title,
  children,
  size = "md",
  hideCloseButton = false,
}) => {
  return (
    <AnimatePresence>
      {isOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <motion.div
            initial={{ opacity: 0, y: -30 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: 20 }}
            transition={{ duration: 0.3 }}
            className={`bg-white dark:bg-bgDark text-textDark dark:text-textLight rounded-lg shadow-lg w-full ${sizeClasses[size]} relative px-6 py-5`}
          >
            {!hideCloseButton && (
              <button
                className="absolute top-3 right-4 text-gray-400 hover:text-red-500 transition"
                onClick={onClose}
                aria-label="Cerrar modal"
              >
                <FaTimes />
              </button>
            )}

            {title && (
              <h2 className="text-xl font-semibold mb-4 text-center">
                {title}
              </h2>
            )}

            <div>{children}</div>
          </motion.div>
        </div>
      )}
    </AnimatePresence>
  );
};

export default Modal;

```

## frontend\src\components\common\PasswordField.tsx

```tsx
import React, { useState } from "react";
import classNames from "classnames";
import { FaEye, FaEyeSlash } from "react-icons/fa";

interface PasswordFieldProps {
  label: string;
  name: string;
  value: string;
  onChange: (e: React.ChangeEvent<HTMLInputElement>) => void;
  placeholder?: string;
  error?: string;
  required?: boolean;
  autoComplete?: string;
}

const PasswordField: React.FC<PasswordFieldProps> = ({
  label,
  name,
  value,
  onChange,
  placeholder = "••••••••",
  error,
  required = false,
  autoComplete = "current-password",
}) => {
  const [showPassword, setShowPassword] = useState(false);

  return (
    <div className="mb-4">
      <label
        htmlFor={name}
        className="block text-sm font-medium text-gray-700 dark:text-gray-200 mb-1"
      >
        {label} {required && <span className="text-red-500">*</span>}
      </label>

      <div className="relative">
        <input
          id={name}
          name={name}
          type={showPassword ? "text" : "password"}
          value={value}
          onChange={onChange}
          placeholder={placeholder}
          autoComplete={autoComplete}
          className={classNames(
            "w-full border rounded-md py-2 px-3 pr-10 focus:outline-none focus:ring-2",
            {
              "border-gray-300 focus:ring-blue-500": !error,
              "border-red-500 focus:ring-red-500": !!error,
              "dark:bg-gray-800 dark:text-white dark:border-gray-600": true,
            }
          )}
        />

        <button
          type="button"
          onClick={() => setShowPassword((prev) => !prev)}
          className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-500 hover:text-gray-700 dark:text-gray-300"
          aria-label="Mostrar u ocultar contraseña"
        >
          {showPassword ? <FaEyeSlash /> : <FaEye />}
        </button>
      </div>

      {error && (
        <p className="text-red-500 text-sm mt-1 font-medium">{error}</p>
      )}
    </div>
  );
};

export default PasswordField;

```

## frontend\src\components\common\PasswordWithStrengthInputForm.tsx

```tsx
import { useState } from "react";
import { FaEye, FaEyeSlash, FaInfoCircle } from "react-icons/fa";
import {
  getPasswordScore,
  getStrengthLabel,
} from "../../utils/validationHelpersForm";

interface Props {
  value: string;
  onChange: (e: React.ChangeEvent<HTMLInputElement>) => void;
  error?: string;
  showTooltip?: boolean;
  showStrengthBar?: boolean;
  autoFocus?: boolean;
  name?: string;
  placeholder?: string;
}

export default function PasswordWithStrengthInput({
  value,
  onChange,
  error,
  showTooltip = true,
  showStrengthBar = true,
  autoFocus = false,
  name = "password",
  placeholder = "Password",
}: Props) {
  const [showPassword, setShowPassword] = useState(false);
  const score = getPasswordScore(value);
  const label = getStrengthLabel(score);

  return (
    <div className="relative mb-4">
      <div className="absolute flex justify-start mb-1 top-[-14px] left-[4px]">
        {showTooltip && (
          <div className="relative group inline-block">
            <FaInfoCircle
              className="text-blue-500 dark:text-blue-400 cursor-pointer p-0.5"
              tabIndex={0} // para accesibilidad en teclado
            />
            <div className="absolute z-30 top-full right-[-260px] mt-2 w-72 md:w-64 text-xs bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 text-gray-800 dark:text-gray-200 p-2 rounded shadow-md opacity-0 invisible group-hover:opacity-100 group-hover:visible group-focus-within:opacity-100 group-focus-within:visible transition-opacity duration-200 pointer-events-none">
              Usa mínimo 8 caracteres, una mayúscula, un número y un símbolo especial. No uses tu correo ni contraseñas anteriores.
            </div>
          </div>
        )}
      </div>

      <input
        type={showPassword ? "text" : "password"}
        name={name}
        value={value}
        onChange={onChange}
        placeholder={placeholder}
        autoFocus={autoFocus}
        className="input-style pr-10 outline-none dark:bg-gray-900 dark:text-white dark:border-gray-700"
      />

      <button
        type="button"
        onClick={() => setShowPassword(!showPassword)}
        className="absolute right-3 top-[20px] text-gray-600 dark:text-gray-300 hover:text-blue-600 dark:hover:text-blue-400 transition"
        tabIndex={-1}
      >
        {showPassword ? <FaEyeSlash /> : <FaEye />}
      </button>

      {error && <p className="text-red-500 text-sm mt-1">{error}</p>}

      {showStrengthBar && (
        <div className="mt-2">
          <div className="flex gap-1">
            {[...Array(4)].map((_, i) => (
              <div
                key={i}
                className={`h-2 flex-1 rounded ${
                  i < score ? label.bar : "bg-gray-200 dark:bg-gray-600"
                }`}
              />
            ))}
          </div>
          {score > 0 && (
            <p className={`text-sm mt-1 ${label.color}`}>Fuerza: {label.text}</p>
          )}
        </div>
      )}
    </div>
  );
}

```

## frontend\src\components\common\Spinner.tsx

```tsx
import React from "react";

interface SpinnerProps {
  size?: number;
  className?: string;
  color?: string;
}

export const Spinner: React.FC<SpinnerProps> = ({
  size = 24,
  className = "",
  color = "var(--color-primary)", // Puedes usar cualquier variable de tu theme
}) => {
  return (
    <svg
      className={`animate-spin ${className}`}
      width={size}
      height={size}
      viewBox="0 0 24 24"
      style={{ color }}
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
    >
      <circle
        className="opacity-25"
        cx="12"
        cy="12"
        r="10"
        stroke="currentColor"
        strokeWidth="4"
      ></circle>
      <path
        className="opacity-75"
        fill="currentColor"
        d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"
      ></path>
    </svg>
  );
};

```

## frontend\src\components\common\ToastNotification.tsx

```tsx
import { ToastContainer } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";

const ToastNotification = () => {
  return (
    <ToastContainer
      position="top-right"
      autoClose={5000}
      hideProgressBar={false}
      newestOnTop={false}
      closeOnClick
      rtl={false}
      pauseOnFocusLoss
      draggable
      pauseOnHover
      theme="colored" // Puedes cambiar a "light" o "dark"
      toastClassName={() =>
        "bg-white dark:bg-bgDark text-textDark dark:text-textLight rounded shadow-md px-4 py-3"
      }
      className="text-sm font-medium"
      progressClassName={() => "bg-[var(--color-primary)]"}
    />
  );
};

export default ToastNotification;

```

## frontend\src\components\NavMenu.tsx

```tsx
import { Link } from "react-router-dom";
import { AnimatePresence, motion } from "framer-motion";
import {
  ChevronDownIcon,
  PlusIcon,
  MinusIcon,
} from "@heroicons/react/20/solid";
import { useState, useRef, useEffect } from "react";

interface Props {
  isLoggedIn: boolean;
  userRole: string;
  mobileMenuOpen: boolean;
  handleLinkClick: () => void;
}

export const NavMenu: React.FC<Props> = ({
  isLoggedIn,
  userRole,
  mobileMenuOpen,
  handleLinkClick,
}) => {
  const [hoveredMenu, setHoveredMenu] = useState<string | null>(null);
  const menuRef = useRef<HTMLDivElement>(null);

  const menus = [
    { label: "Inicio", to: "/" },
    { label: "Precios", to: "/precios" },
  ];

  const dropdowns = {
    mas: ["Galeria", "Horarios", "Eventos", "Blog", "Reserva"],
    servicios: [
      "Piscinas y Tobogán",
      "Bosque Perdido de los Dinosaurios",
      "Botes y Juegos de Mesa",
      "Zona VIP",
      "Restaurantes",
    ],
  };

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (
        mobileMenuOpen &&
        menuRef.current &&
        !menuRef.current.contains(event.target as Node)
      ) {
        setHoveredMenu(null);
      }
    };

    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, [mobileMenuOpen]);

  return (
    <div
      ref={menuRef}
      className={`flex transition-all duration-300 ${
        mobileMenuOpen
          ? "flex-col items-center space-y-2 mt-4 text-center"
          : "flex-row items-center gap-6"
      } w-full md:w-auto justify-center`}
    >
      {/* Enlaces simples */}
      {menus.map((item, idx) => (
        <Link
          key={idx}
          to={item.to}
          onClick={handleLinkClick}
          className="hover:text-accent1 font-medium transition-colors duration-200"
        >
          {item.label}
        </Link>
      ))}

      {/* Menús desplegables */}
      {(Object.keys(dropdowns) as Array<keyof typeof dropdowns>).map((key) => (
        <div
          key={key}
          className={`relative group ${mobileMenuOpen ? "w-full" : "w-auto"}`}
          onMouseEnter={() => !mobileMenuOpen && setHoveredMenu(key)}
          onMouseLeave={() => !mobileMenuOpen && setHoveredMenu(null)}
        >
          <button
            onClick={() =>
              mobileMenuOpen
                ? setHoveredMenu((prev) => (prev === key ? null : key))
                : null
            }
            className="flex items-center justify-between gap-1 w-full font-medium capitalize hover:text-accent1 transition duration-200"
          >
            {key}
            {mobileMenuOpen ? (
              hoveredMenu === key ? (
                <MinusIcon className="h-5 w-5 transition-all duration-300 text-accent1" />
              ) : (
                <PlusIcon className="h-5 w-5 transition-all duration-300" />
              )
            ) : (
              <motion.div
                animate={{
                  rotate: hoveredMenu === key ? 180 : 0,
                }}
                style={{
                  color:
                    hoveredMenu === key
                      ? "var(--color-accent1)"
                      : "var(--color-textLight)",
                }}
                transition={{ duration: 0.3 }}
              >
                <ChevronDownIcon className="h-5 w-5 text-current transition-all duration-300" />
              </motion.div>
            )}
          </button>

          <AnimatePresence initial={false}>
            {hoveredMenu === key && (
              <motion.div
                key={key}
                initial={{ height: 0, opacity: 0 }}
                animate={{ height: "auto", opacity: 1 }}
                exit={{ height: 0, opacity: 0 }}
                transition={{ duration: 0.3, ease: "easeInOut" }}
                className={`overflow-hidden ${
                  mobileMenuOpen
                    ? "w-full mt-1"
                    : "absolute left-1/2 -translate-x-1/2 top-full mt-2 w-56"
                } backdrop-blur-md bg-bgLight/30 dark:bg-bgDark/40 text-textDark dark:text-textLight rounded-xl shadow-xl ring-1 ring-bgLight/25 z-50`}
              >
                {dropdowns[key].map((label, idx) => (
                  <Link
                    key={idx}
                    to={`/${key}#${label.toLowerCase().replace(/\s+/g, "-")}`}
                    onClick={handleLinkClick}
                    className="block px-4 py-2 text-sm font-semibold hover:bg-accent2/80 hover:text-textLight/90 dark:hover:bg-bgLight/80 dark:hover:text-textDark/90 transition-all duration-200"
                  >
                    {label}
                  </Link>
                ))}
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      ))}

      {/* Links para cliente logueado */}
      {isLoggedIn && userRole === "client" && (
        <>
          <Link
            to="/compras"
            onClick={handleLinkClick}
            className="hover:text-accent1 transition font-medium"
          >
            Mis Compras
          </Link>
          <Link
            to="/perfil"
            onClick={handleLinkClick}
            className="hover:text-accent1 transition font-medium"
          >
            Mi Perfil
          </Link>
        </>
      )}
    </div>
  );
};

```

## frontend\src\components\RouteModalHandler.tsx

```tsx
// src/components/RouteModalHandler.tsx
import { useEffect } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { useAuthModal } from "../store/useAuthModal";

const RouteModalHandler = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const { openModal, isOpen } = useAuthModal();

  // Abre el modal cuando entra a /login o /register
  useEffect(() => {
    if (location.pathname === "/login") {
      openModal("login");
    } else if (location.pathname === "/register") {
      openModal("register");
    }
  }, [location.pathname, openModal]);

  // Si se cierra el modal estando en /login o /register, redirige al home
  useEffect(() => {
    if (
      !isOpen &&
      (location.pathname === "/login" || location.pathname === "/register")
    ) {
      navigate("/");
    }
  }, [isOpen, location.pathname, navigate]);

  return null;
};

export default RouteModalHandler;

```

## frontend\src\components\ThemeToggle.tsx

```tsx
import { useTheme } from '../hooks/useTheme';
import { FaSun, FaMoon } from 'react-icons/fa';

export const ThemeToggle = () => {
  const { darkMode, toggleDarkMode } = useTheme();

  return (
    <button
      onClick={toggleDarkMode}
      className="p-2 rounded-lg bg-gray-200 dark:bg-gray-700 transition-colors"
      aria-label={darkMode ? 'Activar modo claro' : 'Activar modo oscuro'}
    >
      {darkMode ? <FaSun className="text-yellow-400" /> : <FaMoon className="text-gray-700" />}
    </button>
  );
};

```

## frontend\src\context\AuthContext.tsx

```tsx
// AuthContext.tsx
import { createContext } from 'react';
export const AuthContext = createContext(null);
```

## frontend\src\context\ThemeContext.tsx

```tsx
import { createContext } from 'react';

// Definir tipos
export interface ThemeContextType {
  darkMode: boolean;
  toggleDarkMode: () => void;
}

// Crear y exportar el contexto
export const ThemeContext = createContext<ThemeContextType>({
  darkMode: false,
  toggleDarkMode: () => {},
});

```

## frontend\src\context\ThemeProvider.tsx

```tsx
import { useState, useEffect, ReactNode } from 'react';
import { ThemeContext } from './ThemeContext';

interface ThemeProviderProps {
  children: ReactNode;
}

export function ThemeProvider({ children }: ThemeProviderProps) {
  const [darkMode, setDarkMode] = useState<boolean>(() => {
    const savedTheme = localStorage.getItem('theme');
    return savedTheme === 'dark';
  });

  useEffect(() => {
    document.documentElement.classList.toggle('dark', darkMode);
    localStorage.setItem('theme', darkMode ? 'dark' : 'light');
  }, [darkMode]);

  const toggleDarkMode = () => {
    setDarkMode(prev => !prev);
  };

  return (
    <ThemeContext.Provider value={{ darkMode, toggleDarkMode }}>
      {children}
    </ThemeContext.Provider>
  );
}

```

## frontend\src\hooks\useAuth.ts

```typescript
import { useEffect, useState } from "react";

export const useAuth = () => {
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [userRole, setUserRole] = useState<"admin" | "client">("client");

  useEffect(() => {
    const token = localStorage.getItem("token");
    setIsLoggedIn(!!token);

    // Puedes agregar lógica real aquí con JWT decode, etc.
    if (token) {
      const payload = JSON.parse(atob(token.split(".")[1]));
      setUserRole(payload.role || "client");
    }
  }, []);

  const logout = () => {
    localStorage.removeItem("token");
    window.location.href = "/login";
  };

  return { isLoggedIn, userRole, logout };
};

```

## frontend\src\hooks\useTheme.ts

```typescript
import { useContext } from 'react';
import { ThemeContext } from '../context/ThemeContext';

export const useTheme = () => {
  return useContext(ThemeContext);
};
```

## frontend\src\index.css

```css
@import "tailwindcss";

@layer theme, base, components, utilities;

/* Ignorar alertas de error, ya que es una versión reciente de TailwindCSS */
@custom-variant dark (&:where(.dark, .dark *));

@theme {
    --color-primary: #00b1e8;
    --color-secondary: #f26c1d;
    --color-hoverSecondary:#fc843d;
    --color-accent1: #ffda00;
    --color-accent2: #4c2882;
    --color-textDark: #333333;
    --color-textLight: #f5f5f5;
    --color-bgLight: #f5f5f5;
    --color-bgDark: #333333;
    --color-facebook: #1877f2;
    --color-instagram: #e1306c;
    --color-whatsapp: #25d366;
    --color-tiktok: #f5f5f5;
    --color-youtube: #ff0000;
}

.input-style {
    @apply mt-1 w-full px-4 py-2 border-2 border-gray-200 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent transition-all duration-300;
}
  
```

## frontend\src\layout\Container.tsx

```tsx
const Container = ({ children }: { children: React.ReactNode }) => {
    return <div className="max-w-7xl mx-auto px-4">{children}</div>;
  };
  
  export default Container;
  
```

## frontend\src\layout\DashboardLayout.tsx

```tsx
import Sidebar from "../layout/navigation/Sidebar";
import HeaderMobile from "../layout/navigation/HeaderMobile";
import { ReactNode, useState } from "react";
interface Props {
  children: ReactNode;
}

const DashboardLayout = ({ children }: Props) => {
  const [isSidebarOpen, setSidebarOpen] = useState(true);

  return (
    <div className="flex h-screen bg-bgLight dark:bg-bgDark transition-colors">
      <Sidebar isOpen={isSidebarOpen} />
      <div className="flex flex-col flex-1">
        <HeaderMobile onToggleSidebar={() => setSidebarOpen(!isSidebarOpen)} />
        <main className="flex-1 overflow-y-auto p-4">{children}</main>
      </div>
    </div>
  );
};

export default DashboardLayout;
```

## frontend\src\layout\navigation\Footer.tsx

```tsx
import {
    FaMapMarkerAlt,
    FaClock,
    FaFacebook,
    FaInstagram,
    FaWhatsapp,
    FaTiktok,
    FaYoutube,
  } from "react-icons/fa";
  import { Link } from "react-router-dom";
  
  const Footer = () => {
    return (
      <footer className="bg-accent2 text-white py-16 mt-8">
        <div className="container mx-auto px-4 grid grid-cols-1 md:grid-cols-4 gap-8 text-center md:text-left transition-all duration-300">
          {/* Logo + Descripción */}
          <div className="flex flex-col items-center md:items-start">
            <Link to="/" className="flex items-center gap-2">
              <img
                src="../../../public/ARP logo.png"
                alt="Logo de Aqua River Park"
                className="h-20 mb-4 drop-shadow-xl"
              />
            </Link>
            <p className="text-sm opacity-90 max-w-xs">
              Un parque acuático temático con diversión para toda la familia.
            </p>
          </div>
  
          {/* Enlaces rápidos */}
          <div>
            <h3 className="text-xl font-bold mb-4 text-accent1">Enlaces Rápidos</h3>
            <ul className="space-y-2">
              {[
                { href: "#inicio", text: "Inicio" },
                { href: "#atracciones", text: "Atracciones" },
                { href: "#horarios", text: "Horarios" },
                { href: "#promociones", text: "Promociones" },
              ].map((item, index) => (
                <li key={index}>
                  <a
                    href={item.href}
                    className="hover:text-primary transition-colors"
                  >
                    {item.text}
                  </a>
                </li>
              ))}
            </ul>
          </div>
  
          {/* Información de contacto */}
          <div>
            <h3 className="text-xl font-bold mb-4 text-accent1">Contacto</h3>
            <ul className="space-y-2 text-sm">
              <li className="flex items-center justify-center md:justify-start">
                <FaMapMarkerAlt className="mr-2 text-secondary" />
                Calle Principal 123, Ciudad
              </li>
              <li className="flex items-center justify-center md:justify-start">
                <FaClock className="mr-2 text-secondary" />
                9:00 AM - 5:00 PM
              </li>
            </ul>
          </div>
  
          {/* Redes Sociales */}
          <div>
            <h3 className="text-xl font-bold mb-4 text-accent1">Redes Sociales</h3>
            <div className="flex justify-center md:justify-start space-x-4">
              {[
                { icon: FaFacebook, color: "facebook", title: "Facebook" },
                { icon: FaInstagram, color: "instagram", title: "Instagram" },
                { icon: FaWhatsapp, color: "whatsapp", title: "Whatsapp" },
                { icon: FaTiktok, color: "tiktok", title: "TikTok" },
                { icon: FaYoutube, color: "youtube", title: "YouTube" },
              ].map(({ icon: Icon, color, title }, index) => (
                <a
                  key={index}
                  href="#"
                  className="transition-all transform hover:scale-110"
                  title={title}
                  style={{
                    color: `var(--color-${color})`,
                    textShadow: `0 0 6px var(--color-${color})`,
                  }}
                >
                  <Icon size={24} />
                </a>
              ))}
            </div>
          </div>
        </div>
  
        {/* Pie de página */}
        <div className="mt-10 text-center text-xs text-white/70">
          © {new Date().getFullYear()} Aqua River Park. Todos los derechos reservados.
        </div>
      </footer>
    );
  };
  
  export default Footer;
  
```

## frontend\src\layout\navigation\Header.tsx

```tsx
import { Link, useLocation, useNavigate } from "react-router-dom";
import { FaUserCircle, FaBars, FaTimes } from "react-icons/fa";
import { Menu, MenuButton, MenuItem } from "@headlessui/react";
import { AnimatePresence, motion } from "framer-motion";
import { ThemeToggle } from "../../components/ThemeToggle";
import { useAuth } from "../../hooks/useAuth";
import { useEffect, useState, useRef } from "react";
import { NavMenu } from "../../components/NavMenu";
import { useAuthModal } from "../../store/useAuthModal"; // <-- store Zustand

const Header: React.FC = () => {
  const { isLoggedIn, logout, userRole } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);
  const { openModal } = useAuthModal(); // <-- usar Zustand

  const dropdownItems = {
    client: [
      { label: "Perfil", path: "/perfil" },
      { label: "Ajustes", path: "/ajustes" },
      { label: "Compras", path: "/compras" },
    ],
    admin: [
      { label: "Dashboard", path: "/admin" },
      { label: "Perfil", path: "/perfil" },
      { label: "Ajustes", path: "/ajustes" },
    ],
  };

  useEffect(() => {
    setMobileMenuOpen(false);
  }, [location]);

  useEffect(() => {
    if (isLoggedIn && userRole === "admin") {
      navigate("/admin");
    }
  }, [isLoggedIn, userRole, navigate]);

  const handleLinkClick = () => setMobileMenuOpen(false);

  return (
    <header className="bg-primary dark:bg-bgDark text-white shadow-md sticky top-0 z-50 transition-colors duration-300 ease-in-out">
      <div className="max-w-[1400px] mx-auto px-4 md:px-8">
        <div className="flex items-center justify-between h-16 md:h-20">
          {/* Logo y Toggle */}
          <div className="flex items-center gap-3">
            <button
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              className="md:hidden text-2xl transition-transform hover:scale-110"
              aria-label="Abrir menú"
            >
              {mobileMenuOpen ? <FaTimes /> : <FaBars />}
            </button>

            <Link
              to="/"
              className="flex items-center gap-2 transition-transform hover:scale-105"
            >
              <img
                src="/ARP logo.png"
                alt="Logo"
                className="h-10 w-auto drop-shadow"
              />
              <span className="font-bold text-lg">Aqua River Park</span>
            </Link>
          </div>

          {/* Menú de navegación (desktop) */}
          <nav className="hidden md:flex items-center gap-6 justify-center">
            <NavMenu
              isLoggedIn={isLoggedIn}
              userRole={userRole}
              mobileMenuOpen={false}
              handleLinkClick={handleLinkClick}
            />
          </nav>

          {/* Iconos a la derecha */}
          <div className="flex items-center gap-4">
            <ThemeToggle />
            {isLoggedIn ? (
              <Menu as="div" className="relative">
                <MenuButton className="flex items-center transition-transform hover:scale-110">
                  <FaUserCircle className="text-3xl" />
                </MenuButton>
                <AnimatePresence>
                  <motion.div
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: 10 }}
                    transition={{ duration: 0.2 }}
                    className="absolute right-0 mt-2 w-48 bg-white dark:bg-bgDark rounded-md shadow-lg z-50 ring-1 ring-black/10 divide-y divide-gray-200 dark:divide-gray-700"
                  >
                    <div className="py-1">
                      {(dropdownItems[userRole] || []).map((item, idx) => (
                        <MenuItem key={idx}>
                          {({ active }) => (
                            <Link
                              to={item.path}
                              className={`block px-4 py-2 text-sm transition-all duration-200 ${
                                active
                                  ? "bg-gray-100 dark:bg-gray-700 text-primary"
                                  : "text-gray-700 dark:text-white"
                              }`}
                            >
                              {item.label}
                            </Link>
                          )}
                        </MenuItem>
                      ))}
                    </div>
                    <div className="py-1">
                      <MenuItem>
                        {({ active }) => (
                          <button
                            onClick={logout}
                            className={`block w-full text-left px-4 py-2 text-sm transition-all duration-200 ${
                              active
                                ? "bg-red-100 dark:bg-red-600 text-red-700"
                                : "text-red-500"
                            }`}
                          >
                            Cerrar sesión
                          </button>
                        )}
                      </MenuItem>
                    </div>
                  </motion.div>
                </AnimatePresence>
              </Menu>
            ) : (
              <>
                {/* Mobile icon */}
                <button
                  onClick={() => openModal("login")}
                  aria-label="Iniciar sesión"
                  className="md:hidden text-2xl hover:text-accent1 transition-transform"
                >
                  <FaUserCircle />
                </button>

                {/* Desktop button */}
                <button
                  onClick={() => openModal("login")}
                  className="hidden md:inline-block bg-secondary hover:bg-hoverSecondary px-4 py-2 rounded-md text-white transition-colors duration-300 text-sm"
                >
                  Iniciar sesión
                </button>
              </>
            )}
          </div>
        </div>
      </div>

      {/* Menú móvil deslizable */}
      <AnimatePresence>
        {mobileMenuOpen && (
          <motion.div
            ref={menuRef}
            initial={{ y: -20, opacity: 0 }}
            animate={{ y: 0, opacity: 1 }}
            exit={{ y: -20, opacity: 0 }}
            transition={{ duration: 0.3 }}
            className="md:hidden px-6 py-4 bg-primary dark:bg-bgDark space-y-3 shadow-md"
          >
            <NavMenu
              isLoggedIn={isLoggedIn}
              userRole={userRole}
              mobileMenuOpen={true}
              handleLinkClick={handleLinkClick}
            />
          </motion.div>
        )}
      </AnimatePresence>
    </header>
  );
};

export default Header;

```

## frontend\src\layout\navigation\HeaderMobile.tsx

```tsx
import { useEffect } from "react";
import { Link, useLocation } from "react-router-dom";
import { FaBars, FaSun, FaMoon, FaUserCircle } from "react-icons/fa";
import { Menu, MenuButton, MenuItem } from "@headlessui/react";
import { motion, AnimatePresence } from "framer-motion";
import { useAuth } from "../../hooks/useAuth";
import { useTheme } from "../../hooks/useTheme";

interface HeaderMobileProps {
  onToggleSidebar?: () => void;
}

const HeaderMobile: React.FC<HeaderMobileProps> = ({ onToggleSidebar }) => {
  const { darkMode, toggleDarkMode } = useTheme();
  const { isLoggedIn, logout, userRole } = useAuth();
  const location = useLocation();

  const dropdownItems: Record<string, { label: string; path: string }[]> = {
    client: [
      { label: "Perfil", path: "/perfil" },
      { label: "Ajustes", path: "/ajustes" },
    ],
    admin: [
      { label: "Dashboard", path: "/admin" },
      { label: "Perfil", path: "/perfil" },
    ],
  };

  useEffect(() => {
    // Podrías cerrar modales o limpiar algún estado aquí si lo deseas
  }, [location]);

  return (
    <header className="bg-primary dark:bg-bgDark text-white px-4 py-3 flex items-center justify-between shadow-md sticky top-0 z-50">
      {/* Sidebar toggle + Logo */}
      <div className="flex items-center gap-3">
        {onToggleSidebar && (
          <button onClick={onToggleSidebar} className="text-white text-xl">
            <FaBars />
          </button>
        )}
        <Link to="/" className="flex items-center gap-2">
          <img src="/ARP logo.png" alt="Logo" className="h-8" />
          <span className="font-semibold text-base">Aqua River Park</span>
        </Link>
      </div>

      {/* Dark mode + Auth */}
      <div className="flex items-center gap-4">
        <button
          onClick={toggleDarkMode}
          className="p-2 rounded-full bg-white/20 hover:bg-white/30 transition"
          title={darkMode ? "Modo claro" : "Modo oscuro"}
        >
          {darkMode ? <FaSun /> : <FaMoon />}
        </button>

        {isLoggedIn ? (
          <Menu as="div" className="relative">
            <MenuButton className="flex items-center">
              <FaUserCircle className="text-2xl" />
            </MenuButton>
            <AnimatePresence>
              <motion.div
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: 10 }}
                transition={{ duration: 0.2 }}
                className="absolute right-0 mt-2 w-44 bg-white dark:bg-bgDark rounded-md shadow-lg z-50 ring-1 ring-black/10"
              >
                <div className="py-1">
                  {(dropdownItems[userRole] || []).map(
                    (item, idx: number) => (
                      <MenuItem key={idx}>
                        {({ active }: { active: boolean }) => (
                          <Link
                            to={item.path}
                            className={`block px-4 py-2 text-sm ${
                              active
                                ? "bg-gray-100 dark:bg-gray-700 text-primary"
                                : "text-gray-800 dark:text-white"
                            }`}
                          >
                            {item.label}
                          </Link>
                        )}
                      </MenuItem>
                    )
                  )}
                </div>
                <div className="py-1">
                  <MenuItem>
                    {({ active }: { active: boolean }) => (
                      <button
                        onClick={logout}
                        className={`block w-full text-left px-4 py-2 text-sm ${
                          active
                            ? "bg-red-100 dark:bg-red-600 text-red-700"
                            : "text-red-500"
                        }`}
                      >
                        Cerrar sesión
                      </button>
                    )}
                  </MenuItem>
                </div>
              </motion.div>
            </AnimatePresence>
          </Menu>
        ) : (
          <Link
            to="/login"
            className="bg-secondary hover:bg-hoverSecondary px-3 py-1.5 rounded-md text-white text-sm transition"
          >
            Acceder
          </Link>
        )}
      </div>
    </header>
  );
};

export default HeaderMobile;

```

## frontend\src\layout\navigation\MiniFooter.tsx

```tsx
// src/components/navigation/MiniFooter.tsx

const MiniFooter = () => {
    return (
      <footer className="bg-accent2 text-white text-xs py-3 px-4 text-center shadow-md">
        <span className="block md:inline">
          © {new Date().getFullYear()} Aqua River Park
        </span>
        <span className="hidden md:inline mx-2">|</span>
        <span className="block md:inline text-white/80">
          Todos los derechos reservados
        </span>
      </footer>
    );
  };
  
  export default MiniFooter;
  
```

## frontend\src\layout\navigation\Sidebar.tsx

```tsx
// src/layout/navigation/Sidebar.tsx
import { Link, useLocation } from "react-router-dom";
import { FaHome, FaUser, FaCog } from "react-icons/fa";
import classNames from "classnames";

interface SidebarProps {
  isOpen: boolean;
}

const menuItems = [
  { label: "Inicio", path: "/", icon: <FaHome /> },
  { label: "Perfil", path: "/perfil", icon: <FaUser /> },
  { label: "Configuración", path: "/ajustes", icon: <FaCog /> },
];

const Sidebar = ({ isOpen }: SidebarProps) => {
  const location = useLocation();

  return (
    <aside
      className={classNames(
        "h-screen bg-accent2 text-white transition-all duration-300 flex flex-col",
        isOpen ? "w-64" : "w-16"
      )}
    >
      {/* Header */}
      <div className="flex items-center justify-center md:justify-between px-4 py-4 border-b border-white/10">
        {isOpen && <h1 className="text-lg font-bold">Aqua River</h1>}
      </div>

      {/* Menu */}
      <nav className="flex-1 overflow-y-auto mt-4 space-y-2">
        {menuItems.map((item, index) => (
          <Link
            to={item.path}
            key={index}
            className={classNames(
              "flex items-center gap-3 px-4 py-2 rounded-md mx-2 transition-colors",
              location.pathname === item.path
                ? "bg-accent1 text-textDark font-semibold"
                : "hover:bg-white/10"
            )}
          >
            <span className="text-lg">{item.icon}</span>
            {isOpen && <span className="text-sm">{item.label}</span>}
          </Link>
        ))}
      </nav>

      {/* Footer */}
      {isOpen && (
        <div className="px-4 py-4 text-xs text-gray-300 border-t border-white/10">
          © {new Date().getFullYear()} Aqua River Park
        </div>
      )}
    </aside>
  );
};

export default Sidebar;

```

## frontend\src\layout\PublicLayout.tsx

```tsx
import Header from "../layout/navigation/Header";
import Footer from "../layout/navigation/Footer";
// import { ReactNode } from "react";

// interface Props {
//   children: ReactNode;
// }

const PublicLayout = ({ children }: { children: React.ReactNode }) => {
  return (
    <div className="flex flex-col min-h-screen bg-bgLight dark:bg-bgDark transition-colors">
      <Header />
      <main className="flex-grow">{children}</main>
      <Footer />
    </div>
  );
};

export default PublicLayout;

```

## frontend\src\main.tsx

```tsx
// frontend/src/main.tsx
import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import "./index.css";
import { ThemeProvider } from "./context/ThemeProvider";

ReactDOM.createRoot(document.getElementById("root")!).render(
<ThemeProvider>
  <React.StrictMode>
    <App />
  </React.StrictMode>
    </ThemeProvider>
);

```

## frontend\src\pages\ConfirmAccount.tsx

```tsx

```

## frontend\src\pages\ConfirmationMail.tsx

```tsx
import { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import api from "../api/axios";
import { AxiosError } from "axios";
import { FaCheckCircle, FaTimesCircle, FaInfoCircle } from "react-icons/fa";
import { useAuthModal } from "../store/useAuthModal";
import { toast } from "react-toastify";

const ConfirmationMail = () => {
  const { token } = useParams();
  const navigate = useNavigate();
  const { openModal } = useAuthModal();

  const queryParams = new URLSearchParams(window.location.search);
  const emailFromQuery = queryParams.get("email");

  const [message, setMessage] = useState("Confirmando...");
  const [type, setType] = useState<"success" | "info" | "error">("info");
  const [showModal, setShowModal] = useState(false);
  const [email, setEmail] = useState(emailFromQuery || "");
  const [resendMsg, setResendMsg] = useState("");
  const [resendSuccess, setResendSuccess] = useState(false);
  const [isSending, setIsSending] = useState(false); // ✅ Bloqueo de clics

  useEffect(() => {
    const confirmAccount = async () => {
      try {
        const res = await api.get(`/confirm/${token}?email=${emailFromQuery}`);
        const { message } = res.data;

        setMessage(message);
        setType("success");

        if (
          message === "Cuenta confirmada exitosamente." ||
          message === "La cuenta ya ha sido confirmada."
        ) {
          toast.success(message);
          setTimeout(() => {
            navigate("/");
            openModal("login");
          }, 2500);
        }
      } catch (err) {
        const error = err as AxiosError<{ message: string }>;
        const msg = error.response?.data?.message;

        if (msg === "Token inválido o expirado") {
          setMessage("El enlace ya fue utilizado o ha expirado.");
          setType("info");
          setShowModal(true);
        } else {
          setMessage("Ocurrió un error al confirmar tu cuenta.");
          setType("error");
        }
      }
    };

    confirmAccount();
  }, [token, emailFromQuery, navigate, openModal]);

  const handleResend = async (e: React.FormEvent) => {
    e.preventDefault();
    if (isSending) return;

    setIsSending(true);
    setResendMsg("");

    try {
      const res = await api.post("/resend-confirmation", { email });
      toast.success("¡Correo reenviado correctamente!");
      setResendMsg(res.data.message);
      setResendSuccess(true);

      setTimeout(() => {
        setShowModal(false);
        setResendMsg("");
        setEmail("");
        setResendSuccess(false);
        navigate("/");
        openModal("login");
      }, 3000);
    } catch (err) {
      const error = err as AxiosError<{ message: string }>;
      const msg =
        error.response?.data?.message || "Error al reenviar el correo";
      setResendMsg(msg);
      toast.error(msg);
    } finally {
      setIsSending(false);
    }
  };

  const renderIcon = () => {
    if (type === "success")
      return <FaCheckCircle className="text-green-500 text-4xl mb-4 mx-auto" />;
    if (type === "error")
      return <FaTimesCircle className="text-red-500 text-4xl mb-4 mx-auto" />;
    return <FaInfoCircle className="text-yellow-500 text-4xl mb-4 mx-auto" />;
  };

  return (
    <>
      <div className="min-h-screen flex items-center justify-center bg-gray-100 px-4">
        <div className="bg-white shadow-md rounded-lg p-6 w-full max-w-md text-center">
          {renderIcon()}
          <h1 className="text-2xl font-bold mb-2">Confirmación de Cuenta</h1>
          <p
            className={`text-base ${
              type === "success"
                ? "text-green-600"
                : type === "error"
                ? "text-red-500"
                : "text-yellow-600"
            }`}
          >
            {message}
          </p>
        </div>
      </div>

      {showModal && (
        <div className="fixed inset-0 bg-black/70 bg-opacity-40 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg shadow-lg p-8 w-full max-w-md relative">
            {!resendSuccess && (
              <button
                onClick={() => setShowModal(false)}
                className="absolute top-2 right-3 text-gray-500 hover:text-red-500 text-lg font-bold"
              >
                &times;
              </button>
            )}
            <h2 className="text-xl font-bold text-center mb-4 text-sky-600">
              ¿Necesitas un nuevo enlace?
            </h2>
            {!resendSuccess ? (
              <>
                <p className="text-sm text-gray-600 text-center mb-4">
                  Ingresa tu correo para recibir un nuevo enlace de
                  confirmación:
                </p>
                <form onSubmit={handleResend} className="space-y-4">
                  <input
                    type="email"
                    placeholder="Tu correo"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    className="w-full px-4 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-sky-500"
                    required
                  />
                  <button
                    type="submit"
                    disabled={isSending}
                    className={`w-full bg-sky-600 text-white py-2 rounded-md hover:bg-sky-700 transition ${
                      isSending ? "opacity-50 cursor-not-allowed" : ""
                    }`}
                  >
                    {isSending ? "Enviando..." : "Reenviar enlace"}
                  </button>
                  {resendMsg && (
                    <p className="text-sm text-center text-red-500 mt-2">
                      {resendMsg}
                    </p>
                  )}
                </form>
              </>
            ) : (
              <div className="text-center">
                <FaCheckCircle className="text-green-500 text-4xl mx-auto mb-2" />
                <p className="text-green-600 text-sm font-medium">
                  {resendMsg}
                </p>
                <p className="text-sm text-gray-500 mt-2">
                  Redirigiendo al inicio de sesión...
                </p>
              </div>
            )}
          </div>
        </div>
      )}
    </>
  );
};

export default ConfirmationMail;

```

## frontend\src\pages\Dashboard.tsx

```tsx
import { useEffect, useState } from "react";
import api from "../api/axios";
import { useNavigate } from "react-router-dom";

const Dashboard = () => {
  const [user, setUser] = useState<{ name: string; role: string } | null>(null);
  const [error, setError] = useState("");
  const navigate = useNavigate();

  useEffect(() => {
    const fetchData = async () => {
      try {
        const token = localStorage.getItem("token");
        if (!token) {
          navigate("/login");
          return;
        }

        const res = await api.get("/dashboard", {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        });

        setUser({ name: res.data.message.split(" ")[1], role: res.data.role });
      } catch (err: unknown) {
        if (err instanceof Error && (err as { response?: { status: number } }).response?.status === 403) {
          setError("No tienes permisos para acceder al dashboard.");
        } else {
          setError("Acceso no autorizado. Redirigiendo...");
          setTimeout(() => navigate("/login"), 2000);
        }
      }
    };

    fetchData();
  }, [navigate]);

  const handleLogout = () => {
    localStorage.removeItem("token");
    navigate("/login");
  };

  return (
    <div className="max-w-lg mx-auto mt-20">
      <h1 className="text-3xl font-bold mb-4">Dashboard</h1>
      {error && <p className="text-red-500">{error}</p>}
      {user && (
        <>
          <p className="text-lg mb-4">
            Bienvenido <strong>{user.name}</strong>. Tu rol es:{" "}
            <strong>{user.role}</strong>
          </p>
          <button
            onClick={handleLogout}
            className="bg-red-500 text-white px-4 py-2 rounded"
          >
            Cerrar sesión
          </button>
        </>
      )}
    </div>
  );
};

export default Dashboard;

```

## frontend\src\pages\Home.tsx

```tsx
// src/pages/Home.tsx
const Home = () => {
    return (
      <div className="text-center">
        <h1 className="text-3xl font-bold text-primary mt-8">Bienvenido a Aqua River Park</h1>
        <p className="mt-4 text-gray-700 dark:text-gray-300">Tu aventura acuática comienza aquí.</p>
      </div>
    );
  };
  
  export default Home;
  
```

## frontend\src\pages\Login.tsx

```tsx
// import { useEffect, useState } from "react";
// import api from "../api/axios";
// import { useNavigate } from "react-router-dom";
// import { FaEye, FaEyeSlash, FaCheckCircle, FaInfoCircle } from "react-icons/fa";
// import { toast } from "react-toastify";
// import { AxiosError } from "axios";

// const Login = () => {
//   const [email, setEmail] = useState("");
//   const [password, setPassword] = useState("");
//   const [error, setError] = useState("");
//   const [showPassword, setShowPassword] = useState(false);
//   const [showModal, setShowModal] = useState(false);
//   const [modalStep, setModalStep] = useState<"notice" | "form" | "success">(
//     "notice"
//   );
//   const [resendMsg, setResendMsg] = useState("");
//   const navigate = useNavigate();

//   useEffect(() => {
//     const confirmed = sessionStorage.getItem("confirmationSuccess");
//     if (confirmed) {
//       toast.success(
//         "¡Cuenta confirmada con éxito! Ahora puedes iniciar sesión."
//       );
//       sessionStorage.removeItem("confirmationSuccess");
//     }
//   }, []);

//   useEffect(() => {
//     const successMsg = sessionStorage.getItem("toastSuccess");
//     if (successMsg) {
//       toast.success(successMsg);
//       sessionStorage.removeItem("toastSuccess");
//     }
//   }, []);

//   const handleSubmit = async (e: React.FormEvent) => {
//     e.preventDefault();
//     setError("");

//     try {
//       const res = await api.post("/login", { email, password });
//       localStorage.setItem("token", res.data.token);
//       navigate("/dashboard");
//     } catch (err) {
//       const error = err as AxiosError<{
//         message: string;
//         tokenExpired?: boolean;
//       }>;
//       const msg = error.response?.data?.message;

//       if (msg === "Debes confirmar tu cuenta") {
//         const expired = error.response?.data?.tokenExpired;
//         setModalStep(expired ? "form" : "notice");
//         setShowModal(true);
//       } else {
//         setError("Credenciales incorrectas");
//       }
//     }
//   };

//   const handleResend = async (e: React.FormEvent) => {
//     e.preventDefault();
//     setResendMsg("");

//     try {
//       const res = await api.post("/resend-confirmation", { email });
//       setResendMsg(res.data.message);
//       setModalStep("success");

//       setTimeout(() => {
//         toast.success("¡Correo reenviado!, Revisa tu bandeja...");
//         setShowModal(false);
//         setResendMsg("");
//         setEmail("");
//         setPassword("");
//       }, 5000);
//     } catch (err) {
//       const error = err as AxiosError<{ message: string }>;
//       const msg = error.response?.data?.message;

//       if (msg === "La cuenta ya está confirmada") {
//         toast.info("La cuenta ya ha sido confirmada.");
//         setShowModal(false);
//       } else {
//         setResendMsg("Error al reenviar el enlace.");
//       }
//     }
//   };

//   return (
//     <>
//       <div className="max-w-sm mx-auto mt-8">
//         <h1 className="text-2xl font-bold mb-4">Iniciar sesión</h1>
//         <form onSubmit={handleSubmit} className="space-y-4">
//           <input
//             type="email"
//             placeholder="Correo"
//             className="w-full border p-2"
//             value={email}
//             onChange={(e) => setEmail(e.target.value)}
//             required
//           />
//           <div className="relative">
//             <input
//               type={showPassword ? "text" : "password"}
//               placeholder="Contraseña"
//               className="w-full border p-2 pr-10"
//               value={password}
//               onChange={(e) => setPassword(e.target.value)}
//               required
//             />
//             <button
//               type="button"
//               onClick={() => setShowPassword(!showPassword)}
//               className="absolute top-1/2 right-3 transform -translate-y-1/2 text-gray-500"
//             >
//               {showPassword ? <FaEyeSlash /> : <FaEye />}
//             </button>
//           </div>
//           <button
//             type="submit"
//             className="w-full bg-blue-500 text-white p-2 rounded"
//           >
//             Entrar
//           </button>
//           {error && <p className="text-red-500 text-sm">{error}</p>}
//           <p className="text-sm mt-2">
//             ¿No tienes una cuenta?{" "}
//             <a href="/register" className="text-blue-500 underline">
//               Regístrate aquí
//             </a>
//           </p>
//         </form>
//       </div>

//       {showModal && (
//         <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50">
//           <div className="bg-white rounded-lg shadow-lg p-6 w-full max-w-md relative text-center">
//             <button
//               onClick={() => setShowModal(false)}
//               className="absolute top-2 right-3 text-gray-500 hover:text-red-500 text-lg font-bold"
//             >
//               &times;
//             </button>

//             {modalStep === "notice" && (
//               <>
//                 <FaInfoCircle className="text-yellow-500 text-4xl mx-auto mb-2" />
//                 <h2 className="text-xl font-bold mb-2 text-sky-600">
//                   Verifica tu cuenta
//                 </h2>
//                 <p className="text-sm text-gray-600 mb-4">
//                   Aún no has confirmado tu cuenta. Revisa tu correo para
//                   activarla.
//                 </p>
//               </>
//             )}

//             {modalStep === "form" && (
//               <>
//                 <h2 className="text-xl font-bold mb-2 text-sky-600">
//                   Reenviar Enlace
//                 </h2>
//                 <form onSubmit={handleResend} className="space-y-4">
//                   <input
//                     type="email"
//                     placeholder="Tu correo"
//                     className="w-full px-4 py-2 border rounded-md"
//                     value={email}
//                     onChange={(e) => setEmail(e.target.value)}
//                     required
//                   />
//                   <button
//                     type="submit"
//                     className="w-full bg-sky-600 text-white py-2 rounded-md hover:bg-sky-700"
//                   >
//                     Reenviar
//                   </button>
//                   {resendMsg && (
//                     <p className="text-sm text-red-500">{resendMsg}</p>
//                   )}
//                 </form>
//               </>
//             )}

//             {modalStep === "success" && (
//               <>
//                 <FaCheckCircle className="text-green-500 text-4xl mx-auto mb-2" />
//                 <p className="text-green-600 text-sm font-medium">
//                   {resendMsg}
//                 </p>
//                 <p className="text-sm text-gray-500 mt-2">
//                   Serás redirigido al login...
//                 </p>
//               </>
//             )}
//           </div>
//         </div>
//       )}
//     </>
//   );
// };

// export default Login;

```

## frontend\src\pages\NotFound.tsx

```tsx
import { Link } from "react-router-dom";
import { motion } from "framer-motion";
import { useCallback, useEffect, useState } from "react";
import Particles from "react-tsparticles";
import { loadSlim } from "tsparticles-slim"; // ✅ MÁS LIVIANO Y FUNCIONAL
import type { Engine } from "tsparticles-engine";

const NotFound = () => {
  const [isDark, setIsDark] = useState(false);

  useEffect(() => {
    const match = window.matchMedia("(prefers-color-scheme: dark)");
    setIsDark(match.matches);
    const listener = (e: MediaQueryListEvent) => setIsDark(e.matches);
    match.addEventListener("change", listener);
    return () => match.removeEventListener("change", listener);
  }, []);

  const particlesInit = useCallback(async (engine: Engine) => {
    await loadSlim(engine); // ✅ Ya no usamos loadFull
  }, []);

  return (
    <div className="relative h-screen w-full flex items-center justify-center px-4 bg-white dark:bg-gray-900 text-gray-800 dark:text-white overflow-hidden">
      <Particles
        id="tsparticles"
        init={particlesInit}
        className="absolute inset-0 z-0"
        options={{
          fullScreen: false,
          background: { color: { value: "transparent" } },
          particles: {
            number: { value: 60 },
            color: { value: isDark ? "#ffffff" : "#0ea5e9" },
            shape: { type: "circle" },
            opacity: { value: 0.4 },
            size: { value: 3 },
            move: {
              enable: true,
              speed: 1.5,
              direction: "none",
              outModes: "out",
            },
          },
        }}
      />

      <div className="z-10 text-center mt-2">
        <motion.h1
          className="text-[8rem] sm:text-[10rem] font-black tracking-tight leading-none"
          initial={{ scale: 0 }}
          animate={{ scale: 1 }}
          transition={{ duration: 0.6 }}
        >
          404
        </motion.h1>

        <motion.h2
          className="text-3xl sm:text-4xl font-semibold mt-2"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
        >
          ¡Ups! Página no encontrada 😢
        </motion.h2>

        <motion.p
          className="mt-4 max-w-md mx-auto text-gray-600 dark:text-gray-300 text-base sm:text-lg"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.5 }}
        >
          Tal vez escribiste mal la dirección o esta página ya no existe.
        </motion.p>

        <motion.div
          className="mt-6 flex gap-4 justify-center flex-col sm:flex-row"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.8 }}
        >
          <Link
            to="/"
            className="px-6 py-3 bg-gradient-to-r from-blue-600 to-purple-600 text-white font-semibold rounded-md hover:scale-105 transition-transform"
          >
            Ir al inicio
          </Link>
          <Link
            to="/dashboard"
            className="px-6 py-3 border border-gray-400 text-gray-700 dark:text-gray-200 dark:border-gray-500 rounded-md hover:bg-gray-200 dark:hover:bg-gray-700 transition-all"
          >
            Ir al panel
          </Link>
        </motion.div>

        <motion.div
          className="mt-4"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 1.2 }}
        >
          <img
            src="https://illustrations.popsy.co/violet/crashed-error.svg"
            alt="Ilustración de error"
            className="w-64 sm:w-96 mx-auto fill-indigo-500 drop-shadow-2xl drop-shadow-indigo-500/50"
          />
        </motion.div>
      </div>
    </div>
  );
};

export default NotFound;

```

## frontend\src\pages\Register.tsx

```tsx
// import { useState } from "react";
// import api from "../api/axios";
// import { useNavigate } from "react-router-dom";

// const Register = () => {
//   const [name, setName] = useState("");
//   const [email, setEmail] = useState("");
//   const [password, setPassword] = useState("");
//   const [phone, setPhone] = useState("");
//   const [error, setError] = useState("");
//   const navigate = useNavigate();

//   const handleSubmit = async (e: React.FormEvent) => {
//     e.preventDefault();
//     try {
//       await api.post("/register", { name, email, password, phone });
//       alert("Registro exitoso. Revisa tu correo para confirmar tu cuenta.");
//       navigate("/login");
//     } catch (err) {
//       console.error(err);
//       setError("Error al registrarse. Puede que el correo ya exista.");
//     }
//   };

//   return (
//     <div className="max-w-sm mx-auto mt-8">
//       <h1 className="text-2xl font-bold mb-4">Registro</h1>
//       <form onSubmit={handleSubmit} className="space-y-4">
//         <input
//           type="text"
//           placeholder="Nombre"
//           className="w-full border p-2"
//           value={name}
//           onChange={(e) => setName(e.target.value)}
//         />
//         <input
//           type="email"
//           placeholder="Correo"
//           className="w-full border p-2"
//           value={email}
//           onChange={(e) => setEmail(e.target.value)}
//         />
//         <input
//           type="tel"
//           placeholder="Teléfono"
//           className="w-full border p-2"
//           value={phone}
//           onChange={(e) => setPhone(e.target.value)}
//         />
//         <input
//           type="password"
//           placeholder="Contraseña"
//           className="w-full border p-2"
//           value={password}
//           onChange={(e) => setPassword(e.target.value)}
//         />
//         <button
//           type="submit"
//           className="w-full bg-green-600 text-white p-2 rounded"
//         >
//           Registrarse
//         </button>
//         {error && <p className="text-red-500 text-sm">{error}</p>}
//         <p className="text-sm mt-2">
//           ¿Ya tienes una cuenta?{" "}
//           <a href="/login" className="text-blue-500 underline">
//             Inicia sesión aquí
//           </a>
//         </p>
//       </form>
//     </div>
//   );
// };

// export default Register;

```

## frontend\src\pages\ResetPassword.tsx

```tsx
import { useEffect, useState } from "react";
import { useSearchParams, useNavigate } from "react-router-dom";
import { toast } from "react-toastify";
import api from "../api/axios";
import { useAuthModal } from "../store/useAuthModal";
import {
  validatePasswordSecurity,
} from "../utils/validationHelpersForm";
import PasswordWithStrengthInput from "../components/common/PasswordWithStrengthInputForm";
import InputWithLabel from "../components/common/InputWithLabel";

export default function ResetPassword() {
  const [searchParams] = useSearchParams();
  const token = searchParams.get("token") || "";
  const email = searchParams.get("email") || "";
  const navigate = useNavigate();
  const { openModal } = useAuthModal();

  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [passwordError, setPasswordError] = useState("");
  const [confirmPasswordError, setConfirmPasswordError] = useState("");
  const [loading, setLoading] = useState(true);
  const [valid, setValid] = useState(false);
  const [error, setError] = useState("");
  const [resend, setResend] = useState(false);
  const [isSending, setIsSending] = useState(false);

  useEffect(() => {
    const validateToken = async () => {
      try {
        const res = await api.post("/check-token-status", { token });
        setValid(res.data.valid);
        if (!res.data.valid) setError("El enlace ha expirado o es inválido.");
      } catch {
        setError("Error al validar el enlace.");
      } finally {
        setLoading(false);
      }
    };

    if (token) validateToken();
    else {
      setError("Token no proporcionado.");
      setLoading(false);
    }
  }, [token]);

  const handlePasswordChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const newPassword = e.target.value;
    setPassword(newPassword);

    const errors = validatePasswordSecurity(newPassword, email);
    setPasswordError(errors.length > 0 ? errors.join(" ") : "");

    if (confirmPassword && confirmPassword !== newPassword) {
      setConfirmPasswordError("Las contraseñas no coinciden.");
    } else {
      setConfirmPasswordError("");
    }
  };

  const handleConfirmPasswordChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const newConfirm = e.target.value;
    setConfirmPassword(newConfirm);
    if (password !== newConfirm) {
      setConfirmPasswordError("Las contraseñas no coinciden.");
    } else {
      setConfirmPasswordError("");
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (isSending) return;
    setIsSending(true);

    const passwordErrors = validatePasswordSecurity(password, email);
    if (passwordErrors.length > 0) {
      toast.warning(passwordErrors.join(" "));
      setIsSending(false);
      return;
    }

    if (password !== confirmPassword) {
      toast.error("Las contraseñas no coinciden");
      setIsSending(false);
      return;
    }

    try {
      await api.post(`/reset-password/${token}`, { password });
      toast.success("Contraseña actualizada correctamente");

      setTimeout(() => {
        navigate("/");
        openModal("login");
      }, 2000);
    } catch {
      toast.error("Error al actualizar la contraseña");
    } finally {
      setIsSending(false);
    }
  };

  const handleResend = async () => {
    if (isSending) return;
    setIsSending(true);

    try {
      await api.post("/send-recovery", { email });
      toast.success("Se envió un nuevo enlace de recuperación");
      setResend(true);
    } catch {
      toast.error("No se pudo reenviar el correo");
    } finally {
      setIsSending(false);
    }
  };

  if (loading) return <p className="text-center mt-8 dark:text-white">Cargando...</p>;

  if (!valid) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-100 dark:bg-bgDark px-4">
        <div className="bg-white dark:bg-bgLight/10 shadow-md rounded-lg p-6 w-full max-w-md text-center">
          <h2 className="text-xl font-semibold text-red-600 dark:text-red-400 mb-4">{error}</h2>
          {!resend && email ? (
            <>
              <p className="text-sm text-gray-600 dark:text-gray-300 mb-4">
                Puedes reenviar el enlace a: <strong>{email}</strong>
              </p>
              <button
                onClick={handleResend}
                disabled={isSending}
                className={`bg-sky-600 text-white px-4 py-2 rounded hover:bg-sky-700 transition ${
                  isSending ? "opacity-50 cursor-not-allowed" : ""
                }`}
              >
                {isSending ? "Enviando..." : "Reenviar enlace"}
              </button>
            </>
          ) : resend ? (
            <p className="text-green-600 dark:text-green-400">
              Enlace reenviado. Revisa tu correo.
            </p>
          ) : (
            <p className="text-sm text-gray-500 dark:text-gray-300">
              Solicita un nuevo enlace desde "Olvidé mi contraseña".
            </p>
          )}
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-100 dark:bg-bgDark px-4">
      <form
        onSubmit={handleSubmit}
        className="bg-white dark:bg-bgLight/10 shadow-md rounded-lg p-6 w-full max-w-md"
      >
        <h2 className="text-2xl font-bold mb-4 text-center text-sky-600 dark:text-textLight">
          Nueva Contraseña
        </h2>
        <p className="text-sm text-gray-600 dark:text-gray-300 mb-4 text-center">
          Ingresa una nueva contraseña para tu cuenta.
        </p>

        <PasswordWithStrengthInput
          value={password}
          onChange={handlePasswordChange}
          error={passwordError}
          showTooltip={true}
          showStrengthBar={true}
        />

        <InputWithLabel
          label="Confirmar contraseña"
          name="confirmPassword"
          type="password"
          value={confirmPassword}
          onChange={handleConfirmPasswordChange}
          placeholder="Confirma tu contraseña"
          error={confirmPasswordError}
        />

        <button
          type="submit"
          disabled={isSending || passwordError !== "" || confirmPasswordError !== ""}
          className={`w-full bg-sky-600 text-white py-2 rounded hover:bg-sky-700 transition ${
            isSending ? "opacity-50 cursor-not-allowed" : ""
          }`}
        >
          {isSending ? "Actualizando..." : "Actualizar contraseña"}
        </button>
      </form>
    </div>
  );
}

```

## frontend\src\router\AppRouter.tsx

```tsx
// src/router/AppRouter.tsx
import { Routes, Route } from "react-router-dom";
import Home from "../pages/Home";
import Dashboard from "../pages/Dashboard";
import ConfirmationMail from "../pages/ConfirmationMail";
import ResetPassword from "../pages/ResetPassword";
import NotFound from "../pages/NotFound";
import PublicLayout from "../layout/PublicLayout";
import DashboardLayout from "../layout/DashboardLayout";
import PrivateRoute from "../utils/PrivateRoute";

const AppRouter = () => (
  <Routes>
    <Route
      path="/"
      element={
        <PublicLayout>
          <Home />
        </PublicLayout>
      }
    />
    <Route
      path="/login"
      element={
        <PublicLayout>
          <Home />
        </PublicLayout>
      }
    />
    <Route
      path="/register"
      element={
        <PublicLayout>
          <Home />
        </PublicLayout>
      }
    />
    <Route
      path="/confirm/:token"
      element={
        <PublicLayout>
          <ConfirmationMail />
        </PublicLayout>
      }
    />
    <Route
      path="/reset-password"
      element={
        <PublicLayout>
          <ResetPassword />
        </PublicLayout>
      }
    />

    <Route
      path="/dashboard"
      element={
        <PrivateRoute>
          <DashboardLayout>
            <Dashboard />
          </DashboardLayout>
        </PrivateRoute>
      }
    />

    <Route path="*" element={<NotFound />} />
  </Routes>
);

export default AppRouter;

```

## frontend\src\store\useAuthModal.ts

```typescript
import { create } from "zustand";

interface AuthModalState {
  isOpen: boolean;
  view: "login" | "register";
  openModal: (view?: "login" | "register") => void;
  closeModal: () => void;
  toggleView: () => void;
}

export const useAuthModal = create<AuthModalState>((set) => ({
  isOpen: false,
  view: "login",
  openModal: (view = "login") => set({ isOpen: true, view }),
  closeModal: () => set({ isOpen: false }),
  toggleView: () =>
    set((state) => ({
      view: state.view === "login" ? "register" : "login",
    })),
}));

```

## frontend\src\utils\auth.ts

```typescript
export const isAuthenticated = () => true;

```

## frontend\src\utils\PrivateRoute.tsx

```tsx
import { Navigate } from 'react-router-dom';

import { ReactNode } from 'react';

const PrivateRoute = ({ children }: { children: ReactNode }) => {
  const token = localStorage.getItem('token');
  return token ? children : <Navigate to="/login" replace />;
};

export default PrivateRoute;
```

## frontend\src\utils\validationHelpersForm.ts

```typescript
// Capitaliza cada palabra
export const capitalizeName = (name: string) => {
    return name
        .toLowerCase()
        .split(" ")
        .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
        .join(" ");
};


// Devuelve el puntaje de seguridad de la contraseña
export const getPasswordScore = (password: string) => {
    let score = 0;
    if (password.length >= 8) score++;
    if (/[A-Z]/.test(password)) score++;
    if (/[0-9]/.test(password)) score++;
    if (/[^A-Za-z0-9]/.test(password)) score++;
    return score;
};


// Valida el formato de la dirección de correo electrónico
export const validateEmailFormat = (email: string): boolean => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
};

// Valida la seguridad de la contraseña
export const validatePasswordSecurity = (password: string, email: string): string[] => {
    const errors: string[] = [];

    if (password.length < 8) {
        errors.push("Debe tener al menos 8 caracteres.");
    }
    if (!/[A-Z]/.test(password)) {
        errors.push("Debe incluir al menos una letra mayúscula.");
    }
    if (!/[a-z]/.test(password)) {
        errors.push("Debe incluir al menos una letra minúscula.");
    }
    if (!/[0-9]/.test(password)) {
        errors.push("Debe incluir al menos un número.");
    }
    if (!/[^A-Za-z0-9]/.test(password)) {
        errors.push("Debe incluir al menos un símbolo.");
    }
    if (password.toLowerCase() === email.toLowerCase()) {
        errors.push("La contraseña no puede ser igual al correo electrónico.");
    }

    return errors;
};

// Devuelve el texto, color y clase CSS según el puntaje de la contraseña
export const getStrengthLabel = (score: number) => {
    switch (score) {
      case 0:
      case 1:
        return {
          text: "Débil",
          color: "text-red-500 dark:text-red-400",
          bar: "bg-red-500 dark:bg-red-400",
        };
      case 2:
        return {
          text: "Media",
          color: "text-yellow-500 dark:text-yellow-400",
          bar: "bg-yellow-400 dark:bg-yellow-300",
        };
      case 3:
        return {
          text: "Fuerte",
          color: "text-blue-500 dark:text-blue-400",
          bar: "bg-blue-500 dark:bg-blue-400",
        };
      case 4:
        return {
          text: "Muy fuerte",
          color: "text-green-600 dark:text-green-400",
          bar: "bg-green-500 dark:bg-green-400",
        };
      default:
        return {
          text: "",
          color: "",
          bar: "bg-gray-200 dark:bg-gray-600",
        };
    }
  };
  


```

## frontend\src\vite-env.d.ts

```typescript
/// <reference types="vite/client" />

```

## frontend\tsconfig.app.json

```json
{
  "compilerOptions": {
    "tsBuildInfoFile": "./node_modules/.tmp/tsconfig.app.tsbuildinfo",
    "target": "ES2020",
    "useDefineForClassFields": true,
    "lib": ["ES2020", "DOM", "DOM.Iterable"],
    "module": "ESNext",
    "skipLibCheck": true,

    /* Bundler mode */
    "moduleResolution": "bundler",
    "allowImportingTsExtensions": true,
    "isolatedModules": true,
    "moduleDetection": "force",
    "noEmit": true,
    "jsx": "react-jsx",

    /* Linting */
    "strict": true,
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "noFallthroughCasesInSwitch": true,
    "noUncheckedSideEffectImports": true
  },
  "include": ["src", "../backend/src/utils/sanitize.ts"]
}

```

## frontend\tsconfig.node.json

```json
{
  "compilerOptions": {
    "tsBuildInfoFile": "./node_modules/.tmp/tsconfig.node.tsbuildinfo",
    "target": "ES2022",
    "lib": ["ES2023"],
    "module": "ESNext",
    "skipLibCheck": true,

    /* Bundler mode */
    "moduleResolution": "bundler",
    "allowImportingTsExtensions": true,
    "isolatedModules": true,
    "moduleDetection": "force",
    "noEmit": true,

    /* Linting */
    "strict": true,
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "noFallthroughCasesInSwitch": true,
    "noUncheckedSideEffectImports": true
  },
  "include": ["vite.config.ts"]
}

```

## frontend\vite.config.ts

```typescript
// import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { defineConfig } from "vitest/config";

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  test: {
    globals: true,
    environment: "node",
  },
});

```


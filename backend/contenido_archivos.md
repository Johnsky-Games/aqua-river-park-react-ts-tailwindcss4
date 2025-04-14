## src\app.ts

```typescript
import express from 'express';
import dashboardRoutes from './routes/dashboard.routes';
import authRoutes from './routes/auth.routes';
import cors from 'cors';

const app = express();
app.use(cors({
    origin: 'http://localhost:5173', // 👈 Asegúrate que coincida con el frontend
    credentials: true
}));
app.use(express.json());

// Agrupar rutas protegidas bajo /api
app.use('/api', dashboardRoutes);
app.use('/api', authRoutes);

export default app;
```

## src\config\db.ts

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

## src\config\jwt.ts

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

## src\config\mailer.ts

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

## src\controllers\admin.controller.ts

```typescript
// admin.controller.ts
```

## src\controllers\auth.controller.ts

```typescript
import { Request, Response } from "express";
import * as authService from "../services/auth.service";
import { resendConfirmationService } from "../services/confirm.service";


// ✅ REGISTRO
export const register = async (req: Request, res: Response) => {
  try {
    await authService.registerUser(req.body);
    res.status(201).json({
      message: "Registro exitoso. Revisa tu correo para confirmar tu cuenta.",
    });
  } catch (error: any) {
    console.error("❌ Registro:", error.message);
    res.status(400).json({ message: error.message || "Error al registrar" });
  }
};

// ✅ LOGIN
export const login = async (req: Request, res: Response) => {
  const { email, password } = req.body;

  try {
    const data = await authService.loginUser(email, password);
    res.json(data);
  } catch (error: any) {
    if (error.message === "Debes confirmar tu cuenta") {
      res.status(401).json({
        message: error.message,
        tokenExpired: error.tokenExpired || false,
      });
    } else {
      res.status(401).json({ message: error.message || "Error al iniciar sesión" });
    }
  }
};

// ✅ LOGOUT (placeholder si usas JWT)
export const logout = async (_req: Request, res: Response) => {
  res.json({ message: "Sesión cerrada" });
};

// ✅ REENVIAR CONFIRMACIÓN
export const resendConfirmation = async (req: Request, res: Response) => {
  const { email } = req.body;

  try {
    await resendConfirmationService(email); // 👈 llamado correcto
    res.json({ message: "Correo de confirmación reenviado." });
  } catch (error: any) {
    console.error("❌ Reenviar confirmación:", error.message);
    res.status(400).json({ message: error.message });
  }
};

// ✅ SOLICITAR RECUPERACIÓN DE CONTRASEÑA
export const sendRecovery = async (req: Request, res: Response) => {
  const { email } = req.body;

  try {
    await authService.sendResetPassword(email);
    res.json({ message: "Correo de recuperación enviado." });
  } catch (error: any) {
    console.error("❌ Enviar recuperación:", error.message);
    res.status(400).json({ message: error.message });
  }
};

// ✅ CAMBIAR CONTRASEÑA
export const resetPassword = async (req: Request, res: Response) => {
  const { token, password } = req.body;

  try {
    await authService.resetPassword(token, password);
    res.json({ message: "Contraseña actualizada con éxito." });
  } catch (error: any) {
    console.error("❌ Reset password:", error.message);
    res.status(400).json({ message: error.message });
  }
};

```

## src\controllers\cart.controller.ts

```typescript
// cart.controller.ts
```

## src\controllers\cart_items.controller.ts

```typescript
// cart_items.controller.ts
```

## src\controllers\confirm.controller.ts

```typescript
// src/controllers/confirm.controller.ts
import { Request, Response } from "express";
import {
    confirmAccountService,
    resendConfirmationService,
  } from "../services/confirm.service";  

export const confirmUser = async (req: Request, res: Response): Promise<void> => {
    const { token } = req.params;
    const { email } = req.query;

    try {
        const result = await confirmAccountService(token, email as string | undefined);
        res.status(result.code).json({ message: result.message });
    } catch (error: any) {
        console.error("❌ Error al confirmar:", error);
        res.status(500).json({ message: "Error en el servidor" });
    }
};

export const resendConfirmation = async (req: Request, res: Response): Promise<void> => {
    const { email } = req.body;

    try {
        await resendConfirmationService(email);
        res.status(200).json({
            message: "Se envió un nuevo enlace de confirmación a tu correo",
        });
    } catch (error: any) {
        console.error("❌ Error al reenviar confirmación:", error.message || error);
        res.status(400).json({
            message: error.message || "Error al reenviar confirmación",
        });
    }
};

```

## src\controllers\dashboard.controller.ts

```typescript
// backend/src/controllers/dashboard.controller.ts
import { Response } from "express";
import { AuthenticatedRequest } from "../types/express";

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

## src\controllers\emailLog.controller.ts

```typescript
// emailLog.controller.ts
```

## src\controllers\freePass.controller.ts

```typescript
// freePass.controller.ts
```

## src\controllers\invoice.controller.ts

```typescript
// invoice.controller.ts
```

## src\controllers\permission.controller.ts

```typescript
// permission.controller.ts
```

## src\controllers\qrScan.controller.ts

```typescript
// qrScan.controller.ts
```

## src\controllers\recover.controller.ts

```typescript
// backend/src/controllers/recovery.controller.ts
import { Request, Response } from "express";
import db from "../config/db";
import crypto from "crypto";
import bcrypt from "bcryptjs";
import sendRecoveryEmail from "../utils/mailerRecovery";
import { RowDataPacket } from "mysql2";

// ✅ 1. Enviar enlace de recuperación
export const sendRecovery = async (req: Request, res: Response): Promise<void> => {
    const { email } = req.body;
  
    try {
      const [rows] = await db.query<RowDataPacket[]>(
        "SELECT id FROM users WHERE email = ?",
        [email]
      );
  
      if (rows.length === 0) {
        res.status(404).json({ message: "Correo no registrado" });
        return;
      }
  
      const reset_token = crypto.randomBytes(32).toString("hex");
      const reset_expires = new Date(Date.now() + 60 * 60 * 1000); // 1 hora
  
      await db.query(
        "UPDATE users SET reset_token = ?, reset_expires = ? WHERE email = ?",
        [reset_token, reset_expires, email]
      );
  
      // ✅ Confirma en consola el token generado
      console.log("🔑 Token generado y guardado:", reset_token);
  
      await sendRecoveryEmail(email, reset_token);
  
      res.json({ message: "Correo de recuperación enviado. Revisa tu bandeja." });
    } catch (error: any) {
      console.error("❌ Error en sendRecovery:", error.message || error);
      res.status(500).json({ message: "Error en el servidor" });
    }
  };

// ✅ 2. Validar si el token aún es válido
export const checkTokenStatus = async (req: Request, res: Response): Promise<void> => {
  const { token } = req.body;

  try {
    const [rows] = await db.query<RowDataPacket[]>(
      "SELECT reset_expires FROM users WHERE reset_token = ?",
      [token]
    );

    if (rows.length === 0 || new Date(rows[0].reset_expires) < new Date()) {
      res.json({ valid: false });
    } else {
      res.json({ valid: true });
    }
  } catch (error) {
    console.error("❌ Error al verificar token:", error);
    res.status(500).json({ message: "Error en el servidor" });
  }
};

// ✅ 3. Restablecer la contraseña
export const resetPassword = async (req: Request, res: Response): Promise<void> => {
  const { token } = req.params;
  const { password } = req.body;

  try {
    const [rows] = await db.query<RowDataPacket[]>(
      "SELECT id, reset_expires FROM users WHERE reset_token = ?",
      [token]
    );

    if (rows.length === 0) {
      res.status(400).json({ message: "Token inválido" });
      return;
    }

    const user = rows[0];
    if (new Date(user.reset_expires) < new Date()) {
      res.status(400).json({ message: "Token expirado" });
      return;
    }

    const password_hash = await bcrypt.hash(password, 10);
    await db.query(
      "UPDATE users SET password_hash = ?, reset_token = NULL, reset_expires = NULL WHERE id = ?",
      [password_hash, user.id]
    );

    res.json({ message: "Contraseña actualizada correctamente" });
  } catch (error: any) {
    console.error("❌ Error en resetPassword:", error.message);
    res.status(500).json({ message: "Error en el servidor" });
  }
};

```

## src\controllers\role.controller.ts

```typescript
// role.controller.ts
```

## src\controllers\rolePermission.controller.ts

```typescript
// rolePermission.controller.ts
```

## src\controllers\service.controller.ts

```typescript
// service.controller.ts
```

## src\controllers\tokenStatus.controller.ts

```typescript
// backend/src/controllers/tokenStatus.controller.ts
import { Request, Response } from 'express';
import db from '../config/db';
import { RowDataPacket } from 'mysql2';

export const checkTokenStatus = async (req: Request, res: Response): Promise<void> => {
  const { email } = req.body;

  try {
    const [rows] = await db.query<RowDataPacket[]>(
      'SELECT is_confirmed, confirmation_expires FROM users WHERE email = ?',
      [email]
    );

    if (rows.length === 0) {
      res.status(404).json({ message: 'Correo no encontrado' });
      return;
    }

    const user = rows[0];
    const now = new Date();

    const isExpired = new Date(user.confirmation_expires) < now;

    res.status(200).json({
      is_confirmed: user.is_confirmed,
      is_expired: isExpired,
    });
  } catch (error) {
    console.error('❌ Error verificando estado del token:', error);
    res.status(500).json({ message: 'Error en el servidor' });
  }
};

```

## src\controllers\user.controller.ts

```typescript
// user.controller.ts
```

## src\controllers\userPermissions.controller.ts

```typescript
// userPermissions.controller.ts
```

## src\index.ts

```typescript
// index.ts
import app from './app';
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`✅ Servidor iniciado en http://localhost:${PORT}`);
});
```

## src\middlewares\auth.middleware.ts

```typescript
import { Request, Response, NextFunction } from "express";
import { verifyToken, TokenPayload } from "../config/jwt";
import { AuthenticatedRequest } from "../types/express";

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

## src\middlewares\errorHandler.middleware.ts

```typescript
// errorHandler.middleware.ts
```

## src\middlewares\notFound.middleware.ts

```typescript
// notFound.middleware.ts
```

## src\middlewares\role.middleware.ts

```typescript
// role.middleware.ts
import { Response, NextFunction } from 'express';
import { AuthenticatedRequest } from '../types/express'; // Solo importa esto si usas req.user

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

## src\middlewares\validation.middleware.ts

```typescript
// validation.middleware.ts
```

## src\models\cart.model.ts

```typescript
// cart.model.ts
```

## src\models\emailLog.model.ts

```typescript
// emailLog.model.ts
```

## src\models\freePass.model.ts

```typescript
// freePass.model.ts
```

## src\models\index.ts

```typescript
// index.ts
```

## src\models\invoice.model.ts

```typescript
// invoice.model.ts
```

## src\models\permission.model.ts

```typescript
// permission.model.ts
```

## src\models\qrScan.model.ts

```typescript
// qrScan.model.ts
```

## src\models\role.model.ts

```typescript
// role.model.ts
```

## src\models\service.model.ts

```typescript
// service.model.ts
```

## src\models\user.model.ts

```typescript
// user.model.ts
```

## src\repositories\user.repository.ts

```typescript
// src/repositories/user.repository.ts
import db from "../config/db";
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
  const { name, email, password_hash, phone, role_id, confirmation_token, confirmation_expires } = user;

  const [result] = await db.query<ResultSetHeader>(
    `INSERT INTO users (name, email, password_hash, phone, role_id, confirmation_token, confirmation_expires)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [name, email, password_hash, phone, role_id, confirmation_token, confirmation_expires]
  );

  return result.insertId;
};

export const updateConfirmationToken = async (email: string, token: string, expires: Date) => {
  await db.query(
    `UPDATE users SET confirmation_token = ?, confirmation_expires = ? WHERE email = ?`,
    [token, expires, email]
  );
};

export const updateResetToken = async (email: string, token: string, expires: Date) => {
  await db.query(
    `UPDATE users SET reset_token = ?, reset_expires = ? WHERE email = ?`,
    [token, expires, email]
  );
};

export const findUserByResetToken = async (token: string) => {
  const [rows] = await db.query<RowDataPacket[]>(
    "SELECT * FROM users WHERE reset_token = ? AND reset_expires > NOW()",
    [token]
  );
  return rows[0] || null;
};

export const updatePassword = async (userId: number, newPasswordHash: string) => {
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

```

## src\routes\admin.routes.ts

```typescript
// admin.routes.ts
```

## src\routes\auth.routes.ts

```typescript
import { Router } from 'express';
import {
    login,
    register,
    logout,
} from '../controllers/auth.controller';
import { confirmUser, resendConfirmation } from '../controllers/confirm.controller';
// import { checkTokenStatus } from '../controllers/tokenStatus.controller';
import { sendRecovery, checkTokenStatus, resetPassword } from '../controllers/recover.controller'; // 👈 nuevo

import { authMiddleware } from '../middlewares/auth.middleware';
import { getDashboard } from '../controllers/dashboard.controller';
import { checkRole } from '../middlewares/role.middleware';

const router = Router();

// Auth
router.post('/register', register);
router.post('/login', login);
router.post('/logout', logout);

// Confirmación
router.get('/confirm/:token', confirmUser);
router.post('/resend-confirmation', resendConfirmation);

// Recuperación de contraseña
router.post('/send-recovery', sendRecovery);   // 👈 nuevo
router.post('/reset-password', resetPassword); // 👈 nuevo
router.post("/reset-password/:token", resetPassword); // 👈 importante
router.post('/check-token-status', checkTokenStatus); // 👈 nuevo

// Protegidas
router.get('/admin/dashboard', authMiddleware, checkRole(['admin']), getDashboard);

export default router;

```

## src\routes\cart.routes.ts

```typescript
// cart.routes.ts
```

## src\routes\cart_items.routes.ts

```typescript
// cart_items.routes.ts
```

## src\routes\clients.routes.ts

```typescript
// clients.routes.ts
```

## src\routes\dashboard.routes.ts

```typescript
import { Router } from "express";
import { getDashboard } from "../controllers/dashboard.controller";
import { authMiddleware } from "../middlewares/auth.middleware";

const router = Router();

router.get("/dashboard", authMiddleware, getDashboard);

export default router;

```

## src\routes\emailLog.routes.ts

```typescript
// emailLog.routes.ts
```

## src\routes\freePass.routes.ts

```typescript
// freePass.routes.ts
```

## src\routes\index.ts

```typescript
// index.ts
```

## src\routes\invoices.routes.ts

```typescript
// invoices.routes.ts
```

## src\routes\permission.routes.ts

```typescript
// permission.routes.ts
```

## src\routes\qrScan.routes.ts

```typescript
// qrScan.routes.ts
```

## src\routes\role.routes.ts

```typescript
// role.routes.ts
```

## src\routes\rolePermissions.routes.ts

```typescript
// rolePermissions.routes.ts
```

## src\routes\services.routes.ts

```typescript
// services.routes.ts
```

## src\routes\userPermissions.routes.ts

```typescript
// userPermissions.routes.ts
```

## src\routes\users.routes.ts

```typescript
// users.routes.ts
```

## src\services\auth.service.ts

```typescript
// src/services/auth.service.ts
import bcrypt from "bcryptjs";
import crypto from "crypto";
import { generateToken } from "../config/jwt";
import sendConfirmationEmail from "../utils/mailerConfirmation";
import {
  createUser,
  findUserByEmail,
  findUserByResetToken,
  updateConfirmationToken,
  updatePassword,
  updateResetToken,
} from "../repositories/user.repository";

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
  console.log(`📧 Enlace de recuperación: http://localhost:3000/reset-password/${token}`);
};

// ✅ RESTABLECER CONTRASEÑA
export const resetPassword = async (token: string, newPassword: string) => {
  const user = await findUserByResetToken(token);
  if (!user) throw new Error("Token inválido o expirado");

  const password_hash = await bcrypt.hash(newPassword, 10);
  await updatePassword(user.id, password_hash);
};

```

## src\services\confirm.service.ts

```typescript
// src/services/confirm.service.ts
import crypto from "crypto";
import sendConfirmationEmail from "../utils/mailerConfirmation";
import * as userRepo from "../repositories/user.repository";

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

## src\types\express\index.d.ts

```typescript
import { Request } from "express";
import { TokenPayload } from "../config/jwt";

export interface AuthenticatedRequest extends Request {
  user?: TokenPayload;
}

```

## src\utils\mailerConfirmation.ts

```typescript
// backend/utils/mailerConfirmation.ts
import { transporter } from "../config/mailer";

const sendConfirmationEmail = async (email: string, token: string) => {
  const link = `${process.env.FRONTEND_URL}/confirm/${token}?email=${encodeURIComponent(email)}`;
  console.log("🔗 Enlace de confirmación generado:", link);

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

## src\utils\mailerRecovery.ts

```typescript
// backend/utils/mailerRecovery.ts
import { transporter } from "../config/mailer";

const sendRecoveryEmail = async (email: string, token: string) => {
    const link = `${process.env.FRONTEND_URL}/reset-password?token=${token}&email=${encodeURIComponent(email)}`;
    console.log("🔗 Enlace de recuperación generado:", link);

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

# Contenido de Archivos

## src\app.ts

```typescript
import express from "express";
import dashboardRoutes from "@/interfaces/routes/dashboard/dashboard.routes";
import authRoutes from "@/interfaces/routes/auth/auth.routes";
import cors from "cors";
import notFound from "@/interfaces/middlewares/error/notFound.middleware";
import errorHandler from "@/interfaces/middlewares/error/errorHandler.middleware";
import { sanitizeRequest } from "@/interfaces/middlewares/sanitize/sanitizeRequest";
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

## src\domain\models\user\cart.model.ts

```typescript
export interface Cart {
    id: number;
    user_id?: number | null;
    created_at?: Date;
  }
  
```

## src\domain\models\user\cartItem.model.ts

```typescript
export interface CartItem {
    id: number;
    cart_id?: number | null;
    service_id?: number | null;
    quantity: number;
  }
  
```

## src\domain\models\user\permission.model.ts

```typescript
export interface Permission {
    id: number;
    name: string;
  }
  
```

## src\domain\models\user\role.model.ts

```typescript
export interface Role {
    id: number;
    name: string;
  }
  
```

## src\domain\models\user\service.model.ts

```typescript
export type ServiceType = 'entrada' | 'reserva' | 'evento' | 'vip';

export interface Service {
  id: number;
  title: string;
  description?: string | null;
  price: number;
  duration?: string | null;
  image_url?: string | null;
  type?: ServiceType;
  created_at?: Date;
}

```

## src\domain\models\user\user.model.ts

```typescript
export interface User {
    id: number;
    name: string;
    email: string;
    password_hash: string;
    created_at: Date;
    is_confirmed?: boolean;
    confirmation_token?: string | null;
    confirmation_expires?: Date | null;
    reset_token?: string | null;
    reset_expires?: Date | null;
    last_login?: Date | null;
    avatar_url?: string | null;
    login_attempts?: number;
    locked_until?: Date | null;
    role_id?: number | null;
    phone?: string | null;
  }
  
```

## src\domain\ports\role.repository.ts

```typescript
// src/domain/ports/role.repository.ts
import { Role } from "@/domain/models/user/role.model";

export interface RoleRepository {
  findAllRoles(): Promise<Role[]>;
  findRoleById(id: number): Promise<Role | null>;
  findRoleByName(name: string): Promise<Role | null>;
  createRole(role: Omit<Role, "id">): Promise<number>;
  deleteRole(id: number): Promise<void>;
}

```

## src\domain\ports\user.repository.ts

```typescript
import { User } from "@/domain/models/user/user.model";

export interface UserRepository {
  findUserByEmail(
    email: string
  ): Promise<(User & { role_name?: string }) | null>;
  createUser(
    user: Omit<
      User,
      | "id"
      | "created_at"
      | "last_login"
      | "avatar_url"
      | "login_attempts"
      | "locked_until"
    >
  ): Promise<number>;
  updateConfirmationToken(
    email: string,
    token: string,
    expires: Date
  ): Promise<void>;
  updateResetToken(email: string, token: string, expires: Date): Promise<void>;
  findUserByResetToken(
    token: string
  ): Promise<Pick<
    User,
    "id" | "email" | "password_hash" | "reset_expires"
  > | null>;
  updatePassword(userId: number, newPasswordHash: string): Promise<void>;
  findUserByToken(token: string): Promise<User | null>;
  checkConfirmedByEmail(
    email: string
  ): Promise<Pick<User, "is_confirmed"> | null>;
  confirmUserById(id: number): Promise<void>;
  findUserBasicByEmail(email: string): Promise<Pick<User, "id"> | null>;
  getResetTokenExpiration(
    token: string
  ): Promise<Pick<User, "reset_expires"> | null>;
}

```

## src\domain\services\auth\auth.service.ts

```typescript
// src/domain/services/auth/auth.service.ts
import bcrypt from "bcryptjs";
import crypto from "crypto";
import { generateToken } from "@/shared/security/jwt";
import sendConfirmationEmail from "@/infraestructure/mail/mailerConfirmation";
import { UserRepository } from "@/domain/ports/user.repository";
import {
  validateEmail,
  validateNewPassword,
  validatePasswordChange,
} from "@/shared/validations/validators";
import logger from "@/infraestructure/logger/logger";

// 👇 Define aquí los roles permitidos para el JWT
type RoleName = "admin" | "client";

export const registerUser = async (
  deps: { userRepository: UserRepository },
  {
    name,
    email,
    password,
    phone,
  }: {
    name: string;
    email: string;
    password: string;
    phone: string;
  }
) => {
  const { userRepository } = deps;
  validateEmail(email);
  validateNewPassword(password);

  const existingUser = await userRepository.findUserByEmail(email);
  if (existingUser) throw new Error("El correo ya está registrado");

  const password_hash = await bcrypt.hash(password, 10);
  const confirmation_token = crypto.randomBytes(32).toString("hex");
  const confirmation_expires = new Date(Date.now() + 24 * 60 * 60 * 1000);

  await userRepository.createUser({
    name,
    email,
    password_hash,
    phone,
    role_id: 4, // 👈 este número deberías mapearlo con un nombre si lo necesitas
    confirmation_token,
    confirmation_expires,
  });

  await sendConfirmationEmail(email, confirmation_token);
};

export const loginUser = async (
  deps: { userRepository: UserRepository },
  email: string,
  password: string
) => {
  const { userRepository } = deps;
  const user = await userRepository.findUserByEmail(email);
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
    role: (user.role_name || "client") as RoleName, // ← CORREGIDO
  });

  return {
    token,
    user: {
      email: user.email,
      isConfirmed: Boolean(user.is_confirmed),
    },
  };
};

export const sendResetPassword = async (
  deps: { userRepository: UserRepository },
  email: string
) => {
  const { userRepository } = deps;
  const user = await userRepository.findUserByEmail(email);
  if (!user) throw new Error("Correo no registrado");

  const token = crypto.randomBytes(32).toString("hex");
  const expires = new Date(Date.now() + 60 * 60 * 1000);

  await userRepository.updateResetToken(email, token, expires);
  logger.info(`📧 Enlace de recuperación enviado a ${email}`);
};

export const resetPassword = async (
  deps: { userRepository: UserRepository },
  token: string,
  newPassword: string
) => {
  const { userRepository } = deps;
  const user = await userRepository.findUserByResetToken(token);
  if (!user) throw new Error("Token inválido o expirado");

  await validatePasswordChange(newPassword, user.email, user.password_hash);

  const password_hash = await bcrypt.hash(newPassword, 10);
  await userRepository.updatePassword(user.id, password_hash);
};

export const checkResetToken = async (
  deps: { userRepository: UserRepository },
  token: string
) => {
  const { userRepository } = deps;
  const user = await userRepository.findUserByResetToken(token);
  return (
    !!user &&
    user.reset_expires !== null &&
    user.reset_expires !== undefined &&
    new Date(user.reset_expires) > new Date()
  );
};

```

## src\domain\services\auth\confirm.service.ts

```typescript
// src/domain/services/auth/confirm.service.ts
import crypto from "crypto";
import sendConfirmationEmail from "@/infraestructure/mail/mailerConfirmation";
import { UserRepository } from "@/domain/ports/user.repository";

export const confirmAccountService = async (
  deps: { userRepository: UserRepository },
  token: string,
  email?: string
) => {
  const { userRepository } = deps;
  const user = await userRepository.findUserByToken(token);

  if (!user) {
    if (email) {
      const userFromEmail = await userRepository.findUserByEmail(email);
      if (userFromEmail?.is_confirmed === true) {
        return { code: 200, message: "La cuenta ya ha sido confirmada." };
      }
    }
    return { code: 400, message: "Token inválido o expirado" };
  }

  if (user.is_confirmed === true) {
    return { code: 200, message: "La cuenta ya ha sido confirmada." };
  }

  if (!user.confirmation_expires || new Date(user.confirmation_expires) < new Date()) {
    return { code: 400, message: "Token inválido o expirado" };
  }

  await userRepository.confirmUserById(user.id);
  return { code: 200, message: "Cuenta confirmada exitosamente." };
};

export const resendConfirmationService = async (
  deps: { userRepository: UserRepository },
  email: string
) => {
  const { userRepository } = deps;
  const user = await userRepository.findUserByEmail(email);
  if (!user) throw new Error("Correo no encontrado");
  if (user.is_confirmed === true) throw new Error("La cuenta ya está confirmada");

  const token = crypto.randomBytes(32).toString("hex");
  const expires = new Date(Date.now() + 24 * 60 * 60 * 1000);

  await userRepository.updateConfirmationToken(email, token, expires);
  await sendConfirmationEmail(email, token);
};

```

## src\domain\services\auth\recovery.service.ts

```typescript
import crypto from "crypto";
import bcrypt from "bcryptjs";
import sendRecoveryEmail from "@/infraestructure/mail/mailerRecovery";
import { UserRepository } from "@/domain/ports/user.repository";
import { validatePasswordChange } from "@/shared/validations/validators";

/**
 * ✅ Enviar enlace de recuperación por correo
 */
export const sendRecoveryService = async (
  deps: { userRepository: UserRepository },
  email: string
) => {
  const { userRepository } = deps;
  const user = await userRepository.findUserBasicByEmail(email);
  if (!user) throw new Error("Correo no registrado");

  const token = crypto.randomBytes(32).toString("hex");
  const expires = new Date(Date.now() + 60 * 60 * 1000); // 1 hora

  await userRepository.updateResetToken(email, token, expires);
  await sendRecoveryEmail(email, token);
};

/**
 * ✅ Verificar validez de token de recuperación
 */
export const checkTokenStatusService = async (
  deps: { userRepository: UserRepository },
  token: string
): Promise<boolean> => {
  const { userRepository } = deps;
  const resetData = await userRepository.getResetTokenExpiration(token);
  return !!resetData?.reset_expires && new Date(resetData.reset_expires) > new Date();
};

/**
 * ✅ Cambiar contraseña mediante token válido
 */
export const resetPasswordService = async (
  deps: { userRepository: UserRepository },
  token: string,
  newPassword: string
) => {
  const { userRepository } = deps;
  const user = await userRepository.findUserByResetToken(token);
  if (!user) throw new Error("Token inválido o expirado");

  // Validar que no sea la misma contraseña ni igual al correo (reglas fuertes)
  await validatePasswordChange(newPassword, user.email, user.password_hash);

  const password_hash = await bcrypt.hash(newPassword, 10);
  await userRepository.updatePassword(user.id, password_hash);
};

```

## src\index.ts

```typescript
// index.ts
import app from "@/app";
import logger from "@/infraestructure/logger/logger";

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  logger.info(`✅ Servidor iniciado en http://localhost:${PORT}`);
});

```

## src\infraestructure\db\db.ts

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

## src\infraestructure\db\role.repository.ts

```typescript
import { db } from "@/infraestructure/db/db";
import { RowDataPacket, ResultSetHeader } from "mysql2";
import { Role } from "@/domain/models/user/role.model";
import { RoleRepository } from "@/domain/ports/role.repository";

export const roleRepository: RoleRepository = {
  async findAllRoles(): Promise<Role[]> {
    const [rows] = await db.query<RowDataPacket[]>("SELECT * FROM roles");
    return rows as unknown as Role[];
  },

  async findRoleById(id: number): Promise<Role | null> {
    const [rows] = await db.query<RowDataPacket[]>(
      "SELECT * FROM roles WHERE id = ?",
      [id]
    );
    return rows[0] as Role || null;
  },

  async findRoleByName(name: string): Promise<Role | null> {
    const [rows] = await db.query<RowDataPacket[]>(
      "SELECT * FROM roles WHERE name = ?",
      [name]
    );
    return rows[0] as Role || null;
  },

  async createRole(role: Omit<Role, "id">): Promise<number> {
    const [result] = await db.query<ResultSetHeader>(
      "INSERT INTO roles (name) VALUES (?)",
      [role.name]
    );
    return result.insertId;
  },

  async deleteRole(id: number): Promise<void> {
    await db.query("DELETE FROM roles WHERE id = ?", [id]);
  },
};

```

## src\infraestructure\db\user.repository.ts

```typescript
import db from "@/infraestructure/db/db";
import { RowDataPacket, ResultSetHeader } from "mysql2";
import { User } from "@/domain/models/user/user.model";
import { UserRepository } from "@/domain/ports/user.repository";

export const userRepository: UserRepository = {
  async findUserByEmail(email) {
    const [rows] = await db.query<RowDataPacket[]>(
      `SELECT u.*, r.name as role_name 
       FROM users u 
       LEFT JOIN roles r ON u.role_id = r.id 
       WHERE u.email = ?`,
      [email]
    );
    return rows[0] as (User & { role_name?: string }) || null;
  },

  async createUser(user) {
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
      [name, email, password_hash, phone, role_id, confirmation_token, confirmation_expires]
    );

    return result.insertId;
  },

  async updateConfirmationToken(email, token, expires) {
    await db.query(
      `UPDATE users SET confirmation_token = ?, confirmation_expires = ? WHERE email = ?`,
      [token, expires, email]
    );
  },

  async updateResetToken(email, token, expires) {
    await db.query(
      `UPDATE users SET reset_token = ?, reset_expires = ? WHERE email = ?`,
      [token, expires, email]
    );
  },

  async findUserByResetToken(token) {
    const [rows] = await db.query<RowDataPacket[]>(
      `SELECT id, email, password_hash, reset_expires 
       FROM users 
       WHERE reset_token = ? AND reset_expires > NOW()`,
      [token]
    );
    return rows[0] as Pick<User, "id" | "email" | "password_hash" | "reset_expires"> || null;
  },

  async updatePassword(userId, newPasswordHash) {
    await db.query(
      `UPDATE users SET password_hash = ?, reset_token = NULL, reset_expires = NULL WHERE id = ?`,
      [newPasswordHash, userId]
    );
  },

  async findUserByToken(token) {
    const [rows] = await db.query<RowDataPacket[]>(
      `SELECT * FROM users WHERE confirmation_token = ?`,
      [token]
    );
    return rows[0] as User || null;
  },

  async checkConfirmedByEmail(email) {
    const [rows] = await db.query<RowDataPacket[]>(
      `SELECT is_confirmed FROM users WHERE email = ?`,
      [email]
    );
    return rows[0] as Pick<User, "is_confirmed"> || null;
  },

  async confirmUserById(id) {
    await db.query(
      `UPDATE users 
       SET is_confirmed = 1, confirmation_token = NULL, confirmation_expires = NULL 
       WHERE id = ?`,
      [id]
    );
  },

  async findUserBasicByEmail(email) {
    const [rows] = await db.query<RowDataPacket[]>(
      `SELECT id FROM users WHERE email = ?`,
      [email]
    );
    return rows[0] as Pick<User, "id"> || null;
  },

  async getResetTokenExpiration(token) {
    const [rows] = await db.query<RowDataPacket[]>(
      `SELECT reset_expires FROM users WHERE reset_token = ?`,
      [token]
    );
    return rows[0] as Pick<User, "reset_expires"> || null;
  },
};

```

## src\infraestructure\logger\logger.ts

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

## src\infraestructure\mail\mailer.ts

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

## src\infraestructure\mail\mailerConfirmation.ts

```typescript
// backend/utils/mailerConfirmation.ts
import { transporter } from "@/infraestructure/mail/mailer";
import logger from "@/infraestructure/logger/logger";

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

## src\infraestructure\mail\mailerRecovery.ts

```typescript
// backend/utils/mailerRecovery.ts
import { transporter } from "@/infraestructure/mail/mailer";
import logger from "@/infraestructure/logger/logger";

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

## src\infraestructure\security\rateLimit.ts

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

## src\interfaces\controllers\auth\auth.controller.ts

```typescript
import { Request, Response } from "express";
import * as authService from "@/domain/services/auth/auth.service";
import { userRepository } from "@/infraestructure/db/user.repository";
import logger from "@/infraestructure/logger/logger";

// ✅ REGISTRO
export const register = async (req: Request, res: Response) => {
  try {
    await authService.registerUser({ userRepository }, req.body);
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
    const data = await authService.loginUser({ userRepository }, email, password);
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

// ✅ LOGOUT
export const logout = async (_req: Request, res: Response) => {
  res.json({ message: "Sesión cerrada" });
};

// ✅ RECUPERACIÓN DE CONTRASEÑA
export const sendRecovery = async (req: Request, res: Response) => {
  const { email } = req.body;

  try {
    await authService.sendResetPassword({ userRepository }, email);
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
    await authService.resetPassword({ userRepository }, token, password);
    res.json({ message: "Contraseña actualizada con éxito." });
    logger.info(`✅ Clave actualizada con éxito`);
  } catch (error: any) {
    logger.error("❌ Reset password:", error.message);
    res.status(400).json({ message: error.message });
  }
};

```

## src\interfaces\controllers\auth\confirm.controller.ts

```typescript
// src/controllers/confirm.controller.ts
import { Request, Response } from "express";
import {
  confirmAccountService,
  resendConfirmationService,
} from "@/domain/services/auth/confirm.service";
import logger from "@/infraestructure/logger/logger";

// ✅ CONFIRMAR USUARIO
export const confirmUser = async (
  req: Request,
  res: Response
): Promise<void> => {
  const { token } = req.params;
  const { email } = req.query;

  try {
    const result = await confirmAccountService(
      token,
      email as string | undefined
    );
    res.status(result.code).json({ message: result.message });
  } catch (error: any) {
    logger.error("❌ Error al confirmar:", error);
    res.status(500).json({ message: "Error en el servidor" });
  }
};

// ✅ REENVIAR CONFIRMACIÓN
export const resendConfirmation = async (
  req: Request,
  res: Response
): Promise<void> => {
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

## src\interfaces\controllers\auth\recover.controller.ts

```typescript
import { Request, Response } from "express";
import * as recoveryService from "@/domain/services/auth/recovery.service";
import { userRepository } from "@/infraestructure/db/user.repository";
import logger from "@/infraestructure/logger/logger";

// ✅ 1. Enviar correo de recuperación
export const sendRecovery = async (req: Request, res: Response) => {
  const { email } = req.body;

  try {
    await recoveryService.sendRecoveryService({ userRepository }, email);
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
    const isValid = await recoveryService.checkTokenStatusService({ userRepository }, token);
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
    await recoveryService.resetPasswordService({ userRepository }, token, password);
    res.json({ message: "Contraseña actualizada correctamente" });
  } catch (error: any) {
    logger.error("❌ Error en resetPassword:", error.message);
    res.status(500).json({ message: "Error al cambiar contraseña" });
  }
};

```

## src\interfaces\controllers\dashboard\dashboard.controller.ts

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

## src\interfaces\middlewares\auth\auth.middleware.ts

```typescript
import { Request, Response, NextFunction } from "express";
import { verifyToken, TokenPayload } from "@/shared/security/jwt";
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

## src\interfaces\middlewares\error\errorHandler.middleware.ts

```typescript
// middlewares/errorHandler.middleware.ts
import { Request, Response, NextFunction } from "express";
import logger from "@/infraestructure/logger/logger";

const errorHandler = (
  err: any,
  _req: Request,
  res: Response,
  _next: NextFunction
) => {
  logger.error(`❌ Error global: ${err.stack || err.message}`);
  res
    .status(err.status || 500)
    .json({ message: err.message || "Error interno del servidor" });
};

export default errorHandler;

```

## src\interfaces\middlewares\error\notFound.middleware.ts

```typescript
// middlewares/notFound.middleware.ts
import { Request, Response } from "express";
import logger from "@/infraestructure/logger/logger";

const notFound = (req: Request, res: Response) => {
  logger.warn(`🚫 Ruta no encontrada: ${req.method} ${req.originalUrl}`);
  res.status(404).json({ message: "Ruta no encontrada" });
};

export default notFound;

```

## src\interfaces\middlewares\role\role.middleware.ts

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

## src\interfaces\middlewares\sanitize\sanitizeRequest.ts

```typescript
// middlewares/sanitizeRequest.ts
import { sanitize } from "@/shared/sanitize";
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

## src\interfaces\middlewares\validate\validateInput.ts

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

## src\interfaces\routes\auth\auth.routes.ts

```typescript
import { Router } from "express";
import {
  login,
  register,
  logout,
} from "@/interfaces/controllers/auth/auth.controller";
import {
  confirmUser,
  resendConfirmation,
} from "@/interfaces/controllers/auth/confirm.controller";
// import { checkTokenStatus } from '../controllers/tokenStatus.controller';
import {
  sendRecovery,
  checkTokenStatus,
  resetPassword,
} from "@/interfaces/controllers/auth/recover.controller"; // 👈 nuevo

import { authMiddleware } from "@/interfaces/middlewares/auth/auth.middleware";
import { getDashboard } from "@/interfaces/controllers/dashboard/dashboard.controller";
import { checkRole } from "@/interfaces/middlewares/role/role.middleware";
import { validate } from "@/interfaces/middlewares/validate/validateInput";
import { registerSchema, loginSchema } from "@/validations/auth.schema";
import { loginLimiter } from "@/infraestructure/security/rateLimit";
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
router.get("/dashboard", authMiddleware, (req, res) =>
  getDashboard(req as AuthenticatedRequest, res)
);

export default router;

```

## src\interfaces\routes\dashboard\dashboard.routes.ts

```typescript
import { Router } from "express";
import { getDashboard } from "@/interfaces/controllers/dashboard/dashboard.controller";
import { authMiddleware } from "@/interfaces/middlewares/auth/auth.middleware";
import { AuthenticatedRequest } from "@/types/express";

const router = Router();

router.get("/dashboard", authMiddleware, (req, res) =>
  getDashboard(req as AuthenticatedRequest, res)
);

export default router;

```

## src\shared\hash.ts

```typescript
// utils/hash.ts
import bcrypt from "bcryptjs";

export const hashPassword = async (password: string) => await bcrypt.hash(password, 10);
export const verifyPassword = async (plain: string, hashed: string) => await bcrypt.compare(plain, hashed);

```

## src\shared\sanitize.ts

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

## src\shared\security\jwt.ts

```typescript
// jwt.ts
import jwt, { JwtPayload } from 'jsonwebtoken';
import dotenv from 'dotenv';

dotenv.config();

const JWT_SECRET = process.env.JWT_SECRET || 'supersecret';
const JWT_EXPIRES_IN = '7d';

export type RoleName = 'admin' | 'client' | 'moderator' | 'superadmin'; // extensible

export interface TokenPayload {
  id: number;
  email: string;
  name: string;
  role: RoleName;
}

export const generateToken = (payload: TokenPayload): string => {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
};

export const verifyToken = (token: string): TokenPayload => {
  return jwt.verify(token, JWT_SECRET) as TokenPayload;
};

```

## src\shared\tokens.ts

```typescript
// utils/tokens.ts
import crypto from "crypto";

export const generateToken = (length = 32): string => {
  return crypto.randomBytes(length).toString("hex");
};

```

## src\shared\validations\auth.schema.ts

```typescript
// validations/auth.schema.ts
import { z } from "zod";

export const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
});

export const registerSchema = z
  .object({
    name: z.string().min(2),
    email: z.string().email(),
    phone: z.string().regex(/^\d{10}$/),
    password: z.string().min(8),
    confirmPassword: z.string(),
  })
  .refine((data) => data.password === data.confirmPassword, {
    message: "Las contraseñas no coinciden",
    path: ["confirmPassword"],
  });

```

## src\shared\validations\validators.ts

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


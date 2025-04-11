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

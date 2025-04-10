// backend/src/controllers/auth.controller.ts
import { Request, Response } from "express";
import db from "../config/db";
import bcrypt from "bcryptjs";
import { generateToken } from "../config/jwt";
import { RowDataPacket } from "mysql2";
import crypto from "crypto";
import sendConfirmationEmail from "../utils/mailerConfirmation";

export const register = async (req: Request, res: Response): Promise<void> => {
  const { name, email, password, phone } = req.body;

  try {
    const [rows] = await db.query<RowDataPacket[]>(
      "SELECT id FROM users WHERE email = ?",
      [email]
    );

    if (rows.length > 0) {
      res.status(400).json({ message: "El correo ya está registrado" });
      return;
    }

    const password_hash = await bcrypt.hash(password, 10);
    const confirmation_token = crypto.randomBytes(32).toString("hex");
    const confirmation_expires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24h

    await db.query(
      `INSERT INTO users (name, email, password_hash, phone, role_id, confirmation_token, confirmation_expires)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [
        name,
        email,
        password_hash,
        phone,
        4,
        confirmation_token,
        confirmation_expires,
      ]
    );

    await sendConfirmationEmail(email, confirmation_token);

    res.status(201).json({
      message: "Registro exitoso. Revisa tu correo para confirmar tu cuenta.",
    });
  } catch (error: any) {
    console.error("❌ Error al registrar:", error.message || error);
    res.status(500).json({ message: "Error en el servidor" });
  }
};

export const login = async (req: Request, res: Response): Promise<void> => {
  const { email, password } = req.body;

  try {
    const [rows] = await db.query<RowDataPacket[]>(
      "SELECT u.*, r.name as role_name FROM users u LEFT JOIN roles r ON u.role_id = r.id WHERE u.email = ?",
      [email]
    );

    if (rows.length === 0) {
      res.status(401).json({ message: "Correo no registrado" });
      return;
    }

    const user = rows[0];

    if (!user.is_confirmed) {
      const tokenExpired =
        !user.confirmation_token ||
        !user.confirmation_expires ||
        new Date(user.confirmation_expires) < new Date();

      res.status(401).json({
        message: "Debes confirmar tu cuenta",
        tokenExpired,
      });
      return;
    }

    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) {
      res.status(401).json({ message: "Contraseña incorrecta" });
      return;
    }

    const token = generateToken({
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role_name || "client",
    });

    res.json({
      token,
      user: {
        email: user.email,
        isConfirmed: Boolean(user.is_confirmed), // ✅ ESTA ES LA CORRECCIÓN
      },
    });
  } catch (error) {
    console.error("Error al iniciar sesión:", error);
    res.status(500).json({ message: "Error en el servidor" });
  }
};


export const logout = async (req: Request, res: Response): Promise<void> => {
  // Aquí puedes manejar el cierre de sesión si es necesario
  res.json({ message: "Sesión cerrada" });
};


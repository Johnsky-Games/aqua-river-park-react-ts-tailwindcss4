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

export const findUserBasicByEmail = async (email: string) => {
  const [rows] = await db.query<RowDataPacket[]>(
    "SELECT id FROM users WHERE email = ?",
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

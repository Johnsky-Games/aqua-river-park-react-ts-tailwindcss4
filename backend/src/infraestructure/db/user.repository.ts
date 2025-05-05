// src/infraestructure/db/user.repository.ts
import db from "@/config/db";
import { RowDataPacket, ResultSetHeader } from "mysql2";
import { User } from "@/domain/models/user/user.model";
import { UserRepository } from "@/domain/ports/user.repository";

export const userRepository: UserRepository = {
  async findUserByEmail(email: string): Promise<(User & { role_name?: string }) | null> {
    const [rows] = await db.query<RowDataPacket[]>(
      `SELECT u.*, r.name AS role_name
         FROM users u
         LEFT JOIN roles r ON u.role_id = r.id
        WHERE u.email = ?`,
      [email]
    );
    return (rows[0] as User & { role_name?: string }) || null;
  },

  async createUser(
    user: Omit<
      User,
      | "id"
      | "created_at"
      | "last_login"
      | "avatar_url"
      | "login_attempts"
      | "locked_until"
    >
  ): Promise<number> {
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
      `INSERT INTO users
         (name, email, password_hash, phone, role_id, confirmation_token, confirmation_expires)
       VALUES (?,     ?,     ?,             ?,     ?,       ?,                   ?)`,
      [name, email, password_hash, phone, role_id, confirmation_token, confirmation_expires]
    );

    return result.insertId;
  },

  async updateConfirmationToken(email: string, token: string, expires: Date): Promise<void> {
    await db.query(
      `UPDATE users
          SET confirmation_token = ?, confirmation_expires = ?
        WHERE email = ?`,
      [token, expires, email]
    );
  },

  async updateResetToken(email: string, token: string, expires: Date): Promise<void> {
    await db.query(
      `UPDATE users
          SET reset_token = ?, reset_expires = ?
        WHERE email = ?`,
      [token, expires, email]
    );
  },

  async findUserByResetToken(
    token: string
  ): Promise<Pick<User, "id" | "email" | "password_hash" | "reset_expires"> | null> {
    const [rows] = await db.query<RowDataPacket[]>(
      `SELECT id, email, password_hash, reset_expires
         FROM users
        WHERE reset_token = ? AND reset_expires > NOW()`,
      [token]
    );
    return (rows[0] as Pick<User, "id" | "email" | "password_hash" | "reset_expires">) || null;
  },

  async updatePassword(userId: number, newPasswordHash: string): Promise<void> {
    await db.query(
      `UPDATE users
          SET password_hash = ?, reset_token = NULL, reset_expires = NULL
        WHERE id = ?`,
      [newPasswordHash, userId]
    );
  },

  async findUserByToken(token: string): Promise<User | null> {
    const [rows] = await db.query<RowDataPacket[]>(
      `SELECT * FROM users WHERE confirmation_token = ?`,
      [token]
    );
    return (rows[0] as User) || null;
  },

  async checkConfirmedByEmail(email: string): Promise<Pick<User, "is_confirmed"> | null> {
    const [rows] = await db.query<RowDataPacket[]>(
      `SELECT is_confirmed FROM users WHERE email = ?`,
      [email]
    );
    return (rows[0] as Pick<User, "is_confirmed">) || null;
  },

  async confirmUserById(id: number): Promise<void> {
    await db.query(
      `UPDATE users
          SET is_confirmed = 1,
              confirmation_token = NULL,
              confirmation_expires = NULL
        WHERE id = ?`,
      [id]
    );
  },

  async findUserBasicByEmail(email: string): Promise<Pick<User, "id"> | null> {
    const [rows] = await db.query<RowDataPacket[]>(
      `SELECT id FROM users WHERE email = ?`,
      [email]
    );
    return (rows[0] as Pick<User, "id">) || null;
  },

  async getResetTokenExpiration(token: string): Promise<Pick<User, "reset_expires"> | null> {
    const [rows] = await db.query<RowDataPacket[]>(
      `SELECT reset_expires FROM users WHERE reset_token = ?`,
      [token]
    );
    return (rows[0] as Pick<User, "reset_expires">) || null;
  },

  async findUserById(id: number): Promise<(User & { role_name?: string }) | null> {
    const [rows] = await db.query<RowDataPacket[]>(
      `SELECT u.*, r.name AS role_name
         FROM users u
         LEFT JOIN roles r ON u.role_id = r.id
        WHERE u.id = ?`,
      [id]
    );
    return (rows[0] as User & { role_name?: string }) || null;
  },

  /** Incrementa el contador de intentos fallidos */
  async updateLoginAttempts(userId: number, attempts: number): Promise<void> {
    await db.query(
      `UPDATE users SET login_attempts = ? WHERE id = ?`,
      [attempts, userId]
    );
  },

  /** Fija locked_until */
  async updateLockedUntil(userId: number, until: Date | null): Promise<void> {
    await db.query(
      `UPDATE users SET locked_until = ? WHERE id = ?`,
      [until, userId]
    );
  },

  /** Graba la fecha del último login exitoso */
  async updateLastLogin(userId: number, when: Date): Promise<void> {
    await db.query(
      `UPDATE users SET last_login = ? WHERE id = ?`,
      [when, userId]
    );
  },
};

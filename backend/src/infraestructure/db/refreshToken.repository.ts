// src/infraestructure/db/refreshToken.repository.ts
import { db } from "@/config/db";
import { RefreshTokenRepository } from "@/domain/ports/refreshToken.repository";

export const refreshTokenRepository: RefreshTokenRepository = {
  async saveToken(jti, userId, expiresAt) {
    await db.query(
      `INSERT INTO refresh_tokens (jti, user_id, expires_at, revoked)
       VALUES (?, ?, ?, 0)`,
      [jti, userId, expiresAt]
    );
  },

  async revokeToken(jti) {
    await db.query(
      `UPDATE refresh_tokens SET revoked = 1 WHERE jti = ?`,
      [jti]
    );
  },

  async findToken(jti) {
    const [rows]: any = await db.query(
      `SELECT revoked, expires_at FROM refresh_tokens WHERE jti = ?`,
      [jti]
    );
    if (!rows.length) return null;
    return {
      revoked: rows[0].revoked === 1,
      expiresAt: new Date(rows[0].expires_at),
    };
  },
};

// This file defines the RefreshTokenRepository interface, which is responsible for managing refresh tokens in the system.
// It includes methods for saving, revoking, and finding refresh tokens in the database.

export interface RefreshTokenRepository {
  saveToken(jti: string, userId: number, expiresAt: Date): Promise<void>;
  revokeToken(jti: string): Promise<void>;
  findToken(jti: string): Promise<{ revoked: boolean; expiresAt: Date } | null>;
}

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
  ): Promise<
    Pick<User, "id" | "email" | "password_hash" | "reset_expires"> | null
  >;
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

  // ←  NUEVO MÉTODO
  findUserById(
    id: number
  ): Promise<(User & { role_name?: string }) | null>;
}

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
  
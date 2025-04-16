// utils/hash.ts
import bcrypt from "bcryptjs";

export const hashPassword = async (password: string) => await bcrypt.hash(password, 10);
export const verifyPassword = async (plain: string, hashed: string) => await bcrypt.compare(plain, hashed);

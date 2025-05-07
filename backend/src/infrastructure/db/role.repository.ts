import { db } from "@/config/db";
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
    return (rows[0] as Role) || null;
  },

  async findRoleByName(name: string): Promise<Role | null> {
    const [rows] = await db.query<RowDataPacket[]>(
      "SELECT * FROM roles WHERE name = ?",
      [name]
    );
    return (rows[0] as Role) || null;
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

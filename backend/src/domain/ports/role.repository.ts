// src/domain/ports/role.repository.ts
import { Role } from "@/domain/models/user/role.model";

export interface RoleRepository {
  findAllRoles(): Promise<Role[]>;
  findRoleById(id: number): Promise<Role | null>;
  findRoleByName(name: string): Promise<Role | null>;
  createRole(role: Omit<Role, "id">): Promise<number>;
  deleteRole(id: number): Promise<void>;
}

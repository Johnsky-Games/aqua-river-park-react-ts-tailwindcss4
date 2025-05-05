// src/store/useAuthStore.ts
import { create } from "zustand";
import { persist } from "zustand/middleware";

export interface User {
  id: number;
  name: string;
  role: "admin" | "client" | "staff" | "reception" | "editor" | "validator" | string;
}

interface AuthState {
  user: User | null;
  login: (user: User) => void;   // ahora sólo id,name,role
  logout: () => void;
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
      user: null,
      login: (user) => set({ user }),
      logout: () => set({ user: null }),
    }),
    {
      name: "auth-storage",
      partialize: (state) => ({ user: state.user }),
    }
  )
);

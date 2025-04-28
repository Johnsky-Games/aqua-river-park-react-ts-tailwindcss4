// src/store/useAuthStore.ts
import { create } from "zustand";
import { persist } from "zustand/middleware";
import { toast } from "react-toastify";

interface AuthState {
  isLoggedIn: boolean;
  userRole: "admin" | "client" | "staff" | "editor" | "reception" | "validador" | "";
  login: (token: string) => void;
  logout: (expired?: boolean) => void;
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
      isLoggedIn: false,
      userRole: "",
      login: (token) => {
        try {
          const payload = JSON.parse(atob(token.split(".")[1]));
          const role = (payload?.role as AuthState["userRole"]) || "";
          localStorage.setItem("token", token);
          set({ isLoggedIn: true, userRole: role });
        } catch (error) {
          console.error("Error decoding token:", error);
          set({ isLoggedIn: false, userRole: "" });
        }
      },
      logout: (expired = false) => {
        localStorage.removeItem("token");
        set({ isLoggedIn: false, userRole: "" });
        if (expired) {
          toast.info("Tu sesión ha expirado. Por favor, inicia sesión de nuevo.");
        }
      },
    }),
    {
      name: "auth-storage",
      partialize: (state) => ({
        isLoggedIn: state.isLoggedIn,
        userRole: state.userRole,
      }),
    }
  )
);

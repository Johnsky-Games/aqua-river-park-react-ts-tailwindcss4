// src/store/useAuthStore.ts
import { create } from "zustand";
import { persist } from "zustand/middleware";
import { toast } from "react-toastify";

interface AuthState {
  isLoggedIn: boolean;
  userRole: "admin" | "client" | "staff" | "editor" | "reception" | "validador" | "";
  userName: string;        // <--- nuevo
  login: (token: string) => void;
  logout: (expired?: boolean) => void;
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
      isLoggedIn: false,
      userRole: "",
      userName: "",        // <--- inicializamos
      login: (token) => {
        try {
          const payload = JSON.parse(atob(token.split(".")[1]));
          const role = (payload?.role as AuthState["userRole"]) || "";
          const name = (payload?.name as string) || "";  // <--- leemos el nombre
          localStorage.setItem("token", token);
          set({ isLoggedIn: true, userRole: role, userName: name });
        } catch (error) {
          console.error("Error decoding token:", error);
          set({ isLoggedIn: false, userRole: "", userName: "" });
        }
      },
      logout: (expired = false) => {
        localStorage.removeItem("token");
        set({ isLoggedIn: false, userRole: "", userName: "" });
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
        userName: state.userName,    // <--- persistimos también el nombre
      }),
    }
  )
);

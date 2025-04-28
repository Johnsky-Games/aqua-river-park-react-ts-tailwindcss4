// src/store/useAuthStore.ts
import { create } from "zustand";
import { toast } from "react-toastify";

interface AuthState {
  isLoggedIn: boolean;
  userRole: "admin" | "client" | "staff" | "editor" | "reception" | "validador" | "";
  login: (token: string) => void;
  logout: (expired?: boolean) => void;
}

export const useAuthStore = create<AuthState>((set) => ({
  isLoggedIn: false,
  userRole: "",
  login: (token) => {
    try {
      const payload = JSON.parse(atob(token.split(".")[1]));
      const role = payload?.role || "";
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
      toast.info("Debes iniciar sesión");
    }
  },
}));

// 🛠 Auto-hidratar estado cuando recarga página
if (typeof window !== "undefined") {
  const token = localStorage.getItem("token");
  if (token) {
    try {
      const payload = JSON.parse(atob(token.split(".")[1]));
      const role = payload?.role || "";
      useAuthStore.setState({ isLoggedIn: true, userRole: role });
    } catch (error) {
      console.error("Error decoding token:", error);
      useAuthStore.setState({ isLoggedIn: false, userRole: "" });
    }
  }
}

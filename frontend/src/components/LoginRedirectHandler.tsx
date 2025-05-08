// src/components/LoginRedirectHandler.tsx
import { useEffect } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { useAuthStore } from "@/store/useAuthStore";

export function LoginRedirectHandler() {
  const user = useAuthStore((s) => s.user);
  const navigate = useNavigate();
  const { pathname } = useLocation();

  useEffect(() => {
    if (!user) return;

    // Solo redirigimos clientes si intentan entrar a /login o /register
    if (user.role === "client" && ["/login", "/register"].includes(pathname)) {
      navigate("/", { replace: true });
    }
  }, [user, pathname, navigate]);

  return null;
}

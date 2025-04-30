// src/components/LoginRedirectHandler.tsx
import { useEffect } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { useAuthStore } from "@/store/useAuthStore";

export const LoginRedirectHandler = () => {
  const { isLoggedIn, userRole } = useAuthStore();
  const navigate = useNavigate();
  const { pathname } = useLocation();

  useEffect(() => {
    if (!isLoggedIn) return;

    // Cuando el admin acaba de loguearse (o viene de /login o /), lo mandamos a dashboard:
    if (
      userRole === "admin" &&
      (pathname === "/" || pathname === "/login" || pathname === "/register")
    ) {
      navigate("/admin/dashboard", { replace: true });
    }
    // Cliente nunca debe ver login / register:
    if (
      userRole === "client" &&
      (pathname === "/login" || pathname === "/register")
    ) {
      navigate("/", { replace: true });
    }
  }, [isLoggedIn, userRole, pathname, navigate]);

  return null;
};

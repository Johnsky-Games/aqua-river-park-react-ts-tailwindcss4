// src/components/LoginRedirectHandler.tsx
import { useEffect } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { useAuthStore } from "@/store/useAuthStore";

export const LoginRedirectHandler = () => {
  const { isLoggedIn, userRole } = useAuthStore();
  const navigate = useNavigate();
  const { pathname } = useLocation();

  useEffect(() => {
    if (!isLoggedIn) return; // solo actuamos tras login

    // Admin siempre va a dashboard si no está ya allí
    if (userRole === "admin" && pathname !== "/admin/dashboard") {
      navigate("/admin/dashboard", { replace: true });
      return;
    }

    // Cliente nunca debe ver login/register
    if (
      userRole === "client" &&
      (pathname === "/login" || pathname === "/register")
    ) {
      navigate("/", { replace: true });
    }
  }, [isLoggedIn, userRole, pathname, navigate]);

  return null;
};

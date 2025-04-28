import { useEffect } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { useAuthStore } from "@/store/useAuthStore";

export const LoginRedirectHandler = () => {
  const { isLoggedIn, userRole } = useAuthStore();
  const navigate = useNavigate();
  const location = useLocation();

  useEffect(() => {
    if (isLoggedIn) {
      if (userRole === "admin" && location.pathname !== "/admin/dashboard") {
        navigate("/admin/dashboard", { replace: true });
      } else if (userRole === "client" && (location.pathname === "/login" || location.pathname === "/register")) {
        navigate("/", { replace: true });
      }
    }
  }, [isLoggedIn, userRole, location.pathname, navigate]);

  return null;
};

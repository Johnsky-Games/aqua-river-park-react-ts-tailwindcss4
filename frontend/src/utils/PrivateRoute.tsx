import { Navigate, useLocation } from "react-router-dom";
import { ReactNode } from "react";
import { useAuthStore } from "@/store/useAuthStore";
import { toast } from "react-toastify";

interface PrivateRouteProps {
  children: ReactNode;
  allowedRoles: string[];
}

const PrivateRoute = ({ children, allowedRoles }: PrivateRouteProps) => {
  const { isLoggedIn, userRole } = useAuthStore();
  const location = useLocation();

  if (!isLoggedIn) {
    if (location.pathname !== "/login") {
      toast.info("Debes iniciar sesión"); 
    }
    return <Navigate to="/login" replace />;
  }

  if (!allowedRoles.includes(userRole)) {
    if (location.pathname !== "/") {
      toast.error("No tienes permisos para acceder"); 
    }
    return <Navigate to="/" replace />;
  }

  return <>{children}</>;
};

export default PrivateRoute;

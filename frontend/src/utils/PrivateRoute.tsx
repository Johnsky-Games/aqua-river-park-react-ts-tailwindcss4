// src/utils/PrivateRoute.tsx
import { ReactNode, useEffect, useState } from "react";
import { Navigate, useLocation } from "react-router-dom";
import { useAuthStore } from "@/store/useAuthStore";
import { toast } from "react-toastify";

interface PrivateRouteProps {
  children: ReactNode;
  allowedRoles: string[];
}

const PrivateRoute = ({ children, allowedRoles }: PrivateRouteProps) => {
  const { isLoggedIn, userRole } = useAuthStore();
  const location = useLocation();

  // Mantener si ya mostramos toast en esta ruta
  const [hasNotified, setHasNotified] = useState(false);

  useEffect(() => {
    if (hasNotified) return;

    // Usuario no autenticado → toast y redirect a login
    if (!isLoggedIn) {
      // Evitar toast en la propia página de login
      if (location.pathname !== "/login") {
        toast.info("Debes iniciar sesión para continuar");
      }
      setHasNotified(true);
      return;
    }

    // Usuario autenticado pero sin rol permitido → toast y redirect a home
    if (!allowedRoles.includes(userRole)) {
      // Evitar toast en la propia home
      if (location.pathname !== "/") {
        toast.error("No tienes permisos para acceder a esta sección");
      }
      setHasNotified(true);
    }
  }, [isLoggedIn, userRole, allowedRoles, location.pathname, hasNotified]);

  // Redirecciones efectivas (sin toasts aquí)
  if (!isLoggedIn) {
    return <Navigate to="/login" replace />;
  }
  if (!allowedRoles.includes(userRole)) {
    return <Navigate to="/" replace />;
  }

  // Usuario autorizado: renderizamos children
  return <>{children}</>;
};

export default PrivateRoute;

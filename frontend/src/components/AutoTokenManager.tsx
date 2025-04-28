// src/components/AutoTokenManager.tsx
import { useEffect, useRef } from "react";
import { useAuthStore } from "@/store/useAuthStore";
import api from "@/api/axios";

/**
 * AutoTokenManager se encarga de:
 * 1. Verificar al montar y cada minuto si el token está próximo a expirar.
 * 2. Llamar al endpoint `/refresh` (tal como está definido en tu backend) para renovar el token.
 * 3. Actualizar el store y localStorage si llega un nuevo token, o forzar logout si falla/expira.
 */
export const AutoTokenManager: React.FC = () => {
  const { isLoggedIn, login, logout } = useAuthStore();
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    const checkAndRefreshToken = async () => {
      const token = localStorage.getItem("token");
      if (!token) {
        // Si no hay token, limpiar estado y salir
        logout();
        return;
      }

      try {
        // Decodificar payload para leer exp
        const { exp } = JSON.parse(atob(token.split(".")[1])) as { exp?: number };
        const now = Math.floor(Date.now() / 1000);

        // Si exp existe y expira en menos de 5 minutos (300 s)
        if (exp && exp - now < 300) {
          // Llama al endpoint de refresh (asegúrate que coincida con tu ruta: /refresh)
          const res = await api.get<{ token?: string }>("/refresh", { withCredentials: true });
          const newToken = res.data.token;

          if (newToken) {
            // Actualiza estado y storage
            login(newToken);
            localStorage.setItem("token", newToken);
          } else {
            // No llegó token, fuerza logout (expired = true)
            logout(true);
          }
        }
      } catch (err: unknown) {
        console.error("Error auto-refreshing token:", err);
        // En caso de cualquier error, forzar logout por seguridad
        logout(true);
      }
    };

    if (isLoggedIn) {
      // Ejecuta una vez al montar
      checkAndRefreshToken();
      // Programa revisiones cada minuto
      intervalRef.current = setInterval(checkAndRefreshToken, 60_000);
    }

    return () => {
      // Limpia el intervalo al desmontar
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
      }
    };
  }, [isLoggedIn, login, logout]);

  return null;
};

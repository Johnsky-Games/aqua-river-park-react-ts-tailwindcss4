// src/components/UserInitializer.tsx
import React, { useEffect } from "react";
import api from "@/api/axios";
import { useAuthStore } from "@/store/useAuthStore";
import { isAxiosError } from "axios";

export const UserInitializer: React.FC = () => {
  const login = useAuthStore((s) => s.login);

  useEffect(() => {
    const init = async () => {
      // 0) Si no hay cookie refresh_token, no intentamos nada
      if (!document.cookie.includes("refresh_token=")) {
        return;
      }

      // 1) Intentamos refrescar el access token
      try {
        await api.get("/refresh", { withCredentials: true });
      } catch (err) {
        if (isAxiosError(err) && err.response?.status === 401) {
          // 401 esperado: sesión vencida o inexistente
          console.debug("Refresh expirado o inválido, seguimos anónimos");
          return;
        }
        console.error("Error inesperado en /refresh:", err);
        return;
      }

      // 2) Traemos perfil y guardamos en store
      try {
        const { data } = await api.get<{ id: number; name: string; role: string }>(
          "/me",
          { withCredentials: true }
        );
        login({ id: data.id, name: data.name, role: data.role });
        console.log("✅ Usuario logueado:", data);
      } catch (err) {
        console.error("Error obteniendo /me tras refresh:", err);
      }
    };

    init();
  }, [login]);

  return null;
};

// src/components/UserInitializer.tsx
import React, { useEffect } from "react";
import api from "@/api/axios";
import { useAuthStore } from "@/store/useAuthStore";
import { isAxiosError } from "axios";

export const UserInitializer: React.FC = () => {
  const login = useAuthStore((s) => s.login);

  useEffect(() => {
    const init = async () => {
      // 1) Intentamos refrescar el access token
      try {
        await api.get("/refresh");
      } catch (err) {
        if (isAxiosError(err) && err.response?.status === 401) {
          console.warn("Refresh token inválido o expirado — no hay sesión activa");
          return;
        }
        console.error("Error inesperado en /refresh:", err);
        return;
      }

      // 2) Si refresh OK, traemos el perfil
      try {
        const { data } = await api.get<{ id: number; name: string; role: string }>("/me");
        login({ id: data.id, name: data.name, role: data.role });
        console.log("✅ Usuario inicializado en el store:", {
          id: data.id,
          name: data.name,
          role: data.role,
        });
      } catch (err) {
        console.error("No se pudo obtener /me:", err);
      }
    };

    init();
  }, [login]);

  return null;
};

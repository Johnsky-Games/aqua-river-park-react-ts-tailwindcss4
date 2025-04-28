import { useEffect } from "react";
import { useAuthStore } from "@/store/useAuthStore";
import api from "@/api/axios";

export const AutoTokenManager = () => {
  const { isLoggedIn, logout, login } = useAuthStore();

  useEffect(() => {
    let intervalId: ReturnType<typeof setInterval>;

    const checkAndRefreshToken = async () => {
      const token = localStorage.getItem("token");

      if (!token) {
        logout();
        return;
      }

      try {
        const payload = JSON.parse(atob(token.split(".")[1]));
        const now = Math.floor(Date.now() / 1000);

        // Si el token expira en menos de 5 minutos...
        if (payload.exp && payload.exp - now < 300) {
          // Llamar a la API para refrescar
          const res = await api.get("/refresh-token", { withCredentials: true });
          const newToken = res.data.token;

          if (newToken) {
            login(newToken);
            localStorage.setItem("token", newToken);
          } else {
            logout(true);
          }
        }
      } catch (error) {
        console.error("Error auto-refreshing token", error);
        logout(true);
      }
    };

    if (isLoggedIn) {
      intervalId = setInterval(checkAndRefreshToken, 60000); // cada 1 minuto
    }

    return () => {
      if (intervalId) clearInterval(intervalId);
    };
  }, [isLoggedIn, login, logout]);

  return null;
};

// src/pages/Dashboard.tsx
import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuthStore } from "@/store/useAuthStore";
import api from "@/api/axios";

interface UserInfo {
  name: string;
  role: string;
}

const Dashboard: React.FC = () => {
  const [user, setUser] = useState<UserInfo | null>(null);
  const [error, setError] = useState<string>("");
  const navigate = useNavigate();
  const { isLoggedIn, userRole, logout } = useAuthStore();

  useEffect(() => {
    if (!isLoggedIn) {
      navigate("/login", { replace: true });
      return;
    }
    if (userRole !== "admin") {
      navigate("/", { replace: true });
      return;
    }

    const controller = new AbortController();

    const fetchDashboard = async () => {
      try {
        const token = localStorage.getItem("token");
        if (!token) {
          throw new Error("Token no encontrado");
        }

        const res = await api.get("/admin/dashboard", {
          headers: { Authorization: `Bearer ${token}` },
          signal: controller.signal,
        });

        const parts = (res.data.message as string).split(" ");
        setUser({
          name: parts[1] || "Usuario",
          role: res.data.role,
        });
      } catch (err: unknown) {
        // Si la petición fue abortada, no hacemos nada
        if (controller.signal.aborted) return;
        console.error(err);
        setError("No se pudo cargar el dashboard. Intenta de nuevo.");
      }
    };

    fetchDashboard();
    return () => {
      controller.abort();
    };
  }, [isLoggedIn, userRole, navigate]);

  const handleLogout = () => {
    logout();
    navigate("/login", { replace: true });
  };

  return (
    <div className="max-w-lg mx-auto mt-20 space-y-4">
      <h1 className="text-3xl font-bold">Dashboard</h1>

      {error && <p className="text-red-500">{error}</p>}

      {!error && !user && <p className="text-gray-600">Cargando datos del dashboard…</p>}

      {user && (
        <>
          <p className="text-lg">
            Bienvenido <strong>{user.name}</strong>. Tu rol es:{" "}
            <strong>{user.role}</strong>.
          </p>
          <button
            onClick={handleLogout}
            className="mt-4 bg-red-500 hover:bg-red-600 text-white px-4 py-2 rounded transition"
          >
            Cerrar sesión
          </button>
        </>
      )}
    </div>
  );
};

export default Dashboard;

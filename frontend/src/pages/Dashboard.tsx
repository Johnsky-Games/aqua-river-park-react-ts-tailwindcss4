import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuthStore } from "@/store/useAuthStore";
import api from "../api/axios";

const Dashboard = () => {
  const [user, setUser] = useState<{ name: string; role: string } | null>(null);
  const [error, setError] = useState("");
  const { isLoggedIn, logout } = useAuthStore(); // 👈 Estado global de sesión
  const navigate = useNavigate();

  useEffect(() => {
    if (!isLoggedIn) return; // ⛔ Si no está logueado, NO llames la API

    const fetchData = async () => {
      const token = localStorage.getItem("token");

      if (!token) {
        logout(false);
        navigate("/login", { replace: true });
        return;
      }

      try {
        const res = await api.get("/admin/dashboard", {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        });

        setUser({
          name: res.data.message.split(" ")[1],
          role: res.data.role,
        });
      } catch (error: unknown) {
        console.error("Error accediendo al dashboard", error);
        setError("Acceso no autorizado. Redirigiendo...");
        setTimeout(() => {
          logout(false);
          navigate("/login", { replace: true });
        }, 1500);
      }
    };

    fetchData();
  }, [isLoggedIn, logout, navigate]); // ⚡ ahora depende de isLoggedIn

  const handleLogout = () => {
    logout(false); // ✅ cerrar sesión correctamente
    navigate("/", { replace: true });
  };

  return (
    <div className="max-w-lg mx-auto mt-20">
      <h1 className="text-3xl font-bold mb-4">Dashboard</h1>

      {error && <p className="text-red-500 mb-4">{error}</p>}

      {user && (
        <>
          <p className="text-lg mb-4">
            Bienvenido <strong>{user.name}</strong>. Tu rol es:{" "}
            <strong>{user.role}</strong>
          </p>

          <button
            onClick={handleLogout}
            className="bg-red-500 text-white px-4 py-2 rounded hover:bg-red-600 transition-all"
          >
            Cerrar sesión
          </button>
        </>
      )}
    </div>
  );
};

export default Dashboard;

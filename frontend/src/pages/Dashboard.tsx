import { useEffect, useState } from "react";
import api from "../api/axios";
import { useNavigate } from "react-router-dom";

const Dashboard = () => {
  const [user, setUser] = useState<{ name: string; role: string } | null>(null);
  const [error, setError] = useState("");
  const navigate = useNavigate();

  useEffect(() => {
    const fetchData = async () => {
      try {
        const token = localStorage.getItem("token");
        if (!token) {
          navigate("/login");
          return;
        }

        const res = await api.get("/dashboard", {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        });

        setUser({ name: res.data.message.split(" ")[1], role: res.data.role });
      } catch (err: unknown) {
        if (err instanceof Error && (err as { response?: { status: number } }).response?.status === 403) {
          setError("No tienes permisos para acceder al dashboard.");
        } else {
          setError("Acceso no autorizado. Redirigiendo...");
          setTimeout(() => navigate("/login"), 2000);
        }
      }
    };

    fetchData();
  }, [navigate]);

  const handleLogout = () => {
    localStorage.removeItem("token");
    navigate("/login");
  };

  return (
    <div className="max-w-lg mx-auto mt-20">
      <h1 className="text-3xl font-bold mb-4">Dashboard</h1>
      {error && <p className="text-red-500">{error}</p>}
      {user && (
        <>
          <p className="text-lg mb-4">
            Bienvenido <strong>{user.name}</strong>. Tu rol es:{" "}
            <strong>{user.role}</strong>
          </p>
          <button
            onClick={handleLogout}
            className="bg-red-500 text-white px-4 py-2 rounded"
          >
            Cerrar sesión
          </button>
        </>
      )}
    </div>
  );
};

export default Dashboard;

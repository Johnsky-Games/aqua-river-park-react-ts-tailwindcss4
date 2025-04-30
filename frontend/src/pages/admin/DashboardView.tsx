// import { useEffect, useState } from "react";
// import { useNavigate } from "react-router-dom";
// import { useAuthStore } from "@/store/useAuthStore";
// import api from "@/api/axios";

// interface UserInfo {
//   name: string;
//   role: string;
// }

// const Dashboard: React.FC = () => {

//   const [error, setError] = useState<string>("");
//   const navigate = useNavigate();
//   const { isLoggedIn, userRole, logout } = useAuthStore();

//   useEffect(() => {
//     if (!isLoggedIn) {
//       navigate("/login", { replace: true });
//       return;
//     }
//     if (userRole !== "admin") {
//       navigate("/", { replace: true });
//       return;
//     }

//     const controller = new AbortController();

//     const fetchDashboard = async () => {
//       try {
//         const token = localStorage.getItem("token");
//         if (!token) throw new Error("Token no encontrado");

//         const res = await api.get("/admin/dashboard", {
//           headers: { Authorization: `Bearer ${token}` },
//           signal: controller.signal,
//         });
//         const parts = (res.data.message as string).split(" ");
//         setUser({ name: parts[1] || "Usuario", role: res.data.role });
//       } catch (err: unknown) {
//         if (controller.signal.aborted) return;
//         console.error(err);
//         setError("No se pudo cargar el dashboard. Intenta de nuevo.");
//       }
//     };

//     fetchDashboard();
//     return () => controller.abort();
//   }, [isLoggedIn, userRole, navigate]);

//   const handleLogout = () => {
//     logout();
//     navigate("/login", { replace: true });
//   };

//   return (
//     <div className="max-w-lg mx-auto pt-20 space-y-4">
//       <h1 className="text-3xl font-bold">Dashboard</h1>

//       {error && <p className="text-red-500">{error}</p>}
//       {!error && !user && <p className="text-gray-600">Cargando datos…</p>}

//       {user && (
//         <>
//           <p className="text-lg">
//             Bienvenido <strong>{user.name}</strong>. Tu rol es:{" "}
//             <strong>{user.role}</strong>.
//           </p>
//           <button
//             onClick={handleLogout}
//             className="mt-4 bg-red-500 hover:bg-red-600 text-white px-4 py-2 rounded transition"
//           >
//             Cerrar sesión
//           </button>
//         </>
//       )}
//     </div>
//   );
// };

// export default Dashboard;

// src/pages/admin/DashboardView.tsx
import React from "react";
import StatCard from "@/components/StatCard";
import { Line, Bar } from "react-chartjs-2";
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  Title,
  Tooltip,
  Legend,
  ChartData
} from "chart.js";
import {
  BsFileText,
  BsPersonFill,
  BsListCheck,
  BsGearFill,
} from "react-icons/bs";

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  Title,
  Tooltip,
  Legend
);

// **Le damos el tipo ChartData<'line', number[], unknown>**
const sampleVisitorData: ChartData<"line", number[], unknown> = {
  labels: ["Jan", "Feb", "Mar", "Apr", "May", "Jun"],
  datasets: [
    {
      label: "Total Visits",
      data: [3000, 3500, 4000, 4200, 4800, 5000],
      borderColor: "#4F46E5",
      tension: 0.4,
    },
  ],
};

// **Y el tipo ChartData<'bar', number[], unknown>**
const sampleSalesData: ChartData<"bar", number[], unknown> = {
  labels: ["Product A", "Product B", "Product C", "Product D"],
  datasets: [
    {
      label: "Revenue by Product",
      data: [12000, 19000, 15000, 17000],
      backgroundColor: ["#4F46E5", "#10B981", "#F59E0B", "#EF4444"],
    },
  ],
};

const DashboardView: React.FC = () => (
  <div className="max-w-4xl mx-auto pt-20 space-y-4">
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
      <StatCard
        title="Total Revenue"
        value="$54,234"
        percentage={12}
        icon={<BsFileText />}
      />
      <StatCard
        title="Total Visits"
        value="23,456"
        percentage={8}
        icon={<BsPersonFill />}
      />
      <StatCard
        title="New Customers"
        value="1,234"
        percentage={15}
        icon={<BsListCheck />}
      />
      <StatCard
        title="Satisfaction Rate"
        value="96%"
        percentage={5}
        icon={<BsGearFill />}
      />
    </div>

    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
      <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow-lg">
        <h3 className="text-lg font-semibold mb-4 dark:text-white">
          Visitor Trends
        </h3>
        <Line data={sampleVisitorData} options={{ responsive: true }} />
      </div>
      <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow-lg">
        <h3 className="text-lg font-semibold mb-4 dark:text-white">
          Revenue by Product
        </h3>
        <Bar data={sampleSalesData} options={{ responsive: true }} />
      </div>
    </div>
  </div>
);

export default DashboardView;

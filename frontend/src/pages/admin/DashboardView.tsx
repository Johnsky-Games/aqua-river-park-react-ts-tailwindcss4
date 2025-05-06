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
  <div className="max-w-6xl mx-auto pt-20 space-y-4">
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

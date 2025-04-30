// src/components/StatCard.tsx
import React from "react";

interface StatCardProps {
  title: string;
  value: string | number;
  percentage: number;
  icon: React.ReactNode;
}

const StatCard: React.FC<StatCardProps> = ({ title, value, percentage, icon }) => (
  <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow-lg">
    <div className="flex justify-around items-center">
      <div>
        <p className="text-gray-500 dark:text-gray-400 text-sm">{title}</p>
        <h3 className="text-2xl font-bold mt-2 dark:text-white">{value}</h3>
        <span className="text-green-500 text-sm">{percentage}% increase</span>
      </div>
      <div className="text-indigo-600 dark:text-indigo-400 text-3xl">{icon}</div>
    </div>
  </div>
);

export default StatCard;

// src/layout/navigation/Sidebar.tsx
import React, { useState } from "react";
// import { NavLink } from "react-router-dom";
import { BsGrid1X2Fill } from "react-icons/bs";
import { FaHome, FaUser, FaCog } from "react-icons/fa";
import { motion } from "framer-motion";

const menuItems = [
  { label: "Inicio", path: "/admin/dashboard", icon: <FaHome /> },
  { label: "Perfil", path: "/perfil", icon: <FaUser /> },
  { label: "Configuración", path: "/ajustes", icon: <FaCog /> },
];

const Sidebar: React.FC = () => {
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [activeTab, setActiveTab] = useState(menuItems[0].path);

  return (
    <motion.aside
      role="complementary"
      aria-label="Sidebar principal"
      initial={false}
      animate={{ width: sidebarOpen ? "16rem" : "4rem" }}
      transition={{ type: "spring", stiffness: 300, damping: 30 }}
      className="h-screen fixed left-0 top-0 bg-accent2 text-white flex flex-col transition-colors duration-300"
    >
      {/* Header: título + toggle */}
      <div className="p-4">
        <div className="flex items-center justify-between mb-8">
          {sidebarOpen && <h2 className="text-white text-xl font-bold">Aqua River</h2>}
          <button
            onClick={() => setSidebarOpen((open) => !open)}
            className="text-white p-2 rounded hover:bg-accent1 transition-colors"
            aria-label={sidebarOpen ? "Cerrar sidebar" : "Abrir sidebar"}
          >
            <BsGrid1X2Fill />
          </button>
        </div>

        {/* Enlaces */}
        <nav>
          {menuItems.map((item) => {
            const isActive = activeTab === item.path;
            return (
              <button
                key={item.path}
                onClick={() => setActiveTab(item.path)}
                className={`w-full flex items-center p-3 mb-2 rounded-lg transition-colors ${
                  isActive
                    ? "bg-accent1 text-textDark"
                    : "text-gray-300 hover:bg-accent1 hover:text-textDark"
                }`}
              >
                <span className="text-xl">{item.icon}</span>
                {sidebarOpen && <span className="ml-3">{item.label}</span>}
              </button>
            );
          })}
        </nav>
      </div>
    </motion.aside>
  );
};

export default Sidebar;

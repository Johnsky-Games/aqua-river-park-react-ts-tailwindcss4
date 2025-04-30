// src/layout/navigation/Sidebar.tsx
import React from "react";
import { BsGrid1X2Fill, BsFileText, BsListCheck, BsPersonFill, BsGearFill } from "react-icons/bs";
import { motion, AnimatePresence } from "framer-motion";
import { NavLink } from "react-router-dom";

interface SidebarProps {
  isOpen: boolean;
  isMobile: boolean;
  onToggle: () => void;
}

const menuItems = [
  { label: "Dashboard", icon: <BsGrid1X2Fill />, path: "/admin/dashboard" },
  { label: "Invoices",  icon: <BsFileText  />, path: "/admin/invoices" },
  { label: "Entries",   icon: <BsListCheck />, path: "/admin/entries" },
  { label: "Users",     icon: <BsPersonFill/>, path: "/admin/users" },
  { label: "Settings",  icon: <BsGearFill   />, path: "/admin/settings" },
];

const Sidebar: React.FC<SidebarProps> = ({ isOpen, isMobile, onToggle }) => (
  <AnimatePresence>
    {(isOpen || !isMobile) && (
      <motion.aside
        role="complementary"
        initial={false}
        animate={{ width: isOpen ? "16rem" : "4rem" }}
        transition={{ type: "tween", duration: 0.3, ease: "easeInOut" }}
        className="h-screen fixed left-0 top-0 bg-accent2 text-white flex flex-col overflow-hidden z-50"
      >
        <div className="flex flex-col justify-between h-full p-2">
          <div>
            {/* Header */}
            <div className="flex items-center justify-between mb-8">
              <motion.h2
                initial={{ opacity: 0, x: -20 }}
                animate={{
                  opacity: isOpen ? 1 : 0,
                  x:       isOpen ? 0 : -20,
                }}
                transition={{ duration: 0.3 }}
                className="text-xl font-bold whitespace-nowrap overflow-hidden"
              >
                Aqua River
              </motion.h2>
              <button
                onClick={onToggle}
                className="p-4 rounded hover:bg-accent1 transition focus:outline-none"
                aria-label={isOpen ? "Cerrar sidebar" : "Abrir sidebar"}
              >
                <BsGrid1X2Fill size={20} />
              </button>
            </div>

            {/* Navegación */}
            <nav className="space-y-2">
              {menuItems.map(({ label, icon, path }) => (
                <NavLink
                  key={path}
                  to={path}
                  end
                  className={({ isActive }) =>
                    `w-full flex items-center p-3 rounded-lg transition-colors focus:outline-none
                     ${isActive
                       ? "bg-accent1 text-textDark"
                       : "text-gray-300 hover:bg-accent1 hover:text-textDark"}
                     ${isOpen ? "justify-start" : "justify-center"}`
                  }
                >
                  <span className="text-lg">{icon}</span>
                  <AnimatePresence>
                    {isOpen && (
                      <motion.span
                        initial={{ opacity: 0, x: -10 }}
                        animate={{ opacity: 1, x: 0 }}
                        exit={{ opacity: 0, x: -10 }}
                        transition={{ duration: 0.3 }}
                        className="ml-3 whitespace-nowrap overflow-hidden"
                      >
                        {label}
                      </motion.span>
                    )}
                  </AnimatePresence>
                </NavLink>
              ))}
            </nav>
          </div>
        </div>
      </motion.aside>
    )}
  </AnimatePresence>
);

export default Sidebar;

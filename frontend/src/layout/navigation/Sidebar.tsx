// src/layout/navigation/Sidebar.tsx
import React from "react";
import { Link, useLocation } from "react-router-dom";
import {
  BsGrid1X2Fill,
  BsFileText,
  BsListCheck,
  BsPersonFill,
  BsGearFill,
} from "react-icons/bs";
import { motion, AnimatePresence } from "framer-motion";

interface MenuItem {
  label: string;
  path: string;
  icon: React.ReactNode;
}

const menuItems: MenuItem[] = [
  { label: "Dashboard", path: "/admin/dashboard", icon: <BsGrid1X2Fill /> },
  { label: "Invoices",  path: "/invoices",        icon: <BsFileText />    },
  { label: "Entries",   path: "/entries",         icon: <BsListCheck />   },
  { label: "Users",     path: "/users",           icon: <BsPersonFill />  },
  { label: "Settings",  path: "/settings",        icon: <BsGearFill />    },
];

interface SidebarProps {
  isOpen: boolean;
  onToggle: () => void;
  isMobile: boolean;
}

const Sidebar: React.FC<SidebarProps> = ({ isOpen, onToggle, isMobile }) => {
  const { pathname } = useLocation();

  return (
    <AnimatePresence>
      {(isOpen || !isMobile) && (
        <motion.aside
          role="complementary"
          aria-label="Sidebar principal"
          layout
          initial={false}
          animate={{ width: isOpen ? "16rem" : "4rem" }}
          transition={{ type: "tween", duration: 0.3, ease: "easeInOut" }}
          className="h-screen fixed left-0 top-0 bg-accent2 text-white flex flex-col overflow-hidden z-50"
        >
          <div className="flex flex-col justify-between h-full p-2">
            <div>
              {/* header */}
              <div className="flex items-center justify-between mb-8">
                <motion.h2
                  initial={{ opacity: 0, x: -20 }}
                  animate={{
                    opacity: isOpen ? 1 : 0,
                    x: isOpen ? 0 : -20,
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

              {/* menú con enlaces actualizados */}
              <nav className="space-y-2">
                {menuItems.map(item => {
                  const selected = pathname === item.path;
                  return (
                    <Link
                      key={item.path}
                      to={item.path}
                      className={`
                        flex items-center p-3 rounded-lg transition-colors focus:outline-none
                        ${selected
                          ? "bg-accent1 text-textDark"
                          : "text-gray-300 hover:bg-accent1 hover:text-textDark"}
                        ${isOpen ? "justify-start" : "justify-center"}
                      `}
                    >
                      <span className="text-lg">{item.icon}</span>
                      <AnimatePresence>
                        {isOpen && (
                          <motion.span
                            initial={{ opacity: 0, x: -10 }}
                            animate={{ opacity: 1, x: 0 }}
                            exit={{ opacity: 0, x: -10 }}
                            transition={{ duration: 0.3 }}
                            className="ml-3 whitespace-nowrap overflow-hidden"
                          >
                            {item.label}
                          </motion.span>
                        )}
                      </AnimatePresence>
                    </Link>
                  );
                })}
              </nav>
            </div>
          </div>
        </motion.aside>
      )}
    </AnimatePresence>
  );
};

export default Sidebar;

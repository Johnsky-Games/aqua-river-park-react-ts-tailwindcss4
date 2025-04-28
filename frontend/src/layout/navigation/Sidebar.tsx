// src/layout/navigation/Sidebar.tsx
import { NavLink } from "react-router-dom";
import { FaHome, FaUser, FaCog } from "react-icons/fa";
import { motion } from "framer-motion";
import classNames from "classnames";

interface SidebarProps {
  isOpen: boolean;
}

const menuItems = [
  { label: "Inicio", path: "/admin/dashboard", icon: <FaHome /> },
  { label: "Perfil", path: "/perfil", icon: <FaUser /> },
  { label: "Configuración", path: "/ajustes", icon: <FaCog /> },
];

const Sidebar = ({ isOpen }: SidebarProps) => {
  return (
    <motion.aside
      role="complementary"
      aria-label="Sidebar principal"
      initial={false}
      animate={{ width: isOpen ? "16rem" : "4rem" }}
      transition={{ type: "spring", stiffness: 300, damping: 30 }}
      className="h-screen bg-accent2 text-white flex flex-col transition-colors duration-300"
    >
      {/* Header */}
      <div className="flex items-center justify-center md:justify-between px-4 py-4 border-b border-white/10">
        {isOpen && <h1 className="text-lg font-bold">Aqua River</h1>}
      </div>

      {/* Menu */}
      <nav
        role="navigation"
        aria-label="Enlaces principales"
        className="flex-1 overflow-y-auto mt-4 space-y-2"
      >
        {menuItems.map((item, idx) => (
          <NavLink
            to={item.path}
            key={idx}
            end
            className={({ isActive }: { isActive: boolean }) =>
              classNames(
                "flex items-center gap-3 px-4 py-2 rounded-md mx-2 transition-colors",
                isActive
                  ? "bg-accent1 text-textDark font-semibold"
                  : "hover:bg-white/10"
              )
            }
          >
            <span className="text-lg">{item.icon}</span>
            {isOpen && <span className="text-sm">{item.label}</span>}
          </NavLink>
        ))}
      </nav>

      {/* Footer */}
      {isOpen && (
        <div className="px-4 py-4 text-xs text-gray-300 border-t border-white/10">
          © {new Date().getFullYear()} Aqua River Park
        </div>
      )}
    </motion.aside>
  );
};

export default Sidebar;

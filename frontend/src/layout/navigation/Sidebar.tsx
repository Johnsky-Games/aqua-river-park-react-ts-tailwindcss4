// src/layout/navigation/Sidebar.tsx
import { Link, useLocation } from "react-router-dom";
import { FaHome, FaUser, FaCog } from "react-icons/fa";
import classNames from "classnames";

interface SidebarProps {
  isOpen: boolean;
}

const menuItems = [
  { label: "Inicio", path: "/", icon: <FaHome /> },
  { label: "Perfil", path: "/perfil", icon: <FaUser /> },
  { label: "Configuración", path: "/ajustes", icon: <FaCog /> },
];

const Sidebar = ({ isOpen }: SidebarProps) => {
  const location = useLocation();

  return (
    <aside
      className={classNames(
        "h-screen bg-accent2 text-white transition-all duration-300 flex flex-col",
        isOpen ? "w-64" : "w-16"
      )}
    >
      {/* Header */}
      <div className="flex items-center justify-center md:justify-between px-4 py-4 border-b border-white/10">
        {isOpen && <h1 className="text-lg font-bold">Aqua River</h1>}
      </div>

      {/* Menu */}
      <nav className="flex-1 overflow-y-auto mt-4 space-y-2">
        {menuItems.map((item, index) => (
          <Link
            to={item.path}
            key={index}
            className={classNames(
              "flex items-center gap-3 px-4 py-2 rounded-md mx-2 transition-colors",
              location.pathname === item.path
                ? "bg-accent1 text-textDark font-semibold"
                : "hover:bg-white/10"
            )}
          >
            <span className="text-lg">{item.icon}</span>
            {isOpen && <span className="text-sm">{item.label}</span>}
          </Link>
        ))}
      </nav>

      {/* Footer */}
      {isOpen && (
        <div className="px-4 py-4 text-xs text-gray-300 border-t border-white/10">
          © {new Date().getFullYear()} Aqua River Park
        </div>
      )}
    </aside>
  );
};

export default Sidebar;

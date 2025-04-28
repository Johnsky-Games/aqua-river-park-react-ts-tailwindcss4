// src/components/HeaderMobile.tsx
import { useEffect, useRef, useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { FaBars, FaSun, FaMoon, FaUserCircle } from "react-icons/fa";
import { motion, AnimatePresence } from "framer-motion";
import { useAuthStore } from "@/store/useAuthStore";
import { useTheme } from "@/hooks/useTheme";

interface HeaderMobileProps {
  onToggleSidebar?: () => void;
}

const HeaderMobile: React.FC<HeaderMobileProps> = ({ onToggleSidebar }) => {
  const { darkMode, toggleDarkMode } = useTheme();
  const { isLoggedIn, logout, userRole } = useAuthStore();
  const location = useLocation();
  const navigate = useNavigate();
  const menuRef = useRef<HTMLDivElement>(null);
  const [dropdownOpen, setDropdownOpen] = useState(false);

  // Cierra dropdown al cambiar de ruta
  useEffect(() => {
    setDropdownOpen(false);
  }, [location.pathname]);

  // Cierra dropdown al hacer click fuera
  useEffect(() => {
    const onClickOutside = (e: MouseEvent) => {
      if (dropdownOpen && menuRef.current && !menuRef.current.contains(e.target as Node)) {
        setDropdownOpen(false);
      }
    };
    document.addEventListener("mousedown", onClickOutside);
    return () => document.removeEventListener("mousedown", onClickOutside);
  }, [dropdownOpen]);

  const dropdownItems: Record<string, { label: string; path: string }[]> = {
    client: [
      { label: "Perfil", path: "/perfil" },
      { label: "Ajustes", path: "/ajustes" },
    ],
    admin: [
      { label: "Home", path: "/" },
      { label: "Dashboard", path: "/admin/dashboard" },
      { label: "Perfil", path: "/perfil" },
    ],
  };

  const handleLogout = () => {
    logout(false);
    navigate("/", { replace: true });
  };

  return (
    <header className="bg-primary dark:bg-bgDark text-white px-4 py-3 flex items-center justify-between shadow-md sticky top-0 z-50">
      {/* Toggle sidebar + Logo */}
      <div className="flex items-center gap-3">
        {onToggleSidebar && (
          <button onClick={onToggleSidebar} className="text-xl focus:outline-none">
            <FaBars />
          </button>
        )}
        <Link to="/" className="flex items-center gap-2">
          <img src="/ARP logo.png" alt="Logo" className="h-8" />
        </Link>
      </div>

      {/* Controles derecho */}
      <div className="flex items-center gap-4">
        {/* Dark mode toggle */}
        <button
          onClick={toggleDarkMode}
          className="p-2 rounded-full bg-white/20 hover:bg-white/30 transition"
          title={darkMode ? "Modo claro" : "Modo oscuro"}
        >
          {darkMode ? <FaSun className="text-yellow-300" /> : <FaMoon className="text-gray-800" />}
        </button>

        {/* User menu */}
        {isLoggedIn ? (
          <div ref={menuRef} className="relative">
            <button
              onClick={() => setDropdownOpen((o) => !o)}
              className="text-2xl focus:outline-none"
              aria-label="Abrir menú de usuario"
            >
              <FaUserCircle />
            </button>

            <AnimatePresence>
              {dropdownOpen && (
                <motion.div
                  initial={{ opacity: 0, scale: 0.95, y: -10 }}
                  animate={{ opacity: 1, scale: 1, y: 0 }}
                  exit={{ opacity: 0, scale: 0.95, y: -10 }}
                  transition={{ duration: 0.2 }}
                  className="absolute right-0 mt-2 w-44 bg-white dark:bg-bgDark rounded-lg shadow-lg ring-1 ring-black/10 overflow-hidden z-50 divide-y divide-gray-200 dark:divide-gray-700"
                >
                  <div className="py-1">
                    {(dropdownItems[userRole] || []).map((item, idx) => (
                      <Link
                        key={idx}
                        to={item.path}
                        className="block px-4 py-2 text-sm text-gray-800 dark:text-gray-100 hover:bg-gray-100 dark:hover:bg-gray-700 transition"
                      >
                        {item.label}
                      </Link>
                    ))}
                  </div>
                  <div className="py-1">
                    <button
                      onClick={handleLogout}
                      className="w-full text-left px-4 py-2 text-sm text-red-500 hover:bg-red-100 dark:hover:bg-red-600 dark:text-red-300 transition"
                    >
                      Cerrar sesión
                    </button>
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        ) : (
          <Link
            to="/login"
            className="px-3 py-1.5 bg-secondary hover:bg-hoverSecondary rounded-md text-white text-sm transition"
          >
            Acceder
          </Link>
        )}
      </div>
    </header>
  );
};

export default HeaderMobile;

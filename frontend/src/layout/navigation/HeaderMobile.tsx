import { useEffect } from "react";
import { Link, useLocation } from "react-router-dom";
import { FaBars, FaSun, FaMoon, FaUserCircle } from "react-icons/fa";
import { Menu, MenuButton, MenuItem } from "@headlessui/react";
import { motion, AnimatePresence } from "framer-motion";
import { useTheme } from "../../hooks/useTheme";
import { useAuthStore } from "@/store/useAuthStore";

interface HeaderMobileProps {
  onToggleSidebar?: () => void;
}

const HeaderMobile: React.FC<HeaderMobileProps> = ({ onToggleSidebar }) => {
  const { darkMode, toggleDarkMode } = useTheme();
  const { isLoggedIn, logout, userRole } = useAuthStore();
  const location = useLocation();

  const dropdownItems: Record<string, { label: string; path: string }[]> = {
    client: [
      { label: "Perfil", path: "/perfil" },
      { label: "Ajustes", path: "/ajustes" },
    ],
    admin: [
      { label: "Dashboard", path: "/admin/dashboard" },
      { label: "Perfil", path: "/perfil" },
    ],
  };

  useEffect(() => {
    // Podrías cerrar modales o limpiar algún estado aquí si lo deseas
  }, [location]);

  return (
    <header className="bg-primary dark:bg-bgDark text-textLight px-4 py-3 flex items-center justify-between shadow-md sticky top-0 z-50">
      {/* Sidebar toggle + Logo */}
      <div className="flex items-center gap-3">
        {onToggleSidebar && (
          <button onClick={onToggleSidebar} className="text-white text-xl">
            <FaBars />
          </button>
        )}
        <Link to="/" className="flex items-center gap-2">
          <img src="/ARP logo.png" alt="Logo" className="h-8" />
          <span className="font-semibold text-base">Aqua River Park</span>
        </Link>
      </div>

      {/* Dark mode + Auth */}
      <div className="flex items-center gap-4">
        <button
          onClick={toggleDarkMode}
          className="p-2 rounded-full bg-white/20 hover:bg-white/30 transition"
          title={darkMode ? "Modo claro" : "Modo oscuro"}
        >
          {darkMode ? <FaSun /> : <FaMoon />}
        </button>

        {isLoggedIn ? (
          <Menu as="div" className="relative">
            <MenuButton className="flex items-center">
              <FaUserCircle className="text-2xl" />
            </MenuButton>
            <AnimatePresence>
              <motion.div
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: 10 }}
                transition={{ duration: 0.2 }}
                className="absolute right-0 mt-2 w-44 bg-white dark:bg-bgDark rounded-md shadow-lg z-50 ring-1 ring-black/10"
              >
                <div className="py-1">
                  {(dropdownItems[userRole] || []).map(
                    (item, idx: number) => (
                      <MenuItem key={idx}>
                        {({ active }: { active: boolean }) => (
                          <Link
                            to={item.path}
                            className={`block px-4 py-2 text-sm ${
                              active
                                ? "bg-gray-100 dark:bg-gray-700 text-primary"
                                : "text-gray-800 dark:text-white"
                            }`}
                          >
                            {item.label}
                          </Link>
                        )}
                      </MenuItem>
                    )
                  )}
                </div>
                <div className="py-1">
                  <MenuItem>
                    {({ active }: { active: boolean }) => (
                      <button
                        onClick={() => logout(false)}
                        className={`block w-full text-left px-4 py-2 text-sm ${
                          active
                            ? "bg-red-100 dark:bg-red-600 text-red-700"
                            : "text-red-500"
                        }`}
                      >
                        Cerrar sesión
                      </button>
                    )}
                  </MenuItem>
                </div>
              </motion.div>
            </AnimatePresence>
          </Menu>
        ) : (
          <Link
            to="/login"
            className="bg-secondary hover:bg-hoverSecondary px-3 py-1.5 rounded-md text-white text-sm transition"
          >
            Acceder
          </Link>
        )}
      </div>
    </header>
  );
};

export default HeaderMobile;

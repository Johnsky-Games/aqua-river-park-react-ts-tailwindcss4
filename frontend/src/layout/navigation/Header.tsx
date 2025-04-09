import { Link, useLocation } from "react-router-dom";
import { FaUserCircle, FaBars } from "react-icons/fa";
import { useAuth } from "../../hooks/useAuth";
import { Menu, MenuButton, MenuItem } from "@headlessui/react";
import { AnimatePresence, motion } from "framer-motion";
import { ThemeToggle } from "../../components/ThemeToggle"; // ✅ Usando componente limpio
import { useEffect } from "react";

interface HeaderProps {
  onToggleSidebar?: () => void;
}

const Header: React.FC<HeaderProps> = ({ onToggleSidebar }) => {
  const { isLoggedIn, logout, userRole } = useAuth();
  const location = useLocation();

  // Si cambiaras algún estado visual por ruta, aquí podrías reiniciarlo
  useEffect(() => {
    // Placeholder por si necesitas limpiar algo al navegar
  }, [location]);

  const dropdownItems: Record<
    string,
    { label: string; path: string }[]
  > = {
    client: [
      { label: "Perfil", path: "/perfil" },
      { label: "Ajustes", path: "/ajustes" },
      { label: "Compras", path: "/compras" },
    ],
    admin: [
      { label: "Dashboard", path: "/admin" },
      { label: "Perfil", path: "/perfil" },
      { label: "Ajustes", path: "/ajustes" },
    ],
  };

  return (
    <header className="bg-primary dark:bg-bgDark text-white px-4 py-3 shadow-md flex items-center justify-between sticky top-0 z-50 transition-colors">
      {/* Botón para toggle del Sidebar */}
      {onToggleSidebar && (
        <button
          onClick={onToggleSidebar}
          className="md:hidden mr-3 text-white text-xl"
          aria-label="Abrir menú lateral"
        >
          <FaBars />
        </button>
      )}

      <Link to="/" className="flex items-center gap-2">
        <img
          src="../../../public/ARP logo.png"
          alt="Logo"
          className="h-10 w-auto drop-shadow"
        />
        <span className="font-bold text-lg">Aqua River Park</span>
      </Link>

      <div className="flex items-center gap-4">
        {/* Theme toggle */}
        <ThemeToggle />

        {/* Si está logueado, mostrar menú de usuario */}
        {isLoggedIn ? (
          <Menu as="div" className="relative">
            <MenuButton className="flex items-center">
              <FaUserCircle className="text-3xl" />
            </MenuButton>
            <AnimatePresence>
              <motion.div
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: 10 }}
                transition={{ duration: 0.2 }}
                className="absolute right-0 mt-2 w-48 bg-white dark:bg-bgDark rounded-md shadow-lg z-50 ring-1 ring-black/10 divide-y divide-gray-200 dark:divide-gray-700"
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
                                : "text-gray-700 dark:text-white"
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
                        onClick={logout}
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
            className="bg-secondary hover:bg-hoverSecondary px-4 py-2 rounded-md text-white transition-colors text-sm"
          >
            Iniciar sesión
          </Link>
        )}
      </div>
    </header>
  );
};

export default Header;

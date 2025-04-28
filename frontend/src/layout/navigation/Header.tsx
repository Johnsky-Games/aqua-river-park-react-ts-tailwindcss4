// src/layout/navigation/Header.tsx
import { Link, useLocation, useNavigate } from "react-router-dom";
import { FaUserCircle, FaBars, FaTimes } from "react-icons/fa";
import { Menu, MenuButton, MenuItem } from "@headlessui/react";
import { AnimatePresence, motion } from "framer-motion";
import { ThemeToggle } from "../../components/ThemeToggle";
import { useEffect, useState, useRef } from "react";
import { NavMenu } from "../../components/NavMenu";
import { useAuthModal } from "../../store/useAuthModal";
import { useAuthStore } from "@/store/useAuthStore";

// definimos aquí el subconjunto de roles que usamos en este dropdown
type Role = "client" | "admin";

const Header: React.FC = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);
  const { openModal } = useAuthModal();
  const { isLoggedIn, logout, userRole } = useAuthStore();

  // sólo manejamos clientes y administradores en el menú
  const dropdownItems: Record<Role, { label: string; path: string }[]> = {
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

  // cerrar menú móvil al navegar
  useEffect(() => {
    setMobileMenuOpen(false);
  }, [location]);

  const handleLinkClick = () => setMobileMenuOpen(false);

  // si es otro rol o vacío, simplemente mostramos array vacío
  const menuForRole = dropdownItems[userRole as Role] ?? [];

  return (
    <header className="bg-primary dark:bg-bgDark text-white shadow-md sticky top-0 z-50 transition-colors duration-300 ease-in-out">
      <div className="max-w-[1400px] mx-auto px-4 md:px-8">
        <div className="flex items-center justify-between h-14 md:h-18">
          {/* Logo y toggle móvil */}
          <div className="flex items-center gap-3">
            <button
              onClick={() => setMobileMenuOpen(v => !v)}
              className="md:hidden text-2xl transition-transform hover:scale-110"
              aria-label="Abrir menú"
            >
              {mobileMenuOpen ? <FaTimes /> : <FaBars />}
            </button>
            <Link
              to="/"
              className="flex items-center gap-2 transition-transform hover:scale-105"
            >
              <img
                src="/ARP logo.png"
                alt="Logo"
                className="h-16 pb-2 w-auto drop-shadow"
              />
            </Link>
          </div>

          {/* Menú desktop */}
          <nav className="hidden md:flex items-center gap-6 justify-center">
            <NavMenu
              isLoggedIn={isLoggedIn}
              userRole={userRole}
              mobileMenuOpen={false}
              handleLinkClick={handleLinkClick}
            />
          </nav>

          {/* Iconos derecha */}
          <div className="flex items-center gap-4">
            <ThemeToggle />
            {isLoggedIn ? (
              <Menu as="div" className="relative">
                <MenuButton className="flex items-center transition-transform hover:scale-110">
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
                      {menuForRole.map((item, idx) => (
                        <MenuItem key={idx}>
                          {({ active }) => (
                            <Link
                              to={item.path}
                              className={`block px-4 py-2 text-sm transition-all duration-200 ${
                                active
                                  ? "bg-gray-100 dark:bg-gray-700 text-primary"
                                  : "text-gray-700 dark:text-white"
                              }`}
                            >
                              {item.label}
                            </Link>
                          )}
                        </MenuItem>
                      ))}
                    </div>
                    <div className="py-1">
                      <MenuItem>
                        {({ active }) => (
                          <button
                            onClick={() => {
                              logout(false);
                              navigate("/");
                            }}
                            className={`block w-full text-left px-4 py-2 text-sm transition-all duration-200 ${
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
              <>
                <button
                  onClick={() => openModal("login")}
                  aria-label="Iniciar sesión"
                  className="md:hidden text-2xl hover:text-accent1 transition-transform"
                >
                  <FaUserCircle />
                </button>
                <button
                  onClick={() => openModal("login")}
                  className="hidden md:inline-block bg-secondary hover:bg-hoverSecondary px-4 py-2 rounded-md text-white transition-colors duration-300 text-sm"
                >
                  Iniciar sesión
                </button>
              </>
            )}
          </div>
        </div>
      </div>

      {/* Menú móvil */}
      <AnimatePresence>
        {mobileMenuOpen && (
          <motion.div
            ref={menuRef}
            initial={{ y: -20, opacity: 0 }}
            animate={{ y: 0, opacity: 1 }}
            exit={{ y: -20, opacity: 0 }}
            transition={{ duration: 0.3 }}
            className="md:hidden px-6 py-4 bg-primary dark:bg-bgDark space-y-3 shadow-md"
          >
            <NavMenu
              isLoggedIn={isLoggedIn}
              userRole={userRole}
              mobileMenuOpen={true}
              handleLinkClick={handleLinkClick}
            />
          </motion.div>
        )}
      </AnimatePresence>
    </header>
  );
};

export default Header;

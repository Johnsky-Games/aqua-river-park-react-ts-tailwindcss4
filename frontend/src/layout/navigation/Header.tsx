// src/layout/navigation/Header.tsx
import { useState, useEffect } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { FaUserCircle, FaBars, FaTimes } from "react-icons/fa";
import { Menu, MenuButton, MenuItem } from "@headlessui/react";
import { AnimatePresence, motion } from "framer-motion";
import { ThemeToggle } from "../../components/ThemeToggle";
import { NavMenu } from "../../components/NavMenu";
import { useAuthModal } from "../../store/useAuthModal";
import { useAuthStore } from "@/store/useAuthStore";
import api from "@/api/axios";

type Role = "client" | "admin";

export default function Header() {
  const location = useLocation();
  const navigate = useNavigate();
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const openModal = useAuthModal((s) => s.openModal);
  const user = useAuthStore((s) => s.user);
  const logoutStore = useAuthStore((s) => s.logout);

  const isLoggedIn = Boolean(user);
  const userRole: Role = user?.role === "admin" ? "admin" : "client";

  const dropdownItems: Record<Role, { label: string; path: string }[]> = {
    client: [
      { label: "Perfil", path: "/perfil" },
      { label: "Ajustes", path: "/ajustes" },
      { label: "Mis Compras", path: "/compras" },
    ],
    admin: [
      { label: "Dashboard", path: "/admin/dashboard" },
      { label: "Perfil", path: "/perfil" },
      { label: "Ajustes", path: "/ajustes" },
    ],
  };

  useEffect(() => {
    setMobileMenuOpen(false);
  }, [location.pathname]);

  const menuForRole = isLoggedIn ? dropdownItems[userRole] : [];

  const handleLogout = async () => {
    try {
      await api.post("/logout");
    } catch (e) {
      console.error("Logout failed:", e);
    }
    logoutStore();
    navigate("/", { replace: true });
  };

  return (
    <header className="bg-primary dark:bg-bgDark text-white sticky top-0 z-50 shadow-md">
      <div className="max-w-[1400px] mx-auto px-4 md:px-8 flex items-center justify-between h-14">
        {/* Logo + mobile toggle */}
        <div className="flex items-center gap-3">
          <button
            onClick={() => setMobileMenuOpen((v) => !v)}
            className="md:hidden text-2xl"
            aria-label="Abrir menú"
          >
            {mobileMenuOpen ? <FaTimes /> : <FaBars />}
          </button>
          <Link to="/" className="flex items-center gap-2 hover:scale-105 transition">
            <img
              src="/ARP logo.png"
              alt="Logo Aqua River Park"
              className="h-16 w-auto drop-shadow"
            />
          </Link>
        </div>

        {/* Desktop nav */}
        <nav className="hidden md:flex items-center gap-6">
          <NavMenu
            isLoggedIn={isLoggedIn}
            userRole={userRole}
            mobileMenuOpen={false}
            handleLinkClick={() => setMobileMenuOpen(false)}
          />
        </nav>

        {/* Right-side icons */}
        <div className="flex items-center gap-4">
          <ThemeToggle />

          {isLoggedIn ? (
            <Menu as="div" className="relative">
              <MenuButton className="flex items-center space-x-2 focus:outline-none">
                <FaUserCircle className="text-2xl" />
                <div className="text-left">
                  <div className="text-sm font-medium">{user!.name}</div>
                  <div className="text-xs uppercase">{user!.role}</div>
                </div>
              </MenuButton>
              <AnimatePresence>
                <motion.div
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: 10 }}
                  transition={{ duration: 0.2 }}
                  className="absolute right-0 mt-2 w-48 bg-white dark:bg-bgDark rounded-md shadow-lg ring-1 ring-black/10 divide-y divide-gray-200 dark:divide-gray-700 z-50"
                >
                  <div className="py-1">
                    {menuForRole.map((item, idx) => (
                      <MenuItem key={idx}>
                        {({ active }) => (
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
                    ))}
                  </div>
                  <div className="py-1">
                    <MenuItem>
                      {({ active }) => (
                        <button
                          onClick={handleLogout}
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
            <>
              <button
                onClick={() => openModal("login")}
                className="md:hidden text-2xl"
                aria-label="Iniciar sesión"
              >
                <FaUserCircle />
              </button>
              <button
                onClick={() => openModal("login")}
                className="hidden md:inline-block bg-secondary px-4 py-2 rounded-md text-white"
              >
                Iniciar sesión
              </button>
            </>
          )}
        </div>
      </div>

      {/* Mobile nav */}
      <AnimatePresence>
        {mobileMenuOpen && (
          <motion.div
            initial={{ y: -20, opacity: 0 }}
            animate={{ y: 0, opacity: 1 }}
            exit={{ y: -20, opacity: 0 }}
            transition={{ duration: 0.3 }}
            className="md:hidden bg-primary dark:bg-bgDark px-6 py-4 space-y-3"
          >
            <NavMenu
              isLoggedIn={isLoggedIn}
              userRole={userRole}
              mobileMenuOpen={true}
              handleLinkClick={() => setMobileMenuOpen(false)}
            />
          </motion.div>
        )}
      </AnimatePresence>
    </header>
  );
}

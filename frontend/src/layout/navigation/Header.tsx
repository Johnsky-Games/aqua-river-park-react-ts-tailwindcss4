// src/layout/navigation/Header.tsx
import { useState, useEffect, useRef } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { FaUserCircle, FaBars, FaTimes } from "react-icons/fa";
import { AnimatePresence, motion } from "framer-motion";
import { ThemeToggle } from "../../components/ThemeToggle";
import { NavMenu } from "../../components/NavMenu";
import { useAuthModal } from "../../store/useAuthModal";
import { useAuthStore } from "@/store/useAuthStore";
import api from "@/api/axios";
import { isAxiosError } from "axios";

type Role = "client" | "admin";

export default function Header() {
  const location = useLocation();
  const navigate = useNavigate();

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
      { label: "Home", path: "/" },
      { label: "Dashboard", path: "/admin/dashboard" },
      { label: "Perfil", path: "/perfil" },
    ],
  };

  // para menú mobile (Headless nav)
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  useEffect(() => {
    setMobileMenuOpen(false);
  }, [location.pathname]);

  // para el dropdown de usuario
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);

  // cerrar dropdown al cambiar ruta
  useEffect(() => {
    setDropdownOpen(false);
  }, [location.pathname]);

  // cerrar dropdown al click fuera
  useEffect(() => {
    const onClickOutside = (e: MouseEvent) => {
      if (
        dropdownOpen &&
        menuRef.current &&
        !menuRef.current.contains(e.target as Node)
      ) {
        setDropdownOpen(false);
      }
    };
    document.addEventListener("mousedown", onClickOutside);
    return () => {
      document.removeEventListener("mousedown", onClickOutside);
    };
  }, [dropdownOpen]);

  const handleLogout = async () => {
    try {
      await api.post("/logout");
    } catch (error: unknown) {
      if (isAxiosError(error)) {
        if (error.response?.status !== 401) console.error("Logout failed:", error);
      } else {
        console.error("Unexpected logout error:", error);
      }
    } finally {
      logoutStore();
      navigate("/", { replace: true });
    }
  };

  const menuForRole = isLoggedIn ? dropdownItems[userRole] : [];

  return (
    <header className="bg-primary dark:bg-bgDark text-white sticky top-0 z-50 shadow-md">
      <div className="max-w-[1400px] mx-auto px-4 md:px-8 flex items-center justify-between h-14">
        {/* Logo + toggle mobile */}
        <div className="flex items-center gap-3">
          <button
            onClick={() => setMobileMenuOpen((v) => !v)}
            className="md:hidden text-2xl"
            aria-label="Abrir menú"
          >
            {mobileMenuOpen ? <FaTimes /> : <FaBars />}
          </button>
          <Link to="/" className="flex items-center gap-2 hover:scale-105 transition">
            <img src="/ARP logo.png" alt="Logo Aqua River Park" className="h-16 w-auto drop-shadow" />
          </Link>
        </div>

        {/* Navegación desktop */}
        <nav className="hidden md:flex items-center gap-6">
          <NavMenu
            isLoggedIn={isLoggedIn}
            userRole={userRole}
            mobileMenuOpen={false}
            handleLinkClick={() => setMobileMenuOpen(false)}
          />
        </nav>

        {/* Iconos derecha */}
        <div className="flex items-center gap-4">
          <ThemeToggle />

          {isLoggedIn && user ? (
            <div className="relative" ref={menuRef}>
              <button
                onClick={() => setDropdownOpen((o) => !o)}
                className="flex items-center space-x-2 focus:outline-none"
                aria-label="Abrir menú de usuario"
              >
                <FaUserCircle className="text-2xl" />
                <div className="text-left">
                  <div className="text-sm font-medium">{user.name}</div>
                  <div className="text-xs uppercase">{user.role}</div>
                </div>
              </button>

              <AnimatePresence>
                {dropdownOpen && (
                  <motion.div
                    initial={{ opacity: 0, scale: 0.9, y: -10 }}
                    animate={{ opacity: 1, scale: 1, y: 0 }}
                    exit={{ opacity: 0, scale: 0.9, y: -10 }}
                    transition={{ type: "spring", stiffness: 150, damping: 15 }}
                    className="absolute right-0 mt-2 w-44 bg-white dark:bg-bgDark rounded-lg shadow-lg ring-1 ring-black/10 divide-y divide-gray-200 dark:divide-gray-700 z-50 overflow-hidden"
                  >
                    {/* Encabezado usuario */}
                    <div className="px-4 py-2 border-b dark:border-gray-700">
                      <div className="text-sm font-medium text-primary dark:text-white">
                        {user.name}
                      </div>
                      <div className="text-xs uppercase text-secondary dark:text-gray-400">
                        {user.role}
                      </div>
                    </div>
                    {/* Opciones */}
                    <div className="py-1">
                      {menuForRole.map((item, idx) => (
                        <Link
                          key={idx}
                          to={item.path}
                          className="block px-4 py-2 text-sm text-gray-800 dark:text-gray-100 hover:bg-gray-100 dark:hover:bg-gray-700 transition"
                          onClick={() => setDropdownOpen(false)}
                        >
                          {item.label}
                        </Link>
                      ))}
                    </div>
                    {/* Logout */}
                    <div className="py-1">
                      <button
                        onClick={handleLogout}
                        className="w-full text-left px-4 py-2 text-sm text-red-500 hover:bg-red-100 dark:hover:bg-red-600 transition"
                      >
                        Cerrar sesión
                      </button>
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
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

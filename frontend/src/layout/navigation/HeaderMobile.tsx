// src/layout/navigation/HeaderMobile.tsx
import { useEffect, useRef, useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { FaSun, FaMoon, FaUserCircle } from "react-icons/fa";
import { BsList } from "react-icons/bs";
import { motion, AnimatePresence } from "framer-motion";
import { useAuthStore } from "@/store/useAuthStore";
import { useTheme } from "@/hooks/useTheme";
import api from "@/api/axios";
import { isAxiosError } from "axios";

interface HeaderMobileProps {
  isSidebarOpen: boolean;
  onToggle: () => void;
  isMobile: boolean;
}

type Role = "client" | "admin";

export default function HeaderMobile({
  isSidebarOpen,
  onToggle,
  isMobile,
}: HeaderMobileProps) {
  const { darkMode, toggleDarkMode } = useTheme();
  const user = useAuthStore((s) => s.user);
  const logoutStore = useAuthStore((s) => s.logout);
  const navigate = useNavigate();
  const location = useLocation();
  const menuRef = useRef<HTMLDivElement>(null);
  const [dropdownOpen, setDropdownOpen] = useState(false);

  const isLoggedIn = Boolean(user);
  const role: Role = user?.role === "admin" ? "admin" : "client";

  const dropdownItems: Record<Role, { label: string; path: string }[]> = {
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

  // Cerrar dropdown al cambiar de ruta
  useEffect(() => {
    setDropdownOpen(false);
  }, [location.pathname]);

  // Cerrar dropdown al click fuera
  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (
        dropdownOpen &&
        menuRef.current &&
        !menuRef.current.contains(e.target as Node)
      ) {
        setDropdownOpen(false);
      }
    };
    document.addEventListener("mousedown", handleClickOutside);
    return () => {
      document.removeEventListener("mousedown", handleClickOutside);
    };
  }, [dropdownOpen]);

  const handleLogout = async () => {
    try {
      await api.post("/logout");
      console.log("Logout en backend exitoso");
    } catch (error: unknown) {
      if (isAxiosError(error)) {
        // 401 = sesión expirada, no lo tratamos como "error real"
        if (error.response?.status !== 401) {
          console.error("Logout failed:", error);
        }
      } else {
        console.error("Error inesperado al hacer logout:", error);
      }
    } finally {
      // Siempre limpiamos el store y redirigimos
      logoutStore();
      navigate("/", { replace: true });
    }
  };

  return (
    <motion.header
      layout
      initial={false}
      animate={{
        left: isMobile ? 0 : isSidebarOpen ? "16rem" : "4rem",
        width: isMobile
          ? "100%"
          : isSidebarOpen
          ? "calc(100% - 16rem)"
          : "calc(100% - 4rem)",
      }}
      transition={{ type: "tween", duration: 0.3, ease: "easeInOut" }}
      className="fixed top-0 bg-primary dark:bg-bgDark text-white flex items-center justify-between px-4 py-3 shadow z-40"
    >
      <div className="flex items-center gap-4">
        {isMobile && (
          <button
            onClick={onToggle}
            className="p-2 rounded hover:bg-accent1 transition focus:outline-none"
            aria-label="Toggle sidebar"
          >
            <BsList size={20} />
          </button>
        )}
        <Link to="/" className="flex items-center">
          <img src="/ARP logo.png" alt="Logo Aqua River Park" className="h-8" />
        </Link>
      </div>

      <div className="flex items-center gap-4">
        {/* Theme toggle */}
        <button
          onClick={toggleDarkMode}
          className="p-2 rounded-full bg-white/20 hover:bg-white/30 transition"
          title={darkMode ? "Modo claro" : "Modo oscuro"}
        >
          {darkMode ? <FaSun className="text-yellow-300" /> : <FaMoon />}
        </button>

        {isLoggedIn && user ? (
          <div ref={menuRef} className="relative">
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
                  <div className="px-4 py-2 border-b dark:border-gray-700">
                    <div className="text-sm text-accent2 font-medium">
                      {user.name}
                    </div>
                    <div className="text-xs text-secondary uppercase">
                      {user.role}
                    </div>
                  </div>
                  {dropdownItems[role].map((item, i) => (
                    <Link
                      key={i}
                      to={item.path}
                      className="block px-4 py-2 text-sm text-gray-800 dark:text-gray-100 hover:bg-gray-100 dark:hover:bg-gray-700 transition"
                      onClick={() => setDropdownOpen(false)}
                    >
                      {item.label}
                    </Link>
                  ))}
                  <button
                    onClick={handleLogout}
                    className="w-full text-left px-4 py-2 text-sm text-red-500 hover:bg-red-100 dark:hover:bg-red-600 transition"
                  >
                    Cerrar sesión
                  </button>
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
    </motion.header>
  );
}

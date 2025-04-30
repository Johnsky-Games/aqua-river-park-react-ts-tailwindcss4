import { useEffect, useRef, useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { FaSun, FaMoon, FaUserCircle } from "react-icons/fa";
import { BsList } from "react-icons/bs";
import { motion, AnimatePresence } from "framer-motion";
import { useAuthStore } from "@/store/useAuthStore";
import { useTheme } from "@/hooks/useTheme";

interface HeaderMobileProps {
  isSidebarOpen: boolean;
  onToggle: () => void;
  isMobile: boolean;
}

const HeaderMobile: React.FC<HeaderMobileProps> = ({
  isSidebarOpen,
  onToggle,
  isMobile,
}) => {
  const { darkMode, toggleDarkMode } = useTheme();
  const { isLoggedIn, logout, userRole, userName } = useAuthStore();
  const location = useLocation();
  const navigate = useNavigate();
  const menuRef = useRef<HTMLDivElement>(null);
  const [dropdownOpen, setDropdownOpen] = useState<boolean>(false);

  useEffect(() => setDropdownOpen(false), [location.pathname]);
  useEffect(() => {
    const handler = (e: MouseEvent) =>
      dropdownOpen &&
      menuRef.current &&
      !menuRef.current.contains(e.target as Node) &&
      setDropdownOpen(false);
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
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
    <motion.header
      layout // <--- activa animación de layout
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
          <img src="/ARP logo.png" alt="Logo" className="h-8" />
        </Link>

        {/* aquí mostramos rol y nombre */}

        {!isMobile && isLoggedIn && (
          <span className="ml-4 text-sm font-medium">
            {`${userRole.charAt(0).toUpperCase() + userRole.slice(1)}:`}
            <strong className="ml-1">{userName}</strong>
          </span>
        )}
      </div>

      <div className="flex items-center gap-4">
        <button
          onClick={toggleDarkMode}
          className="p-2 rounded-full bg-white/20 hover:bg-white/30 transition"
          title={darkMode ? "Modo claro" : "Modo oscuro"}
        >
          {darkMode ? (
            <FaSun className="text-yellow-300" />
          ) : (
            <FaMoon className="text-gray-800" />
          )}
        </button>

        {isLoggedIn ? (
          <div ref={menuRef} className="relative">
            <button
              onClick={() => setDropdownOpen((o) => !o)}
              className="text-2xl focus:outline-none"
            >
              <FaUserCircle />
            </button>
            <AnimatePresence>
              {dropdownOpen && (
                <motion.div
                  initial={{ opacity: 0, scale: 0.9, y: -10 }}
                  animate={{ opacity: 1, scale: 1, y: 0 }}
                  exit={{ opacity: 0, scale: 0.9, y: -10 }}
                  transition={{ type: "spring", stiffness: 150, damping: 15 }}
                  className="absolute right-0 mt-2 w-44 bg-white dark:bg-bgDark rounded-lg shadow-lg ring-1 ring-black/10 overflow-hidden z-50 divide-y divide-gray-200 dark:divide-gray-700"
                >
                  {dropdownItems[userRole]?.map((item, i) => (
                    <Link
                      key={i}
                      to={item.path}
                      className="block px-4 py-2 text-sm text-gray-800 dark:text-gray-100 hover:bg-gray-100 dark:hover:bg-gray-700 transition"
                    >
                      {item.label}
                    </Link>
                  ))}
                  <button
                    onClick={handleLogout}
                    className="w-full text-left px-4 py-2 text-sm text-red-500 hover:bg-red-100 dark:hover:bg-red-600 dark:text-red-300 transition"
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
};

export default HeaderMobile;

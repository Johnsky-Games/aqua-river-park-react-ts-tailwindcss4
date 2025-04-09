import { Link, useLocation, useNavigate } from "react-router-dom";
import {
  FaUserCircle,
  FaBars,
  FaTimes,
} from "react-icons/fa";
import { useAuth } from "../../hooks/useAuth";
import { Menu, MenuButton, MenuItem } from "@headlessui/react";
import { AnimatePresence, motion } from "framer-motion";
import { ThemeToggle } from "../../components/ThemeToggle";
import { useEffect, useRef, useState } from "react";
import { ChevronDownIcon } from "@heroicons/react/20/solid";

const Header: React.FC = () => {
  const { isLoggedIn, logout, userRole } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();
  const navRef = useRef<HTMLDivElement>(null);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [hoveredMenu, setHoveredMenu] = useState<string | null>(null);

  useEffect(() => {
    setMobileMenuOpen(false);
  }, [location]);

  useEffect(() => {
    if (isLoggedIn && userRole === "admin") {
      navigate("/admin");
    }
  }, [isLoggedIn, userRole, navigate]);

  const handleLinkClick = () => setMobileMenuOpen(false);

  const dropdownItems = {
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
    <header className="bg-primary dark:bg-bgDark text-white px-4 py-3 shadow-md sticky top-0 z-50 transition-colors">
      <div className="flex items-center justify-between max-w-[1400px] mx-auto">
        {/* Logo + Toggle */}
        <div className="flex items-center gap-3 ml-8">
          <button
            className="md:hidden text-xl"
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            aria-label="Menú"
          >
            {mobileMenuOpen ? <FaTimes /> : <FaBars />}
          </button>

          <Link to="/" className="flex items-center gap-2">
            <img
              src="/ARP logo.png"
              alt="Logo"
              className="h-10 w-auto drop-shadow"
            />
            <span className="font-bold text-lg">Aqua River Park</span>
          </Link>
        </div>

        {/* Nav centrado */}
        {(!isLoggedIn || userRole === "client") && (
          <nav
            ref={navRef}
            className={`${
              mobileMenuOpen ? "flex" : "hidden"
            } md:flex flex-col md:flex-row md:items-center md:justify-center gap-4 text-center absolute md:static top-full left-0 w-full md:w-auto bg-primary dark:bg-bgDark md:bg-transparent px-6 py-4 md:py-0 z-40 transition-all duration-300 justify-center`}
          >
            <Link
              to="/"
              onClick={handleLinkClick}
              className="hover:text-accent1 transition"
            >
              Inicio
            </Link>
            <Link
              to="/precios"
              onClick={handleLinkClick}
              className="hover:text-accent1 transition"
            >
              Precios
            </Link>

            {(["mas", "servicios"] as const).map((menuKey) => (
              <div
                key={menuKey}
                className="relative group flex items-center justify-center"
                onMouseEnter={() => setHoveredMenu(menuKey)}
                onMouseLeave={() => setHoveredMenu(null)}
              >
                <button className="flex items-center gap-1 font-medium capitalize hover:text-accent1">
                  {menuKey} <ChevronDownIcon className="h-5 w-5" />
                </button>
                <AnimatePresence>
                  {hoveredMenu === menuKey && (
                    <motion.div
                      initial={{ opacity: 0, scale: 0.95 }}
                      animate={{ opacity: 1, scale: 1 }}
                      exit={{ opacity: 0, scale: 0.95 }}
                      transition={{ duration: 0.2 }}
                      className="absolute left-1/2 transform -translate-x-1/2 top-full mt-2 w-56 max-h-[70vh] overflow-y-auto backdrop-blur-md bg-bgLight/30 dark:bg-bgDark/40 text-textDark dark:text-textLight rounded-xl shadow-xl ring-1 ring-bgLight/25 z-50"
                    >
                      {(menuKey === "mas"
                        ? ["Galeria", "Horarios", "Eventos", "Blog", "Reserva"]
                        : [
                            "Piscinas y Tobogán",
                            "Bosque Perdido de los Dinosaurios",
                            "Botes y Juegos de Mesa",
                            "Zona VIP",
                            "Restaurantes",
                          ]
                      ).map((label, idx) => (
                        <Link
                          key={idx}
                          to={`/${menuKey}#${label
                            .toLowerCase()
                            .replace(/\s+/g, "-")}`}
                          onClick={handleLinkClick}
                          className="block px-4 py-2 text-sm font-semibold hover:bg-accent2/80 hover:text-textLight/90 dark:hover:bg-bgLight/80 dark:hover:text-textDark/90"
                        >
                          {label}
                        </Link>
                      ))}
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>
            ))}

            {isLoggedIn && userRole === "client" && (
              <>
                <Link
                  to="/compras"
                  onClick={handleLinkClick}
                  className="hover:text-accent1 transition font-medium"
                >
                  Mis Compras
                </Link>
                <Link
                  to="/perfil"
                  onClick={handleLinkClick}
                  className="hover:text-accent1 transition font-medium"
                >
                  Mi Perfil
                </Link>
              </>
            )}
          </nav>
        )}

        {/* Iconos */}
        <div className="flex items-center gap-4 mr-8">
          <ThemeToggle />
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
                    {(dropdownItems[userRole] || []).map((item, idx) => (
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
      </div>
    </header>
  );
};

export default Header;

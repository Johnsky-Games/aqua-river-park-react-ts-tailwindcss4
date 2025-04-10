import { Link } from "react-router-dom";
import { AnimatePresence, motion } from "framer-motion";
import {
  ChevronDownIcon,
  PlusIcon,
  MinusIcon,
} from "@heroicons/react/20/solid";
import { useState, useRef, useEffect } from "react";

interface Props {
  isLoggedIn: boolean;
  userRole: string;
  mobileMenuOpen: boolean;
  handleLinkClick: () => void;
}

export const NavMenu: React.FC<Props> = ({
  isLoggedIn,
  userRole,
  mobileMenuOpen,
  handleLinkClick,
}) => {
  const [hoveredMenu, setHoveredMenu] = useState<string | null>(null);
  const menuRef = useRef<HTMLDivElement>(null);

  const menus = [
    { label: "Inicio", to: "/" },
    { label: "Precios", to: "/precios" },
  ];

  const dropdowns = {
    mas: ["Galeria", "Horarios", "Eventos", "Blog", "Reserva"],
    servicios: [
      "Piscinas y Tobogán",
      "Bosque Perdido de los Dinosaurios",
      "Botes y Juegos de Mesa",
      "Zona VIP",
      "Restaurantes",
    ],
  };

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (
        mobileMenuOpen &&
        menuRef.current &&
        !menuRef.current.contains(event.target as Node)
      ) {
        setHoveredMenu(null);
      }
    };

    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, [mobileMenuOpen]);

  return (
    <div
      ref={menuRef}
      className={`flex transition-all duration-300 ${
        mobileMenuOpen
          ? "flex-col items-center space-y-2 mt-4 text-center"
          : "flex-row items-center gap-6"
      } w-full md:w-auto justify-center`}
    >
      {/* Enlaces simples */}
      {menus.map((item, idx) => (
        <Link
          key={idx}
          to={item.to}
          onClick={handleLinkClick}
          className="hover:text-accent1 font-medium transition-colors duration-200"
        >
          {item.label}
        </Link>
      ))}

      {/* Menús desplegables */}
      {(Object.keys(dropdowns) as Array<keyof typeof dropdowns>).map((key) => (
        <div
          key={key}
          className={`relative group ${mobileMenuOpen ? "w-full" : "w-auto"}`}
          onMouseEnter={() => !mobileMenuOpen && setHoveredMenu(key)}
          onMouseLeave={() => !mobileMenuOpen && setHoveredMenu(null)}
        >
          <button
            onClick={() =>
              mobileMenuOpen
                ? setHoveredMenu((prev) => (prev === key ? null : key))
                : null
            }
            className="flex items-center justify-between gap-1 w-full font-medium capitalize hover:text-accent1 transition duration-200"
          >
            {key}
            {mobileMenuOpen ? (
              hoveredMenu === key ? (
                <MinusIcon className="h-5 w-5 transition-all duration-300 text-accent1" />
              ) : (
                <PlusIcon className="h-5 w-5 transition-all duration-300" />
              )
            ) : (
              <motion.div
                animate={{
                  rotate: hoveredMenu === key ? 180 : 0,
                }}
                style={{
                  color:
                    hoveredMenu === key
                      ? "var(--color-accent1)"
                      : "var(--color-textLight)",
                }}
                transition={{ duration: 0.3 }}
              >
                <ChevronDownIcon className="h-5 w-5 text-current transition-all duration-300" />
              </motion.div>
            )}
          </button>

          <AnimatePresence initial={false}>
            {hoveredMenu === key && (
              <motion.div
                key={key}
                initial={{ height: 0, opacity: 0 }}
                animate={{ height: "auto", opacity: 1 }}
                exit={{ height: 0, opacity: 0 }}
                transition={{ duration: 0.3, ease: "easeInOut" }}
                className={`overflow-hidden ${
                  mobileMenuOpen
                    ? "w-full mt-1"
                    : "absolute left-1/2 -translate-x-1/2 top-full mt-2 w-56"
                } backdrop-blur-md bg-bgLight/30 dark:bg-bgDark/40 text-textDark dark:text-textLight rounded-xl shadow-xl ring-1 ring-bgLight/25 z-50`}
              >
                {dropdowns[key].map((label, idx) => (
                  <Link
                    key={idx}
                    to={`/${key}#${label.toLowerCase().replace(/\s+/g, "-")}`}
                    onClick={handleLinkClick}
                    className="block px-4 py-2 text-sm font-semibold hover:bg-accent2/80 hover:text-textLight/90 dark:hover:bg-bgLight/80 dark:hover:text-textDark/90 transition-all duration-200"
                  >
                    {label}
                  </Link>
                ))}
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      ))}

      {/* Links para cliente logueado */}
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
    </div>
  );
};

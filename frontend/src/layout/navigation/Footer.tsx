import {
    FaMapMarkerAlt,
    FaClock,
    FaFacebook,
    FaInstagram,
    FaWhatsapp,
    FaTiktok,
    FaYoutube,
  } from "react-icons/fa";
  import { Link } from "react-router-dom";
  
  const Footer = () => {
    return (
      <footer className="bg-accent2 text-white py-16">
        <div className="container mx-auto px-4 grid grid-cols-1 md:grid-cols-4 gap-8 text-center md:text-left transition-all duration-300">
          {/* Logo + Descripción */}
          <div className="flex flex-col items-center md:items-start">
            <Link to="/" className="flex items-center gap-2">
              <img
                src="../../../public/ARP logo.png"
                alt="Logo de Aqua River Park"
                className="h-20 mb-4 drop-shadow-xl"
              />
            </Link>
            <p className="text-sm opacity-90 max-w-xs">
              Un parque acuático temático con diversión para toda la familia.
            </p>
          </div>
  
          {/* Enlaces rápidos */}
          <div>
            <h3 className="text-xl font-bold mb-4 text-accent1">Enlaces Rápidos</h3>
            <ul className="space-y-2">
              {[
                { href: "#inicio", text: "Inicio" },
                { href: "#atracciones", text: "Atracciones" },
                { href: "#horarios", text: "Horarios" },
                { href: "#promociones", text: "Promociones" },
              ].map((item, index) => (
                <li key={index}>
                  <a
                    href={item.href}
                    className="hover:text-primary transition-colors"
                  >
                    {item.text}
                  </a>
                </li>
              ))}
            </ul>
          </div>
  
          {/* Información de contacto */}
          <div>
            <h3 className="text-xl font-bold mb-4 text-accent1">Contacto</h3>
            <ul className="space-y-2 text-sm">
              <li className="flex items-center justify-center md:justify-start">
                <FaMapMarkerAlt className="mr-2 text-secondary" />
                Calle Principal 123, Ciudad
              </li>
              <li className="flex items-center justify-center md:justify-start">
                <FaClock className="mr-2 text-secondary" />
                9:00 AM - 5:00 PM
              </li>
            </ul>
          </div>
  
          {/* Redes Sociales */}
          <div>
            <h3 className="text-xl font-bold mb-4 text-accent1">Redes Sociales</h3>
            <div className="flex justify-center md:justify-start space-x-4">
              {[
                { icon: FaFacebook, color: "facebook", title: "Facebook" },
                { icon: FaInstagram, color: "instagram", title: "Instagram" },
                { icon: FaWhatsapp, color: "whatsapp", title: "Whatsapp" },
                { icon: FaTiktok, color: "tiktok", title: "TikTok" },
                { icon: FaYoutube, color: "youtube", title: "YouTube" },
              ].map(({ icon: Icon, color, title }, index) => (
                <a
                  key={index}
                  href="#"
                  className="transition-all transform hover:scale-110"
                  title={title}
                  style={{
                    color: `var(--color-${color})`,
                    textShadow: `0 0 6px var(--color-${color})`,
                  }}
                >
                  <Icon size={24} />
                </a>
              ))}
            </div>
          </div>
        </div>
  
        {/* Pie de página */}
        <div className="mt-10 text-center text-xs text-white/70">
          © {new Date().getFullYear()} Aqua River Park. Todos los derechos reservados.
        </div>
      </footer>
    );
  };
  
  export default Footer;
  
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
  const socialLinks = [
    {
      icon: FaFacebook,
      color: "facebook",
      title: "Facebook",
      href: "https://www.facebook.com/aquariverpark",
    },
    {
      icon: FaInstagram,
      color: "instagram",
      title: "Instagram",
      href: "https://www.instagram.com/aquariverpark/#",
    },
    {
      icon: FaWhatsapp,
      color: "whatsapp",
      title: "Whatsapp",
      href: "https://wa.me/tunumerodewhatsapp",
    },
    {
      icon: FaTiktok,
      color: "tiktok",
      title: "TikTok",
      href: "https://www.tiktok.com/@aquariverpark1",
    },
    {
      icon: FaYoutube,
      color: "youtube",
      title: "YouTube",
      href: "https://www.youtube.com/aquariverpark",
    },
  ];

  return (
    <footer className="bg-accent2 text-textLight dark:bg-neutral-900 dark:text-gray-200 py-4 pt-8 transition-colors">
      <div className="container mx-auto px-4 grid grid-cols-1 md:grid-cols-4 gap-8 text-center md:text-left">
        {/* Logo + Descripción */}
        <div className="flex flex-col items-center justify-center md:items-start">
          <Link to="/" className="flex items-center gap-2">
            <img
              src="/ARP logo.png"
              alt="Logo de Aqua River Park"
              className="h-20 mb-4 drop-shadow-xl md:px-5"
            />
          </Link>
          <p className="text-sm opacity-90 max-w-xs md:px-8">
            Un parque acuático temático con diversión para toda la familia.
          </p>
        </div>

        {/* Enlaces rápidos */}
        <div>
          <h3 className="text-xl font-bold mb-4 text-accent1">Enlaces Rápidos</h3>
          <ul className="space-y-2">
            {[
              { href: "/", text: "Inicio" },
              { href: "#attractions", text: "Atracciones" },
              { href: "#horarios", text: "Horarios" },
              { href: "#promociones", text: "Promociones" },
            ].map((item, index) => (
              <li key={index}>
                <a
                  href={item.href}
                  className="hover:text-accent1 transition-colors"
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
              Guayllabamba - Rio Pisque, Quito, Ecuador.
            </li>
            <li className="flex items-center justify-center md:justify-start">
              <FaClock className="mr-2 text-secondary" />
              Lunes a Viernes: 09:00 AM - 06:00 PM
            </li>
            <li className="flex items-center justify-center md:justify-start">
              Fines de semana y feriados: 08:00 AM - 07:00 PM
            </li>
          </ul>
        </div>

        {/* Redes Sociales */}
        <div>
          <h3 className="text-xl font-bold mb-4 text-accent1">Redes Sociales</h3>
          <div className="flex justify-center md:justify-start space-x-4">
            {socialLinks.map(({ icon: Icon, color, title, href }, index) => (
              <a
                key={index}
                href={href}
                className="transition-all transform hover:scale-110"
                title={title}
                target="_blank"
                rel="noopener noreferrer"
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
      <div className="mt-10 text-center text-xs text-white/70 dark:text-gray-400">
        © {new Date().getFullYear()} Aqua River Park. Todos los derechos reservados.
      </div>
    </footer>
  );
};

export default Footer;

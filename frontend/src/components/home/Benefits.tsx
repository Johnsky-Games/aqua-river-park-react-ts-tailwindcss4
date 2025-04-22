// components/Benefits.tsx
import { FaSwimmer, FaTree, FaUtensils, FaShieldAlt, FaTicketAlt } from "react-icons/fa";
import { motion } from "framer-motion";

const benefits = [
  {
    icon: <FaSwimmer size={40} className="text-cyan-600 group-hover:text-purple-600 transition-colors" />,
    title: "Piscinas",
    description: "Diversión refrescante para toda la familia.",
  },
  {
    icon: <FaTree size={40} className="text-green-600 group-hover:text-purple-600 transition-colors" />,
    title: "Naturaleza",
    description: "Rodeado de un ambiente natural y relajante.",
  },
  {
    icon: <FaUtensils size={40} className="text-amber-600 group-hover:text-purple-600 transition-colors" />,
    title: "Gastronomía",
    description: "Sabores únicos en cada rincón.",
  },
  {
    icon: <FaShieldAlt size={40} className="text-red-600 group-hover:text-purple-600 transition-colors" />,
    title: "Seguridad",
    description: "Personal capacitado para tu tranquilidad.",
  },
  {
    icon: <FaTicketAlt size={40} className="text-blue-600 group-hover:text-purple-600 transition-colors" />,
    title: "Promociones",
    description: "Premios por cada 6 facturas registradas.",
  },
];

export const Benefits = () => {
  return (
    <section className="py-16 bg-secondary/10 dark:bg-neutral-900 text-center" id="benefits">
      <div className="max-w-6xl mx-auto px-4">
        <motion.h2
          initial={{ opacity: 0, y: -30 }}
          whileInView={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
          className="text-3xl font-bold mb-6 text-primary dark:text-white"
        >
          ¿Por qué elegir Aqua River Park?
        </motion.h2>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-6 sm:gap-8">
          {benefits.map((item, index) => (
            <motion.div
              key={index}
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ delay: index * 0.1, duration: 0.5 }}
            >
              <div className="group bg-white dark:bg-neutral-800 shadow-md hover:bg-accent2/15 dark:hover:bg-bgDark cursor-pointer hover:shadow-xl rounded-2xl p-6 h-full transition duration-300">
                <div className="mb-4 flex justify-center">{item.icon}</div>
                <h3 className="text-xl font-semibold text-textDark dark:text-white">{item.title}</h3>
                <p className="mt-2 text-gray-600 dark:text-gray-300">{item.description}</p>
              </div>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
};

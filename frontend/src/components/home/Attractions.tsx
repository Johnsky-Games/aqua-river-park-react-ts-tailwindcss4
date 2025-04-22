// components/Attractions.tsx
import { FaWater, FaMountain, FaSpa, FaFish, FaSun, FaBiking } from "react-icons/fa";
import { motion } from "framer-motion";

const attractions = [
  {
    icon: <FaWater size={36} className="text-cyan-500 group-hover:text-purple-600 transition-colors" />,
    title: "Río y Toboganes",
    description: "Deslízate en nuestros toboganes o relájate en el río lento.",
  },
  {
    icon: <FaMountain size={36} className="text-amber-600 group-hover:text-purple-600 transition-colors" />,
    title: "Zona Natural",
    description: "Senderos rodeados de vegetación y aire puro.",
  },
  {
    icon: <FaSpa size={36} className="text-pink-500 group-hover:text-purple-600 transition-colors" />,
    title: "Área Zen",
    description: "Relájate en nuestra zona de masajes y spa natural.",
  },
  {
    icon: <FaFish size={36} className="text-blue-500 group-hover:text-purple-600 transition-colors" />,
    title: "Lago con Peces",
    description: "Ideal para fotos y paseos familiares.",
  },
  {
    icon: <FaSun size={36} className="text-yellow-500 group-hover:text-purple-600 transition-colors" />,
    title: "Solarium",
    description: "Disfruta del sol en un espacio abierto y cómodo.",
  },
  {
    icon: <FaBiking size={36} className="text-lime-500 group-hover:text-purple-600 transition-colors" />,
    title: "Zona Deportiva",
    description: "Canchas, rutas para bicicletas y más diversión activa.",
  },
];

export const Attractions = () => {
  return (
    <section id="attractions" className="py-16 bg-bgLight dark:bg-bgDark text-center">
      <div className="max-w-6xl mx-auto px-4">
        <motion.h2
          initial={{ opacity: 0, y: -30 }}
          whileInView={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
          className="text-3xl font-bold text-primary dark:text-white mb-10"
        >
          Atracciones Destacadas
        </motion.h2>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-8 cursor-pointer">
          {attractions.map((item, index) => (
            <motion.div
              key={index}
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ delay: index * 0.1, duration: 0.5 }}
              className="group bg-white dark:bg-neutral-800 hover:bg-secondary/20 dark:hover:bg-neutral-700 p-6 rounded-2xl shadow-md hover:shadow-xl transition"
            >
              <div className="mb-4 flex justify-center">{item.icon}</div>
              <h3 className="text-xl font-semibold text-[--color-primary] dark:text-white">{item.title}</h3>
              <p className="text-textDark/75 dark:text-gray-300 mt-2">{item.description}</p>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
};

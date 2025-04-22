// components/Location.tsx
import { FaMapMarkerAlt, FaClock } from "react-icons/fa";
import { motion } from "framer-motion";

export const Location = () => {
  return (
    <section id="location" className="py-16 bg-bgLight dark:bg-bgDark text-gray-800 dark:text-white">
      <div className="max-w-6xl mx-auto px-4">
        <motion.h2
          initial={{ opacity: 0, y: -30 }}
          whileInView={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
          className="text-3xl font-bold text-center text-primary dark:text-white mb-10"
        >
          Horarios y Ubicación
        </motion.h2>

        <div className="grid md:grid-cols-2 gap-8">
          {/* Información */}
          <motion.div
            initial={{ opacity: 0, x: -30 }}
            whileInView={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.6 }}
            className="flex flex-col justify-center"
          >
            <div className="flex items-start gap-4 mb-6">
              <FaMapMarkerAlt size={28} className="text-primary dark:text-accent2 mt-1" />
              <div>
                <h3 className="text-xl font-semibold text-[--color-primary] dark:text-white">Dirección</h3>
                <p className="text-gray-600 dark:text-gray-300">
                  Vía al río, Km 12, Parroquia San Pedro, Quito, Ecuador.
                </p>
              </div>
            </div>

            <div className="flex items-start gap-4">
              <FaClock size={28} className="text-[--color-primary] dark:text-accent2 mt-1" />
              <div>
                <h3 className="text-xl font-semibold text-primary dark:text-white">Horario</h3>
                <p className="text-gray-600 dark:text-gray-300">
                  Lunes a Viernes: 09:00 AM - 06:00 PM <br />
                  Fines de semana y feriados: 08:00 AM - 07:00 PM
                </p>
              </div>
            </div>
          </motion.div>

          {/* Mapa */}
          <motion.div
            initial={{ opacity: 0, x: 30 }}
            whileInView={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.6 }}
            className="rounded-lg overflow-hidden shadow-lg"
          >
            <iframe
              title="Ubicación Aqua River Park"
              src="https://www.google.com/maps/embed?pb=!1m18!1m12!1m3!1d997.1577814259337!2d-78.4820648582634!3d-0.18065319771840107!2m3!1f0!2f0!3f0!3m2!1i1024!2i768!4f13.1!3m3!1m2!1s0x91d59a6aaef0f4d3%3A0x7e6b805b9c2d79e2!2sParque%20Recreacional!5e0!3m2!1ses-419!2sec!4v1713632500000!5m2!1ses-419!2sec"
              width="100%"
              height="300"
              style={{ border: 0 }}
              allowFullScreen
              loading="lazy"
              referrerPolicy="no-referrer-when-downgrade"
            />
          </motion.div>
        </div>
      </div>
    </section>
  );
};
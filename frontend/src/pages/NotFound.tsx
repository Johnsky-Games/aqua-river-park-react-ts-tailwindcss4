import { Link } from "react-router-dom";
import { motion } from "framer-motion";
import { useCallback, useEffect, useState } from "react";
import Particles from "react-tsparticles";
import { loadSlim } from "tsparticles-slim"; // ✅ MÁS LIVIANO Y FUNCIONAL
import type { Engine } from "tsparticles-engine";

const NotFound = () => {
  const [isDark, setIsDark] = useState(false);

  useEffect(() => {
    const match = window.matchMedia("(prefers-color-scheme: dark)");
    setIsDark(match.matches);
    const listener = (e: MediaQueryListEvent) => setIsDark(e.matches);
    match.addEventListener("change", listener);
    return () => match.removeEventListener("change", listener);
  }, []);

  const particlesInit = useCallback(async (engine: Engine) => {
    await loadSlim(engine); // ✅ Ya no usamos loadFull
  }, []);

  return (
    <div className="relative h-screen w-full flex items-center justify-center px-4 bg-white dark:bg-gray-900 text-gray-800 dark:text-white overflow-hidden">
      <Particles
        id="tsparticles"
        init={particlesInit}
        className="absolute inset-0 z-0"
        options={{
          fullScreen: false,
          background: { color: { value: "transparent" } },
          particles: {
            number: { value: 60 },
            color: { value: isDark ? "#ffffff" : "#0ea5e9" },
            shape: { type: "circle" },
            opacity: { value: 0.4 },
            size: { value: 3 },
            move: {
              enable: true,
              speed: 1.5,
              direction: "none",
              outModes: "out",
            },
          },
        }}
      />

      <div className="z-10 text-center mt-2">
        <motion.h1
          className="text-[8rem] sm:text-[10rem] font-black tracking-tight leading-none"
          initial={{ scale: 0 }}
          animate={{ scale: 1 }}
          transition={{ duration: 0.6 }}
        >
          404
        </motion.h1>

        <motion.h2
          className="text-3xl sm:text-4xl font-semibold mt-2"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
        >
          ¡Ups! Página no encontrada 😢
        </motion.h2>

        <motion.p
          className="mt-4 max-w-md mx-auto text-gray-600 dark:text-gray-300 text-base sm:text-lg"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.5 }}
        >
          Tal vez escribiste mal la dirección o esta página ya no existe.
        </motion.p>

        <motion.div
          className="mt-6 flex gap-4 justify-center flex-col sm:flex-row"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.8 }}
        >
          <Link
            to="/"
            className="px-6 py-3 bg-gradient-to-r from-blue-600 to-purple-600 text-white font-semibold rounded-md hover:scale-105 transition-transform"
          >
            Ir al inicio
          </Link>
          <Link
            to="/admin/dashboard"
            className="px-6 py-3 border border-gray-400 text-gray-700 dark:text-gray-200 dark:border-gray-500 rounded-md hover:bg-gray-200 dark:hover:bg-gray-700 transition-all"
          >
            Ir al panel
          </Link>
        </motion.div>

        <motion.div
          className="mt-4"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 1.2 }}
        >
          <img
            src="https://illustrations.popsy.co/violet/crashed-error.svg"
            alt="Ilustración de error"
            className="w-64 sm:w-96 mx-auto fill-indigo-500 drop-shadow-2xl drop-shadow-indigo-500/50"
          />
        </motion.div>
      </div>
    </div>
  );
};

export default NotFound;

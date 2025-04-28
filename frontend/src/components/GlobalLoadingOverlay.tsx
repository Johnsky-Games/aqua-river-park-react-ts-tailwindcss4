import { motion, AnimatePresence } from "framer-motion";
import { useGlobalLoading } from "@/store/useGlobalLoading";

export const GlobalLoadingOverlay = () => {
  const { isLoading } = useGlobalLoading();

  return (
    <AnimatePresence>
      {isLoading && (
        <motion.div
          className="fixed inset-0 z-[1000] bg-black/50 flex items-center justify-center"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.3 }}
        >
          <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow-lg flex items-center gap-4">
            <div className="w-6 h-6 border-4 border-blue-500 border-t-transparent rounded-full animate-spin" />
            <p className="text-gray-700 dark:text-white text-sm font-medium">
              Cargando...
            </p>
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  );
};

import React from "react";
import { motion, AnimatePresence } from "framer-motion";
import { FaTimes } from "react-icons/fa";

interface ModalProps {
  isOpen: boolean;
  onClose: () => void;
  title?: string;
  children: React.ReactNode;
  size?: "sm" | "md" | "lg";
  hideCloseButton?: boolean;
}

const sizeClasses = {
  sm: "max-w-sm",
  md: "max-w-md",
  lg: "max-w-2xl",
};

const Modal: React.FC<ModalProps> = ({
  isOpen,
  onClose,
  title,
  children,
  size = "md",
  hideCloseButton = false,
}) => {
  return (
    <AnimatePresence>
      {isOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <motion.div
            initial={{ opacity: 0, y: -30 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: 20 }}
            transition={{ duration: 0.3 }}
            className={`bg-white dark:bg-bgDark text-textDark dark:text-textLight rounded-lg shadow-lg w-full ${sizeClasses[size]} relative px-6 py-5`}
          >
            {!hideCloseButton && (
              <button
                className="absolute top-3 right-4 text-gray-400 hover:text-red-500 transition"
                onClick={onClose}
                aria-label="Cerrar modal"
              >
                <FaTimes />
              </button>
            )}

            {title && (
              <h2 className="text-xl font-semibold mb-4 text-center">
                {title}
              </h2>
            )}

            <div>{children}</div>
          </motion.div>
        </div>
      )}
    </AnimatePresence>
  );
};

export default Modal;

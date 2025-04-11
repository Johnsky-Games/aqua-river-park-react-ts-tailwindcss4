// src/components/auth/AuthSidePanel.tsx
import { motion } from "framer-motion";

interface Props {
  title: string;
  description: string;
  buttonText: string;
  onToggle: () => void;
}

export default function AuthSidePanel({ title, description, buttonText, onToggle }: Props) {
  return (
    <motion.div
      key={title}
      initial={{ x: 300, opacity: 0 }}
      animate={{ x: 0, opacity: 1 }}
      exit={{ x: -300, opacity: 0 }}
      transition={{ duration: 0.5, ease: "easeInOut" }}
      className="w-full md:w-fit p-6 md:p-8 flex flex-col justify-center text-center space-y-6 bg-white"
    >
      <h2 className="text-3xl md:text-4xl font-bold bg-gradient-to-r from-indigo-500 via-purple-500 to-pink-500 text-transparent bg-clip-text">
        {title}
      </h2>
      <p className="text-gray-600">{description}</p>
      <button
        onClick={onToggle}
        className="px-6 py-3 rounded-full bg-gradient-to-r from-indigo-500 via-purple-500 to-pink-500 text-white font-semibold hover:scale-105 transition-all"
      >
        {buttonText}
      </button>
    </motion.div>
  );
}

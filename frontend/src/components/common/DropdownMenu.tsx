import { Link } from "react-router-dom";
import { AnimatePresence, motion } from "framer-motion";

interface Props {
  visible: boolean;
  menuKey: string;
  labels: string[];
  onLinkClick: () => void;
}

export const DropdownMenu: React.FC<Props> = ({
  visible,
  menuKey,
  labels,
  onLinkClick,
}) => {
  return (
    <AnimatePresence>
      {visible && (
        <motion.div
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          exit={{ opacity: 0, scale: 0.95 }}
          transition={{ duration: 0.2, ease: "easeOut" }}
          className="absolute left-1/2 transform -translate-x-1/2 top-full mt-2 w-56 max-h-[70vh] overflow-y-auto backdrop-blur-md bg-bgLight/30 dark:bg-bgDark/40 text-textDark dark:text-textLight rounded-xl shadow-xl ring-1 ring-bgLight/25 z-50"
        >
          {labels.map((label, idx) => (
            <Link
              key={idx}
              to={`/${menuKey}#${label.toLowerCase().replace(/\s+/g, "-")}`}
              onClick={onLinkClick}
              className="block px-4 py-2 text-sm font-semibold hover:bg-accent2/80 hover:text-white dark:hover:bg-bgLight/80 dark:hover:text-textDark/90 transition-all duration-200"
            >
              {label}
            </Link>
          ))}
        </motion.div>
      )}
    </AnimatePresence>
  );
};

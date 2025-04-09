import { useTheme } from '../hooks/useTheme';
import { FaSun, FaMoon } from 'react-icons/fa';

export const ThemeToggle = () => {
  const { darkMode, toggleDarkMode } = useTheme();

  return (
    <button
      onClick={toggleDarkMode}
      className="p-2 rounded-lg bg-gray-200 dark:bg-gray-700 transition-colors"
      aria-label={darkMode ? 'Activar modo claro' : 'Activar modo oscuro'}
    >
      {darkMode ? <FaSun className="text-yellow-400" /> : <FaMoon className="text-gray-700" />}
    </button>
  );
};

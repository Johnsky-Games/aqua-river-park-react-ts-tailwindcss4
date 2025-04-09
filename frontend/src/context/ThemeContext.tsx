import { createContext } from 'react';

// Definir tipos
export interface ThemeContextType {
  darkMode: boolean;
  toggleDarkMode: () => void;
}

// Crear y exportar el contexto
export const ThemeContext = createContext<ThemeContextType>({
  darkMode: false,
  toggleDarkMode: () => {},
});

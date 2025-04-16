import { useState } from "react";
import { FaEye, FaEyeSlash, FaInfoCircle } from "react-icons/fa";
import {
  getPasswordScore,
  getStrengthLabel,
} from "../../utils/validationHelpersForm";

interface Props {
  value: string;
  onChange: (e: React.ChangeEvent<HTMLInputElement>) => void;
  error?: string;
  showTooltip?: boolean;
  showStrengthBar?: boolean;
  autoFocus?: boolean;
  name?: string;
  placeholder?: string;
}

export default function PasswordWithStrengthInput({
  value,
  onChange,
  error,
  showTooltip = true,
  showStrengthBar = true,
  autoFocus = false,
  name = "password",
  placeholder = "Password",
}: Props) {
  const [showPassword, setShowPassword] = useState(false);
  const score = getPasswordScore(value);
  const label = getStrengthLabel(score);

  return (
    <div className="relative mb-4">
      <div className="absolute flex justify-start mb-1 top-[-14px] left-[4px]">
        {showTooltip && (
          <div className="relative group inline-block">
            <FaInfoCircle
              className="text-blue-500 dark:text-blue-400 cursor-pointer p-0.5"
              tabIndex={0} // para accesibilidad en teclado
            />
            <div className="absolute z-30 top-full right-[-260px] mt-2 w-72 md:w-64 text-xs bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 text-gray-800 dark:text-gray-200 p-2 rounded shadow-md opacity-0 invisible group-hover:opacity-100 group-hover:visible group-focus-within:opacity-100 group-focus-within:visible transition-opacity duration-200 pointer-events-none">
              Usa mínimo 8 caracteres, una mayúscula, un número y un símbolo especial. No uses tu correo ni contraseñas anteriores.
            </div>
          </div>
        )}
      </div>

      <input
        type={showPassword ? "text" : "password"}
        name={name}
        value={value}
        onChange={onChange}
        placeholder={placeholder}
        autoFocus={autoFocus}
        className="input-style pr-10 outline-none dark:bg-gray-900 dark:text-white dark:border-gray-700"
      />

      <button
        type="button"
        onClick={() => setShowPassword(!showPassword)}
        className="absolute right-3 top-[20px] text-gray-600 dark:text-gray-300 hover:text-blue-600 dark:hover:text-blue-400 transition"
        tabIndex={-1}
      >
        {showPassword ? <FaEyeSlash /> : <FaEye />}
      </button>

      {error && <p className="text-red-500 text-sm mt-1">{error}</p>}

      {showStrengthBar && (
        <div className="mt-2">
          <div className="flex gap-1">
            {[...Array(4)].map((_, i) => (
              <div
                key={i}
                className={`h-2 flex-1 rounded ${
                  i < score ? label.bar : "bg-gray-200 dark:bg-gray-600"
                }`}
              />
            ))}
          </div>
          {score > 0 && (
            <p className={`text-sm mt-1 ${label.color}`}>Fuerza: {label.text}</p>
          )}
        </div>
      )}
    </div>
  );
}

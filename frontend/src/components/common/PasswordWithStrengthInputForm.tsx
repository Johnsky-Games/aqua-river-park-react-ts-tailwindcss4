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
      <label className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-1 flex items-center gap-2">
        Contraseña
        {showTooltip && (
          <span className="relative group">
            <FaInfoCircle className="text-blue-500 cursor-pointer dark:text-blue-400" />
            <div
              className="absolute left-6 top-[-8px] w-64 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-600 text-gray-700 dark:text-gray-300 text-xs p-2 rounded-md shadow-md
              opacity-0 scale-95 group-hover:opacity-100 group-hover:scale-100 transform transition-all duration-200 ease-out z-10"
            >
              Usa mínimo 8 caracteres, una mayúscula, un número y un símbolo
              especial. No uses tu correo ni contraseñas anteriores.
            </div>
          </span>
        )}
      </label>

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
        className="absolute right-3 top-[38px] text-gray-600 dark:text-gray-300 hover:text-blue-600 dark:hover:text-blue-400 transition"
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
            <p className={`text-sm mt-1 ${label.color}`}>
              Fuerza: {label.text}
            </p>
          )}
        </div>
      )}
    </div>
  );
}

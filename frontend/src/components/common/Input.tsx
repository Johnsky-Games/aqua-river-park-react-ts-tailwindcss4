import React from "react";
import { twMerge } from "tailwind-merge";

interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  label?: string;
  error?: string;
  icon?: React.ReactNode;
  fullWidth?: boolean;
}

const Input: React.FC<InputProps> = ({
  label,
  error,
  icon,
  fullWidth = true,
  className,
  ...props
}) => {
  return (
    <div className={twMerge("mb-4", fullWidth ? "w-full" : "", className)}>
      {label && (
        <label className="block text-sm font-medium text-gray-700 dark:text-textLight mb-1">
          {label}
        </label>
      )}

      <div className="relative">
        {icon && (
          <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-gray-500 dark:text-gray-300">
            {icon}
          </div>
        )}
        <input
          {...props}
          className={twMerge(
            "appearance-none block w-full px-3 py-2 border rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent text-sm",
            icon ? "pl-10" : "",
            error
              ? "border-red-500 focus:ring-red-500"
              : "border-gray-300 dark:border-gray-600 dark:bg-bgDark dark:text-textLight",
            props.disabled ? "opacity-50 cursor-not-allowed" : ""
          )}
        />
      </div>

      {error && (
        <p className="text-sm text-red-600 mt-1 font-medium">{error}</p>
      )}
    </div>
  );
};

export default Input;

import React from "react";
import classNames from "classnames";

interface FormFieldProps {
  label: string;
  name: string;
  type?: string;
  value: string;
  onChange: (e: React.ChangeEvent<HTMLInputElement>) => void;
  placeholder?: string;
  icon?: React.ReactNode;
  error?: string;
  required?: boolean;
  disabled?: boolean;
  autoComplete?: string;
}

const FormField: React.FC<FormFieldProps> = ({
  label,
  name,
  type = "text",
  value,
  onChange,
  placeholder = "",
  icon,
  error,
  required = false,
  disabled = false,
  autoComplete,
}) => {
  return (
    <div className="mb-4">
      <label
        htmlFor={name}
        className="block text-sm font-medium text-gray-700 dark:text-gray-200 mb-1"
      >
        {label} {required && <span className="text-red-500">*</span>}
      </label>

      <div className="relative">
        {icon && (
          <div className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 pointer-events-none">
            {icon}
          </div>
        )}

        <input
          type={type}
          name={name}
          id={name}
          value={value}
          onChange={onChange}
          placeholder={placeholder}
          disabled={disabled}
          autoComplete={autoComplete}
          className={classNames(
            "w-full border rounded-md py-2 px-3 focus:outline-none focus:ring-2",
            {
              "pl-10": icon,
              "border-gray-300 focus:ring-blue-500":
                !error && !disabled,
              "border-red-500 focus:ring-red-500": error,
              "bg-gray-100 cursor-not-allowed": disabled,
              "dark:bg-gray-800 dark:text-white dark:border-gray-600": true,
            }
          )}
        />
      </div>

      {error && (
        <p className="text-red-500 text-sm mt-1 font-medium">{error}</p>
      )}
    </div>
  );
};

export default FormField;

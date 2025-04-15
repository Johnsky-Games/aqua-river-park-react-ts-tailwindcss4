import React from "react";

interface Props extends React.InputHTMLAttributes<HTMLInputElement> {
  label: string;
  name: string;
  error?: string;
}

const InputWithLabel: React.FC<Props> = ({
  label,
  name,
  error,
  ...props
}) => {
  return (
    <div className="mb-4">
      <label
        htmlFor={name}
        className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-1 flex items-center gap-2"
      >
        {label}
      </label>

      <input
        id={name}
        name={name}
        className="input-style outline-none dark:bg-gray-900 dark:text-white dark:border-gray-700"
        {...props}
      />

      {error && <p className="text-red-500 text-sm mt-1">{error}</p>}
    </div>
  );
};

export default InputWithLabel;

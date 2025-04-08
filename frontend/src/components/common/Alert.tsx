import React from "react";
import classNames from "classnames";
import {
  FaCheckCircle,
  FaExclamationTriangle,
  FaInfoCircle,
  FaTimesCircle,
} from "react-icons/fa";

interface AlertProps {
  type?: "success" | "error" | "warning" | "info";
  message: string;
  className?: string;
}

const iconMap = {
  success: <FaCheckCircle className="text-green-600 text-xl mr-2" />,
  error: <FaTimesCircle className="text-red-600 text-xl mr-2" />,
  warning: <FaExclamationTriangle className="text-yellow-600 text-xl mr-2" />,
  info: <FaInfoCircle className="text-blue-600 text-xl mr-2" />,
};

const Alert: React.FC<AlertProps> = ({
  type = "info",
  message,
  className = "",
}) => {
  const baseStyles =
    "flex items-start gap-2 px-4 py-3 rounded-md shadow-sm text-sm font-medium";

  const typeStyles = {
    success: "bg-green-100 text-green-800 dark:bg-green-900/20 dark:text-green-200",
    error: "bg-red-100 text-red-800 dark:bg-red-900/20 dark:text-red-200",
    warning: "bg-yellow-100 text-yellow-800 dark:bg-yellow-900/20 dark:text-yellow-200",
    info: "bg-blue-100 text-blue-800 dark:bg-blue-900/20 dark:text-blue-200",
  };

  return (
    <div className={classNames(baseStyles, typeStyles[type], className)}>
      {iconMap[type]}
      <span>{message}</span>
    </div>
  );
};

export default Alert;

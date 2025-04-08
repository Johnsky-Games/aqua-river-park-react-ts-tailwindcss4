import React from "react";
import { Link } from "react-router-dom";
import { FaChevronRight } from "react-icons/fa";

interface BreadcrumbItem {
  label: string;
  path?: string;
  isCurrent?: boolean;
}

interface BreadcrumbProps {
  items: BreadcrumbItem[];
  className?: string;
}

const Breadcrumb: React.FC<BreadcrumbProps> = ({ items, className = "" }) => {
  return (
    <nav
      className={`text-sm text-gray-600 dark:text-gray-300 ${className}`}
      aria-label="breadcrumb"
    >
      <ol className="flex flex-wrap items-center space-x-2">
        {items.map((item, idx) => (
          <li key={idx} className="flex items-center">
            {item.path && !item.isCurrent ? (
              <Link
                to={item.path}
                className="hover:underline text-blue-600 dark:text-blue-400"
              >
                {item.label}
              </Link>
            ) : (
              <span className="font-semibold text-gray-900 dark:text-white">
                {item.label}
              </span>
            )}
            {idx < items.length - 1 && (
              <FaChevronRight className="mx-2 text-xs text-gray-400" />
            )}
          </li>
        ))}
      </ol>
    </nav>
  );
};

export default Breadcrumb;

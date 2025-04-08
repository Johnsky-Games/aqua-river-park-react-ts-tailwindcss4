import React from "react";
import classNames from "classnames";

interface CardProps extends React.HTMLAttributes<HTMLDivElement> {
  title?: string;
  subtitle?: string;
  footer?: React.ReactNode;
  children: React.ReactNode;
  shadow?: boolean;
  hoverable?: boolean;
  rounded?: boolean;
  bordered?: boolean;
}

const Card: React.FC<CardProps> = ({
  title,
  subtitle,
  footer,
  children,
  className,
  shadow = true,
  hoverable = false,
  rounded = true,
  bordered = false,
  ...props
}) => {
  return (
    <div
      className={classNames(
        "bg-white dark:bg-bgDark text-textDark dark:text-textLight transition-all duration-300",
        {
          "shadow-md": shadow,
          "hover:shadow-lg hover:scale-[1.01] transform transition-all":
            hoverable,
          "rounded-lg": rounded,
          "border border-gray-200 dark:border-gray-700": bordered,
        },
        className
      )}
      {...props}
    >
      {(title || subtitle) && (
        <div className="p-4 border-b border-gray-100 dark:border-gray-700">
          {title && <h2 className="text-lg font-semibold">{title}</h2>}
          {subtitle && (
            <p className="text-sm text-gray-500 dark:text-gray-400">
              {subtitle}
            </p>
          )}
        </div>
      )}

      <div className="p-4">{children}</div>

      {footer && (
        <div className="px-4 py-3 border-t border-gray-100 dark:border-gray-700">
          {footer}
        </div>
      )}
    </div>
  );
};

export default Card;

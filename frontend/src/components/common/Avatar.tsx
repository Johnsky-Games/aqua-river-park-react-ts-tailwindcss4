import React from "react";
import classNames from "classnames";

interface AvatarProps {
  name?: string;
  imageUrl?: string;
  size?: "sm" | "md" | "lg";
  status?: "online" | "offline" | "busy";
  className?: string;
}

const sizeClasses = {
  sm: "w-8 h-8 text-sm",
  md: "w-10 h-10 text-base",
  lg: "w-14 h-14 text-lg",
};

const statusColors = {
  online: "bg-green-500",
  offline: "bg-gray-400",
  busy: "bg-red-500",
};

export const Avatar: React.FC<AvatarProps> = ({
  name,
  imageUrl,
  size = "md",
  status,
  className = "",
}) => {
  const initials = name
    ? name
        .split(" ")
        .map((n) => n[0])
        .join("")
        .toUpperCase()
        .slice(0, 2)
    : "?";

  return (
    <div className={classNames("relative inline-block", className)}>
      <div
        className={classNames(
          "rounded-full bg-gray-200 dark:bg-gray-700 flex items-center justify-center overflow-hidden text-white font-semibold",
          sizeClasses[size]
        )}
      >
        {imageUrl ? (
          <img
            src={imageUrl}
            alt={name}
            className="w-full h-full object-cover"
          />
        ) : (
          <span>{initials}</span>
        )}
      </div>

      {status && (
        <span
          className={classNames(
            "absolute bottom-0 right-0 w-3 h-3 rounded-full ring-2 ring-white dark:ring-gray-900",
            statusColors[status]
          )}
        />
      )}
    </div>
  );
};

export default Avatar;

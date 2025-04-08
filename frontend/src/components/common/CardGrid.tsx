import React from "react";
import classNames from "classnames";

interface CardGridProps {
  children: React.ReactNode;
  columns?: number; // número de columnas base (por defecto 1 en móvil, luego responsive)
  gap?: string; // espacio entre tarjetas (por defecto 'gap-6')
  className?: string;
}

const CardGrid: React.FC<CardGridProps> = ({
  children,
  columns = 1,
  gap = "gap-6",
  className = "",
}) => {
  const gridCols = {
    1: "grid-cols-1",
    2: "sm:grid-cols-2",
    3: "sm:grid-cols-2 md:grid-cols-3",
    4: "sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4",
  };

  return (
    <div
      className={classNames(
        "grid w-full",
        gap,
        gridCols[columns as keyof typeof gridCols],
        className
      )}
    >
      {children}
    </div>
  );
};

export default CardGrid;

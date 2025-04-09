// src/components/navigation/MiniFooter.tsx

const MiniFooter = () => {
    return (
      <footer className="bg-accent2 text-white text-xs py-3 px-4 text-center shadow-md">
        <span className="block md:inline">
          © {new Date().getFullYear()} Aqua River Park
        </span>
        <span className="hidden md:inline mx-2">|</span>
        <span className="block md:inline text-white/80">
          Todos los derechos reservados
        </span>
      </footer>
    );
  };
  
  export default MiniFooter;
  
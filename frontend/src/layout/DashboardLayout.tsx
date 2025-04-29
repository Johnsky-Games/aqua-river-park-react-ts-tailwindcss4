import Sidebar from "../layout/navigation/Sidebar";
import HeaderMobile from "../layout/navigation/HeaderMobile";
import { ReactNode, useState, useEffect } from "react";

interface Props {
  children: ReactNode;
}

const DashboardLayout = ({ children }: Props) => {
  // arrancamos desde localStorage
  const [isSidebarOpen, setSidebarOpen] = useState<boolean>(() => {
    return localStorage.getItem("sidebarOpen") === "true";
  });
  const [isMobile, setIsMobile] = useState<boolean>(false);

  // detectamos si estamos en móvil o desktop
  useEffect(() => {
    const handleResize = () => {
      setIsMobile(window.innerWidth < 768);
    };
    handleResize();
    window.addEventListener("resize", handleResize);
    return () => window.removeEventListener("resize", handleResize);
  }, []);

  // toggle + persistencia
  const toggleSidebar = () => {
    setSidebarOpen((open) => {
      const next = !open;
      localStorage.setItem("sidebarOpen", next.toString());
      return next;
    });
  };

  return (
    <div className="h-screen bg-bgLight dark:bg-bgDark transition-colors">
      {/* Sidebar: recibe isOpen, onToggle e isMobile */}
      <Sidebar
        isOpen={isSidebarOpen}
        onToggle={toggleSidebar}
        isMobile={isMobile}
      />

      <div className="flex flex-col flex-1 overflow-x-hidden">
        {/* HeaderMobile: recibe isSidebarOpen, onToggle e isMobile */}
        <HeaderMobile
          isSidebarOpen={isSidebarOpen}
          onToggle={toggleSidebar}
          isMobile={isMobile}
        />

        <main
          className={`
    flex-1 overflow-y-auto p-4
    transition-all ease-in-out duration-300  
    ${isMobile ? "ml-0" : isSidebarOpen ? "md:ml-64" : "md:ml-20"}
  `}
        >
          {children}
        </main>
      </div>
    </div>
  );
};

export default DashboardLayout;

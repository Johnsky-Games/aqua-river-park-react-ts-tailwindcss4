// src/layout/DashboardLayout.tsx
import React, { useState, useEffect } from "react";
import { Outlet } from "react-router-dom";

import Sidebar from "@/layout/navigation/Sidebar";
import HeaderMobile from "@/layout/navigation/HeaderMobile";

const DashboardLayout: React.FC = () => {
  const [isSidebarOpen, setSidebarOpen] = useState(() =>
    localStorage.getItem("sidebarOpen") === "true"
  );
  const [isMobile, setIsMobile] = useState(false);

  useEffect(() => {
    const handleResize = () => setIsMobile(window.innerWidth < 768);
    handleResize();
    window.addEventListener("resize", handleResize);
    return () => window.removeEventListener("resize", handleResize);
  }, []);

  const toggleSidebar = () => {
    setSidebarOpen((open) => {
      const next = !open;
      localStorage.setItem("sidebarOpen", next.toString());
      return next;
    });
  };

  return (
    <div className="h-screen flex bg-bgLight dark:bg-bgDark">
      <Sidebar isOpen={isSidebarOpen} isMobile={isMobile} onToggle={toggleSidebar} />
      <div className="flex-1 flex flex-col overflow-x-hidden">
        <HeaderMobile
          isSidebarOpen={isSidebarOpen}
          onToggle={toggleSidebar}
          isMobile={isMobile}
        />
        <main
          className={`flex-1 overflow-y-auto p-4 transition-all duration-300 ${
            isMobile
              ? "ml-0"
              : isSidebarOpen
              ? "md:ml-64"
              : "md:ml-20"
          }`}
        >
          <Outlet />
        </main>
      </div>
    </div>
  );
};

export default DashboardLayout;

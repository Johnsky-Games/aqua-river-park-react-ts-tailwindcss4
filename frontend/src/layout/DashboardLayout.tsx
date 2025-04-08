import Sidebar from "../layout/navigation/Sidebar";
import HeaderMobile from "../layout/navigation/HeaderMobile";
import { ReactNode, useState } from "react";

interface Props {
  children: ReactNode;
}

const DashboardLayout = ({ children }: Props) => {
  const [isSidebarOpen, setSidebarOpen] = useState(true);

  return (
    <div className="flex h-screen bg-bgLight dark:bg-bgDark transition-colors">
      <Sidebar isOpen={isSidebarOpen} />
      <div className="flex flex-col flex-1">
        <HeaderMobile onToggleSidebar={() => setSidebarOpen(!isSidebarOpen)} />
        <main className="flex-1 overflow-y-auto p-4">{children}</main>
      </div>
    </div>
  );
};

export default DashboardLayout;

// src/layout/PublicLayout.tsx
import { Outlet } from "react-router-dom";
import Header from "@/layout/navigation/Header";
import Footer from "@/layout/navigation/Footer";

const PublicLayout: React.FC = () => {
  return (
    <>
      <Header />
      <main className="pt-0">
        <Outlet />
      </main>
      <Footer />
    </>
  );
};

export default PublicLayout;

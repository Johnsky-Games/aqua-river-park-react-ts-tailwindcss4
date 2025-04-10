import Header from "../layout/navigation/Header";
import Footer from "../layout/navigation/Footer";
// import { ReactNode } from "react";

// interface Props {
//   children: ReactNode;
// }

const PublicLayout = ({ children }: { children: React.ReactNode }) => {
  return (
    <div className="flex flex-col min-h-screen bg-bgLight dark:bg-bgDark transition-colors">
      <Header />
      <main className="flex-grow">{children}</main>
      <Footer />
    </div>
  );
};

export default PublicLayout;

// pages/Home.tsx
import { Hero } from "@/components/home/Hero";
import { Benefits } from "@/components/home/Benefits";
import { Attractions } from "@/components/home/Attractions";
import { RegisterInvoice } from "@/components/home/RegisterInvoice";
import { Location } from "@/components/home/Location";

type InvoiceData = {
  cedula: string;
  email: string;
  phone: string;
  invoiceNumber: string;
};

const Home = () => {
  const handleInvoiceSubmit = (data: InvoiceData) => {
    console.log("Factura registrada:", data);
    // Aquí puedes conectar con una API si deseas enviar el formulario
  };

  return (
    <main className="overflow-x-hidden">
      <Hero />
      <Benefits />
      <Attractions />
      <RegisterInvoice onSubmit={handleInvoiceSubmit} />
      <Location />
    </main>
  );
};

export default Home;

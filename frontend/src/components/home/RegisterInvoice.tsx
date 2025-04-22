import { useEffect, useRef, useState } from "react";
import { useForm } from "react-hook-form";
import { motion } from "framer-motion";
import { FaTicketAlt } from "react-icons/fa";
import { createScope, animate } from "animejs";
import Input from "@/components/common/Input";

// Tipos de datos

type InvoiceData = {
  cedula: string;
  email: string;
  phone: string;
  invoiceNumber: string;
};

type Props = {
  onSubmit: (data: InvoiceData) => void;
};

export const RegisterInvoice = ({ onSubmit }: Props) => {
  const {
    handleSubmit,
    formState: { errors },
    reset,
  } = useForm<InvoiceData>();

  const rootRef = useRef<HTMLFormElement>(null);
  const [formValues, setFormValues] = useState<InvoiceData>({
    cedula: "",
    email: "",
    phone: "",
    invoiceNumber: "",
  });

  useEffect(() => {
    const scope = createScope({ root: rootRef });
    scope.add(() => {
      animate(".register-title", {
        opacity: [0, 1],
        translateY: [-30, 0],
        duration: 600,
        easing: "easeOutExpo",
        delay: 100,
      });

      animate(".register-field", {
        opacity: [0, 1],
        translateY: [20, 0],
        duration: 500,
        easing: "easeOutExpo",
        delay: (_: unknown, i: number) => 300 + i * 100,
      });

      animate(".register-button", {
        opacity: [0, 1],
        scale: [0.95, 1],
        duration: 500,
        easing: "easeOutBack",
        delay: 800,
      });
    });

    return () => scope.revert();
  }, []);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setFormValues((prev) => ({ ...prev, [e.target.name]: e.target.value }));
  };

  const onSubmitForm = (data: InvoiceData) => {
    onSubmit(data);
    reset();
    setFormValues({ cedula: "", email: "", phone: "", invoiceNumber: "" });
  };

  return (
    <section id="register" className="py-12 px-4 sm:px-6 lg:px-8 bg-secondary/10 dark:bg-neutral-900">
      <motion.form
        ref={rootRef}
        onSubmit={handleSubmit(onSubmitForm)}
        initial="hidden"
        whileInView="visible"
        viewport={{ once: true, amount: 0.2 }}
        transition={{ staggerChildren: 0.15 }}
        className="max-w-xl mx-auto bg-white dark:bg-neutral-800 rounded-2xl shadow-lg p-6 sm:p-8 border border-gray-100 dark:border-neutral-700"
      >
        <div className="space-y-6">
          <motion.h3
            variants={{
              hidden: { opacity: 0, y: -30 },
              visible: { opacity: 1, y: 0 },
            }}
            className="register-title text-2xl sm:text-3xl font-bold text-accent2 dark:text-white text-center"
          >
            Registro de Facturas
          </motion.h3>

          <div className="register-conditions bg-gradient-to-r from-accent2/10 to-primary/10 dark:from-accent2/20 dark:to-primary/20 p-4 sm:p-6 rounded-xl border border-accent2/40">
            <div className="flex items-center gap-3 mb-4">
              <FaTicketAlt className="text-2xl sm:text-3xl text-secondary animate-bounce" />
              <h4 className="text-lg sm:text-xl font-bold text-accent2 dark:text-white">
                ¡Condiciones de la Promoción!
              </h4>
            </div>
            <ul className="space-y-3 text-sm sm:text-base">
              {["Registra 5 facturas diferentes del parque",
                "Las facturas deben ser del mismo mes",
                "Monto mínimo por factura: $20",
                "Al completar las 5 facturas, recibirás un código para un ticket gratis",
                "Promoción válida hasta agotar stock"].map((item) => (
                <li key={item} className="flex items-center gap-2 text-bgDark dark:text-neutral-200">
                  <div className="h-2 w-2 rounded-full bg-secondary" />
                  <span className="flex-1">{item}</span>
                </li>
              ))}
            </ul>
          </div>

          {[{
            name: "cedula",
            label: "Cédula de identidad",
            type: "text",
            pattern: /^[0-9]{10}$/,
          }, {
            name: "email",
            label: "Correo electrónico",
            type: "email",
            pattern: /^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}$/i,
          }, {
            name: "phone",
            label: "Teléfono",
            type: "text",
            pattern: /^[0-9]{10}$/,
          }, {
            name: "invoiceNumber",
            label: "Número de factura",
            type: "text",
          }].map((field) => (
            <motion.div
              key={field.name}
              className="register-field"
              variants={{ hidden: { opacity: 0, y: 20 }, visible: { opacity: 1, y: 0 } }}
            >
              <Input
                label={field.label}
                name={field.name}
                type={field.type}
                value={formValues[field.name as keyof InvoiceData] || ""}
                onChange={handleChange}
                error={errors[field.name as keyof InvoiceData]?.message}
                placeholder={field.label}
                required
              />
            </motion.div>
          ))}

          <motion.button
            variants={{
              hidden: { opacity: 0, scale: 0.95 },
              visible: { opacity: 1, scale: 1 },
            }}
            type="submit"
            className="register-button w-full bg-gradient-to-r from-accent2 to-primary text-white rounded-xl py-3 px-4 font-medium hover:shadow-lg transition-all duration-200"
          >
            Registrar Factura
          </motion.button>
        </div>
      </motion.form>
    </section>
  );
};

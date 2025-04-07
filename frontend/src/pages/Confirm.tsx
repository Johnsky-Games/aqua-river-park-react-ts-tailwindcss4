import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import api from "../api/axios";

const Confirm = () => {
  const { token } = useParams();
  const [message, setMessage] = useState("Confirmando...");

  useEffect(() => {
    const confirmAccount = async () => {
      try {
        const res = await api.get(`/confirm/${token}`);
        setMessage(res.data.message);
      } catch {
        setMessage("El enlace de confirmación no es válido o ya expiró.");
      }
    };

    confirmAccount();
  }, [token]);

  return (
    <div className="max-w-md mx-auto mt-20 text-center">
      <h1 className="text-2xl font-bold mb-4">Confirmación de Cuenta</h1>
      <p>{message}</p>
    </div>
  );
};

export default Confirm;

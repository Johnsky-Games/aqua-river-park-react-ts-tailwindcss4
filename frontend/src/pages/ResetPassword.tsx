import { useEffect, useState } from "react";
import { useSearchParams, useNavigate } from "react-router-dom";
import { toast } from "react-toastify";
import api from "../api/axios";
import { useAuthModal } from "../store/useAuthModal"; // 👈 NUEVO

export default function ResetPassword() {
  const [searchParams] = useSearchParams();
  const token = searchParams.get("token") || "";
  const email = searchParams.get("email") || "";
  const navigate = useNavigate();
  const { openModal } = useAuthModal(); // 👈 NUEVO

  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [loading, setLoading] = useState(true);
  const [valid, setValid] = useState(false);
  const [error, setError] = useState("");
  const [resend, setResend] = useState(false);
  const [isSending, setIsSending] = useState(false); // 👈 NUEVO


  useEffect(() => {
    const validateToken = async () => {
      try {
        const res = await api.post("/check-token-status", { token });
        if (res.data.valid) {
          setValid(true);
        } else {
          setError("El enlace ha expirado o es inválido.");
        }
      } catch {
        setError("Error al validar el enlace.");
      } finally {
        setLoading(false);
      }
    };

    if (token) validateToken();
    else {
      setError("Token no proporcionado.");
      setLoading(false);
    }
  }, [token]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (password.length < 8) {
      toast.warning("La contraseña debe tener al menos 8 caracteres");
      return;
    }

    if (password !== confirmPassword) {
      toast.error("Las contraseñas no coinciden");
      return;
    }

    try {
      await api.post(`/reset-password/${token}`, { password });
      toast.success("Contraseña actualizada correctamente");

      setTimeout(() => {
        navigate("/");     // 👈 Regresa a home
        openModal("login"); // 👈 Abre el modal de login
      }, 2000);
    } catch {
      toast.error("Error al actualizar la contraseña");
    }
  };

  const handleResend = async () => {
    if (isSending) return; // 👈 Evita spam de clics
    setIsSending(true);
    try {
      await api.post("/send-recovery", { email });
      toast.success("Se envió un nuevo enlace de recuperación");
      setResend(true);
    } catch {
      toast.error("No se pudo reenviar el correo");
    } finally {
      setIsSending(false); // ✅ Vuelve a habilitar
    }
  };

  if (loading) return <p className="text-center mt-8">Cargando...</p>;

  if (!valid) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-100 px-4">
        <div className="bg-white shadow-md rounded-lg p-6 w-full max-w-md text-center">
          <h2 className="text-xl font-semibold text-red-600 mb-4">{error}</h2>
          {!resend && email ? (
            <>
              <p className="text-sm text-gray-600 mb-4">
                Si deseas puedes reenviar el enlace a: <strong>{email}</strong>
              </p>
              <button
                onClick={handleResend}
                className="bg-sky-600 text-white px-4 py-2 rounded hover:bg-sky-700"
              >
                Reenviar enlace
              </button>
            </>
          ) : resend ? (
            <p className="text-green-600">
              Enlace reenviado. Revisa tu correo.
            </p>
          ) : (
            <p className="text-sm text-gray-500">
              Por favor, solicita un nuevo enlace desde la opción "Olvidé mi
              contraseña".
            </p>
          )}
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-100 px-4">
      <form
        onSubmit={handleSubmit}
        className="bg-white shadow-md rounded-lg p-6 w-full max-w-md"
      >
        <h2 className="text-2xl font-bold mb-4 text-center text-sky-600">
          Nueva Contraseña
        </h2>

        <input
          type="password"
          placeholder="Nueva contraseña"
          className="input-style mb-3"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />

        <input
          type="password"
          placeholder="Confirmar contraseña"
          className="input-style mb-4"
          value={confirmPassword}
          onChange={(e) => setConfirmPassword(e.target.value)}
        />

        <button
          type="submit"
          className="w-full bg-sky-600 text-white py-2 rounded hover:bg-sky-700 transition"
        >
          Guardar Contraseña
        </button>
      </form>
    </div>
  );
}

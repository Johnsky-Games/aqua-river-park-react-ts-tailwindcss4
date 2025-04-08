import { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import api from "../api/axios";
import { AxiosError } from "axios";
import { FaCheckCircle, FaTimesCircle, FaInfoCircle } from "react-icons/fa";

const ConfirmationMail = () => {
  const { token } = useParams();
  const navigate = useNavigate();

  const queryParams = new URLSearchParams(window.location.search);
  const emailFromQuery = queryParams.get("email");

  const [message, setMessage] = useState("Confirmando...");
  const [type, setType] = useState<"success" | "info" | "error">("info");
  const [showModal, setShowModal] = useState(false);
  const [email, setEmail] = useState(emailFromQuery || "");
  const [resendMsg, setResendMsg] = useState("");
  const [resendSuccess, setResendSuccess] = useState(false);

  useEffect(() => {
    const confirmAccount = async () => {
      try {
        const res = await api.get(`/confirm/${token}?email=${emailFromQuery}`);
        setMessage(res.data.message);
        setType("success");

        if (
          res.data.message.includes("ya ha sido confirmada") ||
          res.data.message.includes("Cuenta confirmada exitosamente")
        ) {
          setTimeout(() => {
            sessionStorage.setItem("toastSuccess", "¡Cuenta confirmada correctamente!");
            navigate("/login");
          }, 5000);
        }
      } catch (err) {
        const error = err as AxiosError<{ message: string }>;
        const msg = error.response?.data?.message;

        if (msg === "Token inválido o expirado") {
          setMessage("El enlace ya fue utilizado o ha expirado.");
          setType("info");
          setShowModal(true);
        } else {
          setMessage("Ocurrió un error al confirmar tu cuenta.");
          setType("error");
        }
      }
    };

    confirmAccount();
  }, [token, emailFromQuery, navigate]);

  const handleResend = async (e: React.FormEvent) => {
    e.preventDefault();
    setResendMsg("");
    try {
      const res = await api.post("/resend-confirmation", { email });
      setResendMsg(res.data.message);
      setResendSuccess(true);

      setTimeout(() => {
        sessionStorage.setItem("toastSuccess", "¡Enlace reenviado correctamente!");
        setShowModal(false);
        setResendMsg("");
        setEmail("");
        setResendSuccess(false);
        navigate("/login");
      }, 5000);
    } catch (err) {
      const error = err as AxiosError<{ message: string }>;
      setResendMsg(
        error.response?.data?.message ||
          "Ocurrió un error al reenviar el enlace."
      );
    }
  };

  const renderIcon = () => {
    if (type === "success")
      return <FaCheckCircle className="text-green-500 text-4xl mb-4 mx-auto" />;
    if (type === "error")
      return <FaTimesCircle className="text-red-500 text-4xl mb-4 mx-auto" />;
    return <FaInfoCircle className="text-yellow-500 text-4xl mb-4 mx-auto" />;
  };

  return (
    <>
      <div className="min-h-screen flex items-center justify-center bg-gray-100 px-4">
        <div className="bg-white shadow-md rounded-lg p-6 w-full max-w-md text-center">
          {renderIcon()}
          <h1 className="text-2xl font-bold mb-2">Confirmación de Cuenta</h1>
          <p
            className={`text-base ${
              type === "success"
                ? "text-green-600"
                : type === "error"
                ? "text-red-500"
                : "text-yellow-600"
            }`}
          >
            {message}
          </p>
        </div>
      </div>

      {showModal && (
        <div className="fixed inset-0 bg-black/70 bg-opacity-40 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg shadow-lg p-8 w-full max-w-md relative">
            {!resendSuccess && (
              <button
                onClick={() => setShowModal(false)}
                className="absolute top-2 right-3 text-gray-500 hover:text-red-500 text-lg font-bold"
              >
                &times;
              </button>
            )}
            <h2 className="text-xl font-bold text-center mb-4 text-sky-600">
              ¿Necesitas un nuevo enlace?
            </h2>
            {!resendSuccess ? (
              <>
                <p className="text-sm text-gray-600 text-center mb-4">
                  Ingresa tu correo para recibir un nuevo enlace de
                  confirmación:
                </p>
                <form onSubmit={handleResend} className="space-y-4">
                  <input
                    type="email"
                    placeholder="Tu correo"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    className="w-full px-4 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-sky-500"
                    required
                  />
                  <button
                    type="submit"
                    className="w-full bg-sky-600 text-white py-2 rounded-md hover:bg-sky-700 transition"
                  >
                    Reenviar enlace
                  </button>
                  {resendMsg && (
                    <p className="text-sm text-center text-red-500 mt-2">
                      {resendMsg}
                    </p>
                  )}
                </form>
              </>
            ) : (
              <div className="text-center">
                <FaCheckCircle className="text-green-500 text-4xl mx-auto mb-2" />
                <p className="text-green-600 text-sm font-medium">
                  {resendMsg}
                </p>
                <p className="text-sm text-gray-500 mt-2">
                  Redirigiendo al inicio de sesión...
                </p>
              </div>
            )}
          </div>
        </div>
      )}
    </>
  );
};

export default ConfirmationMail;

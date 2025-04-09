import { useEffect, useState } from "react";
import api from "../api/axios";
import { useNavigate } from "react-router-dom";
import { FaEye, FaEyeSlash, FaCheckCircle, FaInfoCircle } from "react-icons/fa";
import { toast } from "react-toastify";
import { AxiosError } from "axios";

const Login = () => {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [showModal, setShowModal] = useState(false);
  const [modalStep, setModalStep] = useState<"notice" | "form" | "success">(
    "notice"
  );
  const [resendMsg, setResendMsg] = useState("");
  const navigate = useNavigate();

  useEffect(() => {
    const confirmed = sessionStorage.getItem("confirmationSuccess");
    if (confirmed) {
      toast.success(
        "¡Cuenta confirmada con éxito! Ahora puedes iniciar sesión."
      );
      sessionStorage.removeItem("confirmationSuccess");
    }
  }, []);

  useEffect(() => {
    const successMsg = sessionStorage.getItem("toastSuccess");
    if (successMsg) {
      toast.success(successMsg);
      sessionStorage.removeItem("toastSuccess");
    }
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");

    try {
      const res = await api.post("/login", { email, password });
      localStorage.setItem("token", res.data.token);
      navigate("/dashboard");
    } catch (err) {
      const error = err as AxiosError<{
        message: string;
        tokenExpired?: boolean;
      }>;
      const msg = error.response?.data?.message;

      if (msg === "Debes confirmar tu cuenta") {
        const expired = error.response?.data?.tokenExpired;
        setModalStep(expired ? "form" : "notice");
        setShowModal(true);
      } else {
        setError("Credenciales incorrectas");
      }
    }
  };

  const handleResend = async (e: React.FormEvent) => {
    e.preventDefault();
    setResendMsg("");

    try {
      const res = await api.post("/resend-confirmation", { email });
      setResendMsg(res.data.message);
      setModalStep("success");

      setTimeout(() => {
        toast.success("¡Correo reenviado!, Revisa tu bandeja...");
        setShowModal(false);
        setResendMsg("");
        setEmail("");
        setPassword("");
      }, 5000);
    } catch (err) {
      const error = err as AxiosError<{ message: string }>;
      const msg = error.response?.data?.message;

      if (msg === "La cuenta ya está confirmada") {
        toast.info("La cuenta ya ha sido confirmada.");
        setShowModal(false);
      } else {
        setResendMsg("Error al reenviar el enlace.");
      }
    }
  };

  return (
    <>
      <div className="max-w-sm mx-auto mt-8">
        <h1 className="text-2xl font-bold mb-4">Iniciar sesión</h1>
        <form onSubmit={handleSubmit} className="space-y-4">
          <input
            type="email"
            placeholder="Correo"
            className="w-full border p-2"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
          />
          <div className="relative">
            <input
              type={showPassword ? "text" : "password"}
              placeholder="Contraseña"
              className="w-full border p-2 pr-10"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
            <button
              type="button"
              onClick={() => setShowPassword(!showPassword)}
              className="absolute top-1/2 right-3 transform -translate-y-1/2 text-gray-500"
            >
              {showPassword ? <FaEyeSlash /> : <FaEye />}
            </button>
          </div>
          <button
            type="submit"
            className="w-full bg-blue-500 text-white p-2 rounded"
          >
            Entrar
          </button>
          {error && <p className="text-red-500 text-sm">{error}</p>}
          <p className="text-sm mt-2">
            ¿No tienes una cuenta?{" "}
            <a href="/register" className="text-blue-500 underline">
              Regístrate aquí
            </a>
          </p>
        </form>
      </div>

      {showModal && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg shadow-lg p-6 w-full max-w-md relative text-center">
            <button
              onClick={() => setShowModal(false)}
              className="absolute top-2 right-3 text-gray-500 hover:text-red-500 text-lg font-bold"
            >
              &times;
            </button>

            {modalStep === "notice" && (
              <>
                <FaInfoCircle className="text-yellow-500 text-4xl mx-auto mb-2" />
                <h2 className="text-xl font-bold mb-2 text-sky-600">
                  Verifica tu cuenta
                </h2>
                <p className="text-sm text-gray-600 mb-4">
                  Aún no has confirmado tu cuenta. Revisa tu correo para
                  activarla.
                </p>
              </>
            )}

            {modalStep === "form" && (
              <>
                <h2 className="text-xl font-bold mb-2 text-sky-600">
                  Reenviar Enlace
                </h2>
                <form onSubmit={handleResend} className="space-y-4">
                  <input
                    type="email"
                    placeholder="Tu correo"
                    className="w-full px-4 py-2 border rounded-md"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    required
                  />
                  <button
                    type="submit"
                    className="w-full bg-sky-600 text-white py-2 rounded-md hover:bg-sky-700"
                  >
                    Reenviar
                  </button>
                  {resendMsg && (
                    <p className="text-sm text-red-500">{resendMsg}</p>
                  )}
                </form>
              </>
            )}

            {modalStep === "success" && (
              <>
                <FaCheckCircle className="text-green-500 text-4xl mx-auto mb-2" />
                <p className="text-green-600 text-sm font-medium">
                  {resendMsg}
                </p>
                <p className="text-sm text-gray-500 mt-2">
                  Serás redirigido al login...
                </p>
              </>
            )}
          </div>
        </div>
      )}
    </>
  );
};

export default Login;

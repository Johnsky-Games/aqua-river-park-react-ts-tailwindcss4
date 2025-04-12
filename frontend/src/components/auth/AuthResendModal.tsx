import { useState, FormEvent } from "react";
import { FaCheckCircle, FaInfoCircle } from "react-icons/fa";

interface Props {
  showModal: boolean;
  modalStep: "notice" | "form" | "success";
  email: string;
  resendMsg: string;
  onClose: () => void;
  onEmailChange: (email: string) => void;
  onResend: (e: React.FormEvent) => void;
  type: "confirm" | "recover";
}

export default function AuthResendModal({
  showModal,
  modalStep,
  email,
  resendMsg,
  onClose,
  onEmailChange,
  onResend,
  type,
}: Props) {

  const [isSending, setIsSending] = useState(false);

  const handleLocalResend = async (e: FormEvent) => {
    if (isSending) return;
    setIsSending(true);
    await onResend(e);
    setIsSending(false);
  };

  if (!showModal) return null;

  const isRecover = type === "recover";
  const title = isRecover ? "Recuperar Contraseña" : "Verifica tu cuenta";
  const formTitle = isRecover ? "Enviar enlace de recuperación" : "Reenviar Enlace";
  const formDescription = isRecover ? "Ingresa tu correo para recuperar tu contraseña." : "Aún no has confirmado tu cuenta. Revisa tu correo para activarla.";
  const successMsg =
    resendMsg ||
    (isRecover
      ? "Enlace de recuperación enviado con éxito. Revisa tu correo."
      : "Enlace de confirmación reenviado con éxito. Revisa tu correo.");

  return (
    <div
      className="fixed inset-0 bg-black/40 z-[1000] flex items-center justify-center"
      onMouseDown={onClose}
    >
      <div
        className="bg-white rounded-lg shadow-lg p-6 w-full max-w-md relative text-center"
        onMouseDown={(e) => e.stopPropagation()} // Esto evita que el click cierre el modal
      >
        <button
          onClick={onClose}
          className="absolute top-2 right-3 text-gray-500 hover:text-red-500 text-lg font-bold"
        >
          &times;
        </button>

        {modalStep === "notice" && (
          <>
            <FaInfoCircle className="text-yellow-500 text-4xl mx-auto mb-2" />
            <h2 className="text-xl font-bold mb-2 text-sky-600">{title}</h2>
            <p className="text-sm text-gray-600 mb-4">
              {isRecover
                ? "Ingresa tu correo para recuperar tu contraseña."
                : "Aún no has confirmado tu cuenta. Revisa tu correo para activarla."}
            </p>
          </>
        )}

        {modalStep === "form" && (
          <>
            <h2 className="text-xl font-bold mb-2 text-sky-600">{formTitle}</h2>
            <p className="text-sm text-gray-600 mb-4">{formDescription}</p>
            <form onSubmit={handleLocalResend} className="space-y-4">
              <input
                type="email"
                placeholder="Tu correo"
                className="w-full px-4 py-2 border rounded-md"
                value={email}
                onChange={(e) => onEmailChange(e.target.value)}
                required
              />
              <button
                type="submit"
                disabled={isSending}
                className={`w-full bg-sky-600 text-white py-2 rounded hover:bg-sky-700 transition ${
                  isSending ? "opacity-50 cursor-not-allowed" : ""
                }`}
              >
                {isSending ? "Enviando..." : "Reenviar enlace"}
              </button>
              {resendMsg && <p className="text-sm text-red-500">{resendMsg}</p>}
            </form>
          </>
        )}

        {modalStep === "success" && (
          <>
            <FaCheckCircle className="text-green-500 text-4xl mx-auto mb-2" />
            <p className="text-green-600 text-sm font-medium">{successMsg}</p>
            <p className="text-sm text-gray-500 mt-2">
              Serás redirigido al login...
            </p>
          </>
        )}
      </div>
    </div>
  );
}

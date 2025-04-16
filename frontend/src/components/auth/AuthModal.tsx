import { motion, AnimatePresence } from "framer-motion";
import { FaTimes } from "react-icons/fa";
import { useAuthModal } from "../../store/useAuthModal";
import AuthForm from "./AuthForm";
import AuthSidePanel from "./AuthSidePanel";
import AuthResendModal from "./AuthResendModal";
import { useEffect, useRef, useState } from "react";
import api from "../../api/axios";
import { AxiosError } from "axios";
import { toast } from "react-toastify";

const messages = {
  login: {
    title: "Welcome Back! 👋",
    description: "We're so excited to see you again! Enter your details to access your account.",
    sideTitle: "New Here? 🌟",
    sideDescription: "Join our community and discover amazing features!",
    sideButton: "Create Account",
    submit: "Sign In",
  },
  register: {
    title: "Join Our Community! 🎉",
    description: "Create an account and start your journey with us today.",
    sideTitle: "One of Us? 🎈",
    sideDescription: "Already have an account? Sign in and continue your journey!",
    sideButton: "Sign In",
    submit: "Sign Up",
  },
};

export default function AuthModal() {
  const { isOpen, closeModal, view, toggleView } = useAuthModal();
  const isLogin = view === "login";
  const modalRef = useRef<HTMLDivElement>(null);

  const [formEmail, setFormEmail] = useState("");
  const [resendMsg, setResendMsg] = useState("");
  const [modalStep, setModalStep] = useState<"notice" | "form" | "success">("notice");
  const [modalType, setModalType] = useState<"confirm" | "recover">("confirm");
  const [showModal, setShowModal] = useState(false);

  useEffect(() => {
    const closeOnOutside = (e: MouseEvent) => {
      if (modalRef.current && !modalRef.current.contains(e.target as Node)) closeModal();
    };
    const closeOnEsc = (e: KeyboardEvent) => {
      if (e.key === "Escape") closeModal();
    };
    document.addEventListener("mousedown", closeOnOutside);
    document.addEventListener("keydown", closeOnEsc);
    return () => {
      document.removeEventListener("mousedown", closeOnOutside);
      document.removeEventListener("keydown", closeOnEsc);
    };
  }, [closeModal]);

  const handleResend = async (e: React.FormEvent) => {
    e.preventDefault();
    setResendMsg("");

    const endpoint =
      modalType === "recover" ? "/send-recovery" : "/resend-confirmation";

    try {
      const res = await api.post(endpoint, { email: formEmail });
      setResendMsg(res.data.message);
      setModalStep("success");

      setTimeout(() => {
        toast.success(
          modalType === "recover"
            ? "¡Correo de recuperación enviado!"
            : "¡Correo reenviado!, Revisa tu bandeja..."
        );
        setShowModal(false);
        setResendMsg("");
        setFormEmail("");
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

  if (!isOpen) return null;

  const isDesktop = typeof window !== "undefined" && window.innerWidth >= 768;

  return (
    <>
      <motion.div
        className="fixed inset-0 bg-black/40 backdrop-blur-sm z-[999] flex items-center justify-center p-4 overflow-y-auto"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
      >
        <button
          onClick={closeModal}
          className="absolute top-4 right-4 z-[1000] text-white text-2xl bg-black/50 hover:bg-black/70 p-2 rounded-full"
        >
          <FaTimes />
        </button>

        <motion.div
          ref={modalRef}
          initial={{ scale: 0.95, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          exit={{ scale: 0.9, opacity: 0 }}
          transition={{ duration: 0.3 }}
          className={`bg-bgLight dark:bg-gray-900 text-gray-800 dark:text-gray-100 backdrop-blur-md rounded-3xl shadow-2xl shadow-bgLight w-full max-w-4xl flex flex-col md:flex-row overflow-hidden transition-all ease-in-out duration-700 ${
            isLogin ? "md:flex-row-reverse" : "md:flex-row"
          }`}
        >
          {isDesktop && (
            <AnimatePresence mode="wait">
              <motion.div
                key={view}
                initial={{ x: isLogin ? 300 : -300, opacity: 0 }}
                animate={{ x: 0, opacity: 1 }}
                exit={{ x: isLogin ? -300 : 300, opacity: 0 }}
                transition={{ duration: 0.5, ease: "easeInOut" }}
                className="hidden md:flex w-full md:w-1/2 p-6 md:p-8 flex-col justify-center text-center space-y-6 bg-white dark:bg-gray-800"
              >
                <AuthSidePanel
                  title={messages[view].sideTitle}
                  description={messages[view].sideDescription}
                  buttonText={messages[view].sideButton}
                  onToggle={toggleView}
                />
              </motion.div>
            </AnimatePresence>
          )}

          <AnimatePresence mode="wait">
            <motion.div
              key={`${view}-form`}
              initial={{ x: isLogin ? -300 : 300, opacity: 0 }}
              animate={{ x: 0, opacity: 1 }}
              exit={{ x: isLogin ? 300 : -300, opacity: 0 }}
              transition={{ duration: 0.5, ease: "easeInOut" }}
              className="w-full md:w-1/2 p-6 md:p-8 bg-gray-50 dark:bg-gray-900"
            >
              <h2 className="text-3xl font-bold text-center mb-2 bg-gradient-to-r from-indigo-500 via-purple-500 to-pink-500 text-transparent bg-clip-text">
                {messages[view].title}
              </h2>
              <p className="text-center text-sm text-gray-600 dark:text-gray-300 mb-4">
                {messages[view].description}
              </p>

              <AuthForm
                modalStep={modalStep}
                showModal={showModal}
                modalType={modalType}
                setFormEmail={setFormEmail}
                setModalStep={setModalStep}
                setShowModal={setShowModal}
                setModalType={setModalType}
              />
            </motion.div>
          </AnimatePresence>
        </motion.div>
      </motion.div>

      <AuthResendModal
        modalStep={modalStep}
        showModal={showModal}
        email={formEmail}
        resendMsg={resendMsg}
        onClose={() => setShowModal(false)}
        onEmailChange={setFormEmail}
        onResend={handleResend}
        type={modalType}
      />
    </>
  );
}

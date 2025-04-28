# Contenido de Archivos

## eslint.config.js

```javascript
import js from '@eslint/js'
import globals from 'globals'
import reactHooks from 'eslint-plugin-react-hooks'
import reactRefresh from 'eslint-plugin-react-refresh'
import tseslint from 'typescript-eslint'

export default tseslint.config(
  { ignores: ['dist'] },
  {
    extends: [js.configs.recommended, ...tseslint.configs.recommended],
    files: ['**/*.{ts,tsx}'],
    languageOptions: {
      ecmaVersion: 2020,
      globals: globals.browser,
    },
    plugins: {
      'react-hooks': reactHooks,
      'react-refresh': reactRefresh,
    },
    rules: {
      ...reactHooks.configs.recommended.rules,
      'react-refresh/only-export-components': [
        'warn',
        { allowConstantExport: true },
      ],
    },
  },
)

```

## index.html

```html
<!doctype html>
<html lang="en">

<head>
  <meta charset="UTF-8" />
  <link rel="icon" type="image" href="/ARP logo.png" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Aqua River Park</title>
</head>

<body>
  <div id="root"></div>
  <script type="module" src="/src/main.tsx"></script>
</body>

</html>
```
## README.md

```markdown
# React + TypeScript + Vite

This template provides a minimal setup to get React working in Vite with HMR and some ESLint rules.

Currently, two official plugins are available:

- [@vitejs/plugin-react](https://github.com/vitejs/vite-plugin-react/blob/main/packages/plugin-react/README.md) uses [Babel](https://babeljs.io/) for Fast Refresh
- [@vitejs/plugin-react-swc](https://github.com/vitejs/vite-plugin-react-swc) uses [SWC](https://swc.rs/) for Fast Refresh

## Expanding the ESLint configuration

If you are developing a production application, we recommend updating the configuration to enable type-aware lint rules:

```js
export default tseslint.config({
  extends: [
    // Remove ...tseslint.configs.recommended and replace with this
    ...tseslint.configs.recommendedTypeChecked,
    // Alternatively, use this for stricter rules
    ...tseslint.configs.strictTypeChecked,
    // Optionally, add this for stylistic rules
    ...tseslint.configs.stylisticTypeChecked,
  ],
  languageOptions: {
    // other options...
    parserOptions: {
      project: ['./tsconfig.node.json', './tsconfig.app.json'],
      tsconfigRootDir: import.meta.dirname,
    },
  },
})
```

You can also install [eslint-plugin-react-x](https://github.com/Rel1cx/eslint-react/tree/main/packages/plugins/eslint-plugin-react-x) and [eslint-plugin-react-dom](https://github.com/Rel1cx/eslint-react/tree/main/packages/plugins/eslint-plugin-react-dom) for React-specific lint rules:

```js
// eslint.config.js
import reactX from 'eslint-plugin-react-x'
import reactDom from 'eslint-plugin-react-dom'

export default tseslint.config({
  plugins: {
    // Add the react-x and react-dom plugins
    'react-x': reactX,
    'react-dom': reactDom,
  },
  rules: {
    // other rules...
    // Enable its recommended typescript rules
    ...reactX.configs['recommended-typescript'].rules,
    ...reactDom.configs.recommended.rules,
  },
})
```

```

## src\api\axios.ts

```typescript
// frontend/src/api/axios.ts
import axios from 'axios';

const api = axios.create({
  baseURL: 'http://localhost:3000/api', // 👈 Este debe apuntar al backend
});

export default api;

```

## src\App.css

```css

```

## src\App.tsx

```tsx
// src/App.tsx
import { BrowserRouter as Router } from "react-router-dom";
import AppRouter from "./router/AppRouter";
import { ToastContainer } from "react-toastify";
import { useAuthModal } from "./store/useAuthModal";
import AuthModal from "./components/auth/AuthModal";
import RouteModalHandler from "./components/RouteModalHandler";
import "react-toastify/dist/ReactToastify.css";

function App() {
  const { isOpen } = useAuthModal();

  return (
    <Router>
      <RouteModalHandler />
      <AppRouter />
      {isOpen && <AuthModal />}
      <ToastContainer position="top-right" autoClose={3000} />
    </Router>
  );
}

export default App;

```
## src\components\auth\AuthForm.tsx

```tsx
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { AxiosError } from "axios";
import api from "../../api/axios";
import { toast } from "react-toastify";
import { useAuthModal } from "../../store/useAuthModal";
import AuthResendModal from "./AuthResendModal";
import {
  getPasswordScore,
  capitalizeName,
  validateEmailFormat,
  validatePasswordSecurity,
} from "../../utils/validationHelpersForm";

import InputWithLabel from "../common/InputWithLabel";
import PasswordWithStrengthInput from "../common/PasswordWithStrengthInputForm";

interface Props {
  modalStep: "notice" | "form" | "success";
  showModal: boolean;
  modalType: "confirm" | "recover";
  setFormEmail: React.Dispatch<React.SetStateAction<string>>;
  setModalStep: React.Dispatch<
    React.SetStateAction<"notice" | "form" | "success">
  >;
  setShowModal: React.Dispatch<React.SetStateAction<boolean>>;
  setModalType: React.Dispatch<React.SetStateAction<"confirm" | "recover">>;
}

const initialForm = {
  fullName: "",
  email: "",
  phone: "",
  password: "",
  confirmPassword: "",
};

export default function AuthForm({
  modalStep,
  showModal,
  modalType,
  setFormEmail,
  setModalStep,
  setShowModal,
  setModalType,
}: Props) {
  const { view, closeModal, toggleView } = useAuthModal();
  const isLogin = view === "login";
  const navigate = useNavigate();

  const [formData, setFormData] = useState(initialForm);
  const [errors, setErrors] = useState<{ [key: string]: string }>({});
  const [passwordStrength, setPasswordStrength] = useState(0);
  const [resendMsg, setResendMsg] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);

  const handleInput = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;

    const formattedValue = name === "fullName" ? capitalizeName(value) : value;

    if (name === "password") setPasswordStrength(getPasswordScore(value));

    setFormData((prev) => ({ ...prev, [name]: formattedValue }));
    setErrors((prev) => ({ ...prev, [name]: "" }));
  };

  const validate = () => {
    const errs: { [key: string]: string } = {};

    if (!validateEmailFormat(formData.email)) {
      errs.email = "Correo no válido";
    }

    const passwordErrors = validatePasswordSecurity(
      formData.password,
      formData.email
    );
    if (passwordErrors.length > 0) {
      errs.password = passwordErrors.join(" ");
    }

    if (!isLogin) {
      if (!formData.fullName || formData.fullName.length < 2) {
        errs.fullName = "El nombre debe tener al menos 2 caracteres.";
      }

      if (!/^[0-9]{10}$/.test(formData.phone)) {
        errs.phone = "El teléfono debe tener 10 dígitos.";
      }

      if (formData.password !== formData.confirmPassword) {
        errs.confirmPassword = "Las contraseñas no coinciden.";
      }
    }

    setErrors(errs);
    return Object.keys(errs).length === 0;
  };

  const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (isSubmitting) return; // Evita múltiples envíos
    setIsSubmitting(true);

    const isValid = validate();
    if (!isValid) {
      setIsSubmitting(false); // 🔁 Agrega esto para volver a habilitar el botón
      return;
    }

    try {
      if (isLogin) {
        const res = await api.post("/login", {
          email: formData.email,
          password: formData.password,
        });

        if (!res.data.user.isConfirmed) {
          const tokenExpired = res.data.tokenExpired;
          setModalType("confirm");
          setModalStep(tokenExpired ? "form" : "notice");
          setShowModal(true);
          return;
        }

        closeModal();
        toast.success("Login exitoso!");
        navigate("/");
      } else {
        const res = await api.post("/register", {
          name: formData.fullName,
          email: formData.email,
          phone: formData.phone,
          password: formData.password,
        });

        if (res.status === 200 || res.status === 201) {
          toast.success("Registro exitoso. Revisa tu correo.");
          toggleView();
        }
      }
    } catch (err) {
      const error = err as AxiosError<{
        message: string;
        tokenExpired?: boolean;
      }>;
      const msg = error.response?.data?.message;

      if (msg === "Debes confirmar tu cuenta") {
        const tokenExpired = error.response?.data?.tokenExpired;
        setModalType("confirm");
        setModalStep(tokenExpired ? "form" : "notice");
        setShowModal(true);
      } else if (msg) {
        toast.error(msg);
      } else {
        toast.error("Ocurrió un error inesperado.");
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleResend = async (e: React.FormEvent) => {
    e.preventDefault();
    if (isSubmitting) return; // Evita múltiples envíos
    setIsSubmitting(true);
    setResendMsg("");

    const endpoint =
      modalType === "recover" ? "/send-recovery" : "/resend-confirmation";

    try {
      const res = await api.post(endpoint, {
        email: formData.email,
      });

      setResendMsg(res.data.message);
      setModalStep("success");

      setTimeout(() => {
        toast.success(
          modalType === "recover"
            ? "¡Enlace de recuperación enviado!"
            : "¡Correo de confirmación reenviado!"
        );
        setShowModal(false);
        setResendMsg("");
        setFormData((prev) => ({ ...prev, email: "", password: "" }));
      }, 5000);
    } catch (err) {
      const error = err as AxiosError<{ message: string }>;
      const msg = error.response?.data?.message;

      if (msg === "La cuenta ya está confirmada") {
        toast.info("La cuenta ya ha sido confirmada.");
        setShowModal(false);
      } else {
        setResendMsg("Error al enviar el enlace.");
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <>
      <form onSubmit={handleSubmit} className="space-y-4">
        {!isLogin && (
          <>
            <InputWithLabel
              label=""
              name="fullName"
              value={formData.fullName}
              onChange={handleInput}
              placeholder="Tu nombre completo"
              error={errors.fullName}
            />

            <InputWithLabel
              label=""
              name="phone"
              value={formData.phone}
              onChange={handleInput}
              placeholder="Teléfono"
              error={errors.phone}
            />
          </>
        )}

        <InputWithLabel
          label=""
          name="email"
          type="email"
          value={formData.email}
          onChange={handleInput}
          placeholder="Mail"
          error={errors.email}
          autoFocus
        />

        <PasswordWithStrengthInput
          value={formData.password}
          onChange={handleInput}
          error={errors.password}
          showTooltip={!isLogin}
          showStrengthBar={!isLogin}
        />

        {!isLogin && (
          <InputWithLabel
            label=""
            name="confirmPassword"
            type="password"
            value={formData.confirmPassword}
            onChange={handleInput}
            placeholder="Confirma tu contraseña"
            error={errors.confirmPassword}
          />
        )}

        {isLogin && (
          <div className="flex justify-end text-sm text-blue-600">
            <button
              type="button"
              className="hover:underline"
              onClick={() => {
                setModalType("recover");
                setModalStep("form");
                setShowModal(true);
                setFormEmail(formData.email); // importante para usar en el modal
              }}
            >
              Forgot Password?
            </button>
          </div>
        )}

        <button
          type="submit"
          disabled={isSubmitting || (!isLogin && passwordStrength < 3)}
          className={`w-full bg-gradient-to-r from-indigo-500 via-purple-500 to-pink-500 text-white py-2 rounded-lg hover:opacity-90 transition-all ${
            isSubmitting ? "opacity-50 cursor-not-allowed" : ""
          }`}
        >
          {isSubmitting ? "Conectando..." : isLogin ? "Sign In" : "Sign Up"}
        </button>

        <p className="text-center text-sm text-gray-600 mt-4">
          {isLogin ? "No tienes una cuenta?" : "Ya tienes una cuenta?"}{" "}
          <button
            type="button"
            onClick={toggleView}
            className="text-blue-600 font-semibold hover:underline"
          >
            {isLogin ? "Sign Up" : "Sign In"}
          </button>
        </p>
      </form>

      <AuthResendModal
        modalStep={modalStep}
        showModal={showModal}
        email={formData.email}
        resendMsg={resendMsg}
        onClose={() => setShowModal(false)}
        onEmailChange={(email) => setFormData((prev) => ({ ...prev, email }))}
        onResend={handleResend}
        type={modalType}
      />
    </>
  );
}

```

## src\components\auth\AuthModal.tsx

```tsx
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
    title: "Bienvenido de vuelta! 👋",
    description: "Estamos emocionados de verte nuevamente! Ingresa tus credenciales para acceder a tu cuenta.",
    sideTitle: "Nuevo aquí? 🌟",
    sideDescription: "Únete a nuestra comunidad y descubre cosas increíbles!",
    sideButton: "Cerar Cuenta",
    submit: "Sign In",
  },
  register: {
    title: "Únete a nuestra comunidad! 🎉",
    description: "Crea una cuenta y comienza tu viaje con nosotros hoy.",
    sideTitle: "Uno de nosotros? 🎈",
    sideDescription: "¿Ya tienes una cuenta? Inicia sesión y continúa tu viaje!",
    sideButton: "Iniciar sesión",
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
              className={`w-full md:w-1/2 p-6 md:p-8 bg-gray-50 dark:bg-gray-900 flex flex-col justify-center`}
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

```

## src\components\auth\AuthResendModal.tsx

```tsx
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
  const formTitle = isRecover ? "¿Necesitas un nuevo enlace?" : "Reenviar Enlace";
  const formDescription = isRecover ? "Ingresa tu correo para recuperar tu contraseña." : "Verificación de usuario expirada, ingresa tu correo para recibir un nuevo enlace de confirmación:";
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

```

## src\components\auth\AuthSidePanel.tsx

```tsx
// src/components/auth/AuthSidePanel.tsx
import { motion } from "framer-motion";

interface Props {
  title: string;
  description: string;
  buttonText: string;
  onToggle: () => void;
}

export default function AuthSidePanel({ title, description, buttonText, onToggle }: Props) {
  return (
    <motion.div
      key={title}
      initial={{ x: 300, opacity: 0 }}
      animate={{ x: 0, opacity: 1 }}
      exit={{ x: -300, opacity: 0 }}
      transition={{ duration: 0.5, ease: "easeInOut" }}
      className="w-full md:w-fit p-6 md:p-8 flex flex-col justify-center text-center space-y-6 bg-white"
    >
      <h2 className="text-3xl md:text-4xl font-bold bg-gradient-to-r from-indigo-500 via-purple-500 to-pink-500 text-transparent bg-clip-text">
        {title}
      </h2>
      <p className="text-gray-600">{description}</p>
      <button
        onClick={onToggle}
        className="px-6 py-3 rounded-full bg-gradient-to-r from-indigo-500 via-purple-500 to-pink-500 text-white font-semibold hover:scale-105 transition-all"
      >
        {buttonText}
      </button>
    </motion.div>
  );
}

```

## src\components\common\Alert.tsx

```tsx
import React from "react";
import classNames from "classnames";
import {
  FaCheckCircle,
  FaExclamationTriangle,
  FaInfoCircle,
  FaTimesCircle,
} from "react-icons/fa";

interface AlertProps {
  type?: "success" | "error" | "warning" | "info";
  message: string;
  className?: string;
}

const iconMap = {
  success: <FaCheckCircle className="text-green-600 text-xl mr-2" />,
  error: <FaTimesCircle className="text-red-600 text-xl mr-2" />,
  warning: <FaExclamationTriangle className="text-yellow-600 text-xl mr-2" />,
  info: <FaInfoCircle className="text-blue-600 text-xl mr-2" />,
};

const Alert: React.FC<AlertProps> = ({
  type = "info",
  message,
  className = "",
}) => {
  const baseStyles =
    "flex items-start gap-2 px-4 py-3 rounded-md shadow-sm text-sm font-medium";

  const typeStyles = {
    success: "bg-green-100 text-green-800 dark:bg-green-900/20 dark:text-green-200",
    error: "bg-red-100 text-red-800 dark:bg-red-900/20 dark:text-red-200",
    warning: "bg-yellow-100 text-yellow-800 dark:bg-yellow-900/20 dark:text-yellow-200",
    info: "bg-blue-100 text-blue-800 dark:bg-blue-900/20 dark:text-blue-200",
  };

  return (
    <div className={classNames(baseStyles, typeStyles[type], className)}>
      {iconMap[type]}
      <span>{message}</span>
    </div>
  );
};

export default Alert;

```

## src\components\common\Avatar.tsx

```tsx
import React from "react";
import classNames from "classnames";

interface AvatarProps {
  name?: string;
  imageUrl?: string;
  size?: "sm" | "md" | "lg";
  status?: "online" | "offline" | "busy";
  className?: string;
}

const sizeClasses = {
  sm: "w-8 h-8 text-sm",
  md: "w-10 h-10 text-base",
  lg: "w-14 h-14 text-lg",
};

const statusColors = {
  online: "bg-green-500",
  offline: "bg-gray-400",
  busy: "bg-red-500",
};

export const Avatar: React.FC<AvatarProps> = ({
  name,
  imageUrl,
  size = "md",
  status,
  className = "",
}) => {
  const initials = name
    ? name
        .split(" ")
        .map((n) => n[0])
        .join("")
        .toUpperCase()
        .slice(0, 2)
    : "?";

  return (
    <div className={classNames("relative inline-block", className)}>
      <div
        className={classNames(
          "rounded-full bg-gray-200 dark:bg-gray-700 flex items-center justify-center overflow-hidden text-white font-semibold",
          sizeClasses[size]
        )}
      >
        {imageUrl ? (
          <img
            src={imageUrl}
            alt={name}
            className="w-full h-full object-cover"
          />
        ) : (
          <span>{initials}</span>
        )}
      </div>

      {status && (
        <span
          className={classNames(
            "absolute bottom-0 right-0 w-3 h-3 rounded-full ring-2 ring-white dark:ring-gray-900",
            statusColors[status]
          )}
        />
      )}
    </div>
  );
};

export default Avatar;

```

## src\components\common\Breadcrumb.tsx

```tsx
import React from "react";
import { Link } from "react-router-dom";
import { FaChevronRight } from "react-icons/fa";

interface BreadcrumbItem {
  label: string;
  path?: string;
  isCurrent?: boolean;
}

interface BreadcrumbProps {
  items: BreadcrumbItem[];
  className?: string;
}

const Breadcrumb: React.FC<BreadcrumbProps> = ({ items, className = "" }) => {
  return (
    <nav
      className={`text-sm text-gray-600 dark:text-gray-300 ${className}`}
      aria-label="breadcrumb"
    >
      <ol className="flex flex-wrap items-center space-x-2">
        {items.map((item, idx) => (
          <li key={idx} className="flex items-center">
            {item.path && !item.isCurrent ? (
              <Link
                to={item.path}
                className="hover:underline text-blue-600 dark:text-blue-400"
              >
                {item.label}
              </Link>
            ) : (
              <span className="font-semibold text-gray-900 dark:text-white">
                {item.label}
              </span>
            )}
            {idx < items.length - 1 && (
              <FaChevronRight className="mx-2 text-xs text-gray-400" />
            )}
          </li>
        ))}
      </ol>
    </nav>
  );
};

export default Breadcrumb;

```

## src\components\common\Button.tsx

```tsx
import React from "react";
import { Spinner } from "./Spinner";
import classNames from "classnames";

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: "primary" | "secondary" | "danger" | "outline";
  isLoading?: boolean;
  fullWidth?: boolean;
}

const Button: React.FC<ButtonProps> = ({
  children,
  variant = "primary",
  isLoading = false,
  fullWidth = false,
  className,
  ...props
}) => {
  const baseStyles =
    "inline-flex items-center justify-center px-4 py-2 rounded-md font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-offset-2";

  const variantStyles = {
    primary:
      "bg-blue-600 text-white hover:bg-blue-700 focus:ring-blue-500 dark:bg-blue-500 dark:hover:bg-blue-600",
    secondary:
      "bg-gray-200 text-gray-900 hover:bg-gray-300 focus:ring-gray-400 dark:bg-gray-700 dark:text-white dark:hover:bg-gray-600",
    danger:
      "bg-red-600 text-white hover:bg-red-700 focus:ring-red-500 dark:bg-red-500 dark:hover:bg-red-600",
    outline:
      "border border-gray-300 text-gray-700 hover:bg-gray-100 focus:ring-gray-400 dark:border-gray-600 dark:text-white dark:hover:bg-gray-700",
  };

  const computedClasses = classNames(
    baseStyles,
    variantStyles[variant],
    {
      "w-full": fullWidth,
      "opacity-50 cursor-not-allowed": props.disabled || isLoading,
    },
    className
  );

  return (
    <button className={computedClasses} disabled={props.disabled || isLoading} {...props}>
      {isLoading && <Spinner className="mr-2 h-4 w-4 animate-spin" />}
      {children}
    </button>
  );
};

export default Button;

```

## src\components\common\Card.tsx

```tsx
import React from "react";
import classNames from "classnames";

interface CardProps extends React.HTMLAttributes<HTMLDivElement> {
  title?: string;
  subtitle?: string;
  footer?: React.ReactNode;
  children: React.ReactNode;
  shadow?: boolean;
  hoverable?: boolean;
  rounded?: boolean;
  bordered?: boolean;
}

const Card: React.FC<CardProps> = ({
  title,
  subtitle,
  footer,
  children,
  className,
  shadow = true,
  hoverable = false,
  rounded = true,
  bordered = false,
  ...props
}) => {
  return (
    <div
      className={classNames(
        "bg-white dark:bg-bgDark text-textDark dark:text-textLight transition-all duration-300",
        {
          "shadow-md": shadow,
          "hover:shadow-lg hover:scale-[1.01] transform transition-all":
            hoverable,
          "rounded-lg": rounded,
          "border border-gray-200 dark:border-gray-700": bordered,
        },
        className
      )}
      {...props}
    >
      {(title || subtitle) && (
        <div className="p-4 border-b border-gray-100 dark:border-gray-700">
          {title && <h2 className="text-lg font-semibold">{title}</h2>}
          {subtitle && (
            <p className="text-sm text-gray-500 dark:text-gray-400">
              {subtitle}
            </p>
          )}
        </div>
      )}

      <div className="p-4">{children}</div>

      {footer && (
        <div className="px-4 py-3 border-t border-gray-100 dark:border-gray-700">
          {footer}
        </div>
      )}
    </div>
  );
};

export default Card;

```

## src\components\common\CardGrid.tsx

```tsx
import React from "react";
import classNames from "classnames";

interface CardGridProps {
  children: React.ReactNode;
  columns?: number; // número de columnas base (por defecto 1 en móvil, luego responsive)
  gap?: string; // espacio entre tarjetas (por defecto 'gap-6')
  className?: string;
}

const CardGrid: React.FC<CardGridProps> = ({
  children,
  columns = 1,
  gap = "gap-6",
  className = "",
}) => {
  const gridCols = {
    1: "grid-cols-1",
    2: "sm:grid-cols-2",
    3: "sm:grid-cols-2 md:grid-cols-3",
    4: "sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4",
  };

  return (
    <div
      className={classNames(
        "grid w-full",
        gap,
        gridCols[columns as keyof typeof gridCols],
        className
      )}
    >
      {children}
    </div>
  );
};

export default CardGrid;

```

## src\components\common\CustomToast.tsx

```tsx
import { toast, ToastOptions } from "react-toastify";

const baseOptions: ToastOptions = {
  position: "top-right",
  autoClose: 4000,
  pauseOnHover: true,
  draggable: true,
  closeOnClick: true,
};

export const showSuccess = (message: string, options?: ToastOptions) => {
  toast.success(message, { ...baseOptions, ...options });
};

export const showError = (message: string, options?: ToastOptions) => {
  toast.error(message, { ...baseOptions, ...options });
};

export const showInfo = (message: string, options?: ToastOptions) => {
  toast.info(message, { ...baseOptions, ...options });
};

export const showWarning = (message: string, options?: ToastOptions) => {
  toast.warn(message, { ...baseOptions, ...options });
};

```

## src\components\common\DropdownMenu.tsx

```tsx
import { Link } from "react-router-dom";
import { AnimatePresence, motion } from "framer-motion";

interface Props {
  visible: boolean;
  menuKey: string;
  labels: string[];
  onLinkClick: () => void;
}

export const DropdownMenu: React.FC<Props> = ({
  visible,
  menuKey,
  labels,
  onLinkClick,
}) => {
  return (
    <AnimatePresence>
      {visible && (
        <motion.div
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          exit={{ opacity: 0, scale: 0.95 }}
          transition={{ duration: 0.2, ease: "easeOut" }}
          className="absolute left-1/2 transform -translate-x-1/2 top-full mt-2 w-56 max-h-[70vh] overflow-y-auto backdrop-blur-md bg-bgLight/30 dark:bg-bgDark/40 text-textDark dark:text-textLight rounded-xl shadow-xl ring-1 ring-bgLight/25 z-50"
        >
          {labels.map((label, idx) => (
            <Link
              key={idx}
              to={`/${menuKey}#${label.toLowerCase().replace(/\s+/g, "-")}`}
              onClick={onLinkClick}
              className="block px-4 py-2 text-sm font-semibold hover:bg-accent2/80 hover:text-white dark:hover:bg-bgLight/80 dark:hover:text-textDark/90 transition-all duration-200"
            >
              {label}
            </Link>
          ))}
        </motion.div>
      )}
    </AnimatePresence>
  );
};

```

## src\components\common\FormField.tsx

```tsx
import React from "react";
import classNames from "classnames";

interface FormFieldProps {
  label: string;
  name: string;
  type?: string;
  value: string;
  onChange: (e: React.ChangeEvent<HTMLInputElement>) => void;
  placeholder?: string;
  icon?: React.ReactNode;
  error?: string;
  required?: boolean;
  disabled?: boolean;
  autoComplete?: string;
}

const FormField: React.FC<FormFieldProps> = ({
  label,
  name,
  type = "text",
  value,
  onChange,
  placeholder = "",
  icon,
  error,
  required = false,
  disabled = false,
  autoComplete,
}) => {
  return (
    <div className="mb-4">
      <label
        htmlFor={name}
        className="block text-sm font-medium text-gray-700 dark:text-gray-200 mb-1"
      >
        {label} {required && <span className="text-red-500">*</span>}
      </label>

      <div className="relative">
        {icon && (
          <div className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 pointer-events-none">
            {icon}
          </div>
        )}

        <input
          type={type}
          name={name}
          id={name}
          value={value}
          onChange={onChange}
          placeholder={placeholder}
          disabled={disabled}
          autoComplete={autoComplete}
          className={classNames(
            "w-full border rounded-md py-2 px-3 focus:outline-none focus:ring-2",
            {
              "pl-10": icon,
              "border-gray-300 focus:ring-blue-500":
                !error && !disabled,
              "border-red-500 focus:ring-red-500": error,
              "bg-gray-100 cursor-not-allowed": disabled,
              "dark:bg-gray-800 dark:text-white dark:border-gray-600": true,
            }
          )}
        />
      </div>

      {error && (
        <p className="text-red-500 text-sm mt-1 font-medium">{error}</p>
      )}
    </div>
  );
};

export default FormField;

```

## src\components\common\Input.tsx

```tsx
import React from "react";
import { twMerge } from "tailwind-merge";

interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  label?: string;
  error?: string;
  icon?: React.ReactNode;
  fullWidth?: boolean;
}

const Input: React.FC<InputProps> = ({
  label,
  error,
  icon,
  fullWidth = true,
  className,
  ...props
}) => {
  return (
    <div className={twMerge("mb-4", fullWidth ? "w-full" : "", className)}>
      {label && (
        <label className="block text-sm font-medium text-gray-700 dark:text-textLight mb-1">
          {label}
        </label>
      )}

      <div className="relative">
        {icon && (
          <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-gray-500 dark:text-gray-300">
            {icon}
          </div>
        )}
        <input
          {...props}
          className={twMerge(
            "appearance-none block w-full px-3 py-2 border rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent text-sm",
            icon ? "pl-10" : "",
            error
              ? "border-red-500 focus:ring-red-500"
              : "border-gray-300 dark:border-gray-600 dark:bg-bgDark dark:text-textLight",
            props.disabled ? "opacity-50 cursor-not-allowed" : ""
          )}
        />
      </div>

      {error && (
        <p className="text-sm text-red-600 mt-1 font-medium">{error}</p>
      )}
    </div>
  );
};

export default Input;

```

## src\components\common\InputWithLabel.tsx

```tsx
import React from "react";

interface Props extends React.InputHTMLAttributes<HTMLInputElement> {
  label: string;
  name: string;
  error?: string;
}

const InputWithLabel: React.FC<Props> = ({
  label,
  name,
  error,
  ...props
}) => {
  return (
    <div className="mb-4">
      <label
        htmlFor={name}
        className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-1 flex items-center gap-2"
      >
        {label}
      </label>

      <input
        id={name}
        name={name}
        className="input-style outline-none dark:bg-gray-900 dark:text-white dark:border-gray-700"
        {...props}
      />

      {error && <p className="text-red-500 text-sm mt-1">{error}</p>}
    </div>
  );
};

export default InputWithLabel;

```

## src\components\common\Modal.tsx

```tsx
import React from "react";
import { motion, AnimatePresence } from "framer-motion";
import { FaTimes } from "react-icons/fa";

interface ModalProps {
  isOpen: boolean;
  onClose: () => void;
  title?: string;
  children: React.ReactNode;
  size?: "sm" | "md" | "lg";
  hideCloseButton?: boolean;
}

const sizeClasses = {
  sm: "max-w-sm",
  md: "max-w-md",
  lg: "max-w-2xl",
};

const Modal: React.FC<ModalProps> = ({
  isOpen,
  onClose,
  title,
  children,
  size = "md",
  hideCloseButton = false,
}) => {
  return (
    <AnimatePresence>
      {isOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <motion.div
            initial={{ opacity: 0, y: -30 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: 20 }}
            transition={{ duration: 0.3 }}
            className={`bg-white dark:bg-bgDark text-textDark dark:text-textLight rounded-lg shadow-lg w-full ${sizeClasses[size]} relative px-6 py-5`}
          >
            {!hideCloseButton && (
              <button
                className="absolute top-3 right-4 text-gray-400 hover:text-red-500 transition"
                onClick={onClose}
                aria-label="Cerrar modal"
              >
                <FaTimes />
              </button>
            )}

            {title && (
              <h2 className="text-xl font-semibold mb-4 text-center">
                {title}
              </h2>
            )}

            <div>{children}</div>
          </motion.div>
        </div>
      )}
    </AnimatePresence>
  );
};

export default Modal;

```

## src\components\common\PasswordField.tsx

```tsx
import React, { useState } from "react";
import classNames from "classnames";
import { FaEye, FaEyeSlash } from "react-icons/fa";

interface PasswordFieldProps {
  label: string;
  name: string;
  value: string;
  onChange: (e: React.ChangeEvent<HTMLInputElement>) => void;
  placeholder?: string;
  error?: string;
  required?: boolean;
  autoComplete?: string;
}

const PasswordField: React.FC<PasswordFieldProps> = ({
  label,
  name,
  value,
  onChange,
  placeholder = "••••••••",
  error,
  required = false,
  autoComplete = "current-password",
}) => {
  const [showPassword, setShowPassword] = useState(false);

  return (
    <div className="mb-4">
      <label
        htmlFor={name}
        className="block text-sm font-medium text-gray-700 dark:text-gray-200 mb-1"
      >
        {label} {required && <span className="text-red-500">*</span>}
      </label>

      <div className="relative">
        <input
          id={name}
          name={name}
          type={showPassword ? "text" : "password"}
          value={value}
          onChange={onChange}
          placeholder={placeholder}
          autoComplete={autoComplete}
          className={classNames(
            "w-full border rounded-md py-2 px-3 pr-10 focus:outline-none focus:ring-2",
            {
              "border-gray-300 focus:ring-blue-500": !error,
              "border-red-500 focus:ring-red-500": !!error,
              "dark:bg-gray-800 dark:text-white dark:border-gray-600": true,
            }
          )}
        />

        <button
          type="button"
          onClick={() => setShowPassword((prev) => !prev)}
          className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-500 hover:text-gray-700 dark:text-gray-300"
          aria-label="Mostrar u ocultar contraseña"
        >
          {showPassword ? <FaEyeSlash /> : <FaEye />}
        </button>
      </div>

      {error && (
        <p className="text-red-500 text-sm mt-1 font-medium">{error}</p>
      )}
    </div>
  );
};

export default PasswordField;

```

## src\components\common\PasswordWithStrengthInputForm.tsx

```tsx
import { useState } from "react";
import { FaEye, FaEyeSlash, FaInfoCircle } from "react-icons/fa";
import {
  getPasswordScore,
  getStrengthLabel,
} from "../../utils/validationHelpersForm";

interface Props {
  value: string;
  onChange: (e: React.ChangeEvent<HTMLInputElement>) => void;
  error?: string;
  showTooltip?: boolean;
  showStrengthBar?: boolean;
  autoFocus?: boolean;
  name?: string;
  placeholder?: string;
}

export default function PasswordWithStrengthInput({
  value,
  onChange,
  error,
  showTooltip = true,
  showStrengthBar = true,
  autoFocus = false,
  name = "password",
  placeholder = "Password",
}: Props) {
  const [showPassword, setShowPassword] = useState(false);
  const score = getPasswordScore(value);
  const label = getStrengthLabel(score);

  return (
    <div className="relative mb-4">
      <div className="absolute flex justify-start mb-1 top-[-14px] left-[4px]">
        {showTooltip && (
          <div className="relative group inline-block">
            <FaInfoCircle
              className="text-blue-500 dark:text-blue-400 cursor-pointer p-0.5"
              tabIndex={0} // para accesibilidad en teclado
            />
            <div className="absolute z-30 top-full right-[-260px] mt-2 w-72 md:w-64 text-xs bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 text-gray-800 dark:text-gray-200 p-2 rounded shadow-md opacity-0 invisible group-hover:opacity-100 group-hover:visible group-focus-within:opacity-100 group-focus-within:visible transition-opacity duration-200 pointer-events-none">
              Usa mínimo 8 caracteres, una mayúscula, un número y un símbolo especial. No uses tu correo ni contraseñas anteriores.
            </div>
          </div>
        )}
      </div>

      <input
        type={showPassword ? "text" : "password"}
        name={name}
        value={value}
        onChange={onChange}
        placeholder={placeholder}
        autoFocus={autoFocus}
        className="input-style pr-10 outline-none dark:bg-gray-900 dark:text-white dark:border-gray-700"
      />

      <button
        type="button"
        onClick={() => setShowPassword(!showPassword)}
        className="absolute right-3 top-[20px] text-gray-600 dark:text-gray-300 hover:text-blue-600 dark:hover:text-blue-400 transition"
        tabIndex={-1}
      >
        {showPassword ? <FaEyeSlash /> : <FaEye />}
      </button>

      {error && <p className="text-red-500 text-sm mt-1">{error}</p>}

      {showStrengthBar && (
        <div className="mt-2">
          <div className="flex gap-1">
            {[...Array(4)].map((_, i) => (
              <div
                key={i}
                className={`h-2 flex-1 rounded ${
                  i < score ? label.bar : "bg-gray-200 dark:bg-gray-600"
                }`}
              />
            ))}
          </div>
          {score > 0 && (
            <p className={`text-sm mt-1 ${label.color}`}>Fuerza: {label.text}</p>
          )}
        </div>
      )}
    </div>
  );
}

```

## src\components\common\Spinner.tsx

```tsx
import React from "react";

interface SpinnerProps {
  size?: number;
  className?: string;
  color?: string;
}

export const Spinner: React.FC<SpinnerProps> = ({
  size = 24,
  className = "",
  color = "var(--color-primary)", // Puedes usar cualquier variable de tu theme
}) => {
  return (
    <svg
      className={`animate-spin ${className}`}
      width={size}
      height={size}
      viewBox="0 0 24 24"
      style={{ color }}
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
    >
      <circle
        className="opacity-25"
        cx="12"
        cy="12"
        r="10"
        stroke="currentColor"
        strokeWidth="4"
      ></circle>
      <path
        className="opacity-75"
        fill="currentColor"
        d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"
      ></path>
    </svg>
  );
};

```

## src\components\common\ToastNotification.tsx

```tsx
import { ToastContainer } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";

const ToastNotification = () => {
  return (
    <ToastContainer
      position="top-right"
      autoClose={5000}
      hideProgressBar={false}
      newestOnTop={false}
      closeOnClick
      rtl={false}
      pauseOnFocusLoss
      draggable
      pauseOnHover
      theme="colored" // Puedes cambiar a "light" o "dark"
      toastClassName={() =>
        "bg-white dark:bg-bgDark text-textDark dark:text-textLight rounded shadow-md px-4 py-3"
      }
      className="text-sm font-medium"
      progressClassName={() => "bg-[var(--color-primary)]"}
    />
  );
};

export default ToastNotification;

```

## src\components\home\Attractions.tsx

```tsx
// components/Attractions.tsx
import { FaWater, FaMountain, FaSpa, FaFish, FaSun, FaBiking } from "react-icons/fa";
import { motion } from "framer-motion";
import AOS from 'aos';
import 'aos/dist/aos.css';
import { useEffect } from 'react';

const attractions = [
  {
    icon: <FaWater size={36} className="text-cyan-500 group-hover:text-purple-600 transition-colors" />,
    title: "Río y Toboganes",
    description: "Deslízate en nuestros toboganes o relájate en el río lento.",
  },
  {
    icon: <FaMountain size={36} className="text-amber-600 group-hover:text-purple-600 transition-colors" />,
    title: "Zona Natural",
    description: "Senderos rodeados de vegetación y aire puro.",
  },
  {
    icon: <FaSpa size={36} className="text-pink-500 group-hover:text-purple-600 transition-colors" />,
    title: "Área Zen",
    description: "Relájate en nuestra zona de masajes y spa natural.",
  },
  {
    icon: <FaFish size={36} className="text-blue-500 group-hover:text-purple-600 transition-colors" />,
    title: "Lago con Peces",
    description: "Ideal para fotos y paseos familiares.",
  },
  {
    icon: <FaSun size={36} className="text-yellow-500 group-hover:text-purple-600 transition-colors" />,
    title: "Solarium",
    description: "Disfruta del sol en un espacio abierto y cómodo.",
  },
  {
    icon: <FaBiking size={36} className="text-lime-500 group-hover:text-purple-600 transition-colors" />,
    title: "Zona Deportiva",
    description: "Canchas, rutas para bicicletas y más diversión activa.",
  },
];

export const Attractions = () => {
  useEffect(() => {
    AOS.init({
      duration: 1500, // Duración global de la animación en milisegundos (ajusta para más suavidad)
      easing: 'ease-out-sine', // Tipo de easing para la animación (prueba diferentes valores)
      once: false, // Opcional: si quieres que la animación solo ocurra una vez
    });
  }, []);

  return (
    <section id="attractions" className="py-16 bg-bgLight dark:bg-bgDark text-center">
      <div className="max-w-6xl mx-auto px-4">
        <motion.h2
          initial={{ opacity: 0, y: -30 }}
          whileInView={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
          className="text-3xl font-bold text-primary dark:text-white mb-10"
        >
          Atracciones Destacadas
        </motion.h2>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-8 cursor-pointer">
          {attractions.map((item, index) => (
            <div
              key={index}
              data-aos={
                index % 3 === 0 ? "fade-down-left" : index % 3 === 1 ? "fade-up" : "fade-down-right"
              }
              data-aos-delay={index * 100}
            >
              <motion.div
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.5 }}
                className="h-full"
              >
                <div className="group bg-white dark:bg-neutral-800 hover:bg-secondary/20 dark:hover:bg-neutral-700 p-6 rounded-2xl shadow-md hover:shadow-xl transition h-full flex flex-col">
                  <div className="mb-4 flex justify-center">{item.icon}</div>
                  <h3 className="text-xl font-semibold text-[--color-primary] dark:text-white mb-2">{item.title}</h3>
                  <p className="text-textDark/75 dark:text-gray-300 mt-auto">{item.description}</p>
                </div>
              </motion.div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
};
```

## src\components\home\Benefits.tsx

```tsx
import { FaSwimmer, FaTree, FaUtensils, FaShieldAlt, FaTicketAlt } from "react-icons/fa";
import { motion } from "framer-motion";
import AOS from 'aos';
import 'aos/dist/aos.css';
import { useEffect } from 'react';

const benefits = [
  {
    icon: <FaSwimmer size={40} className="text-cyan-600 group-hover:text-purple-600 transition-colors" />,
    title: "Piscinas",
    description: "Diversión refrescante para toda la familia.",
  },
  {
    icon: <FaTree size={40} className="text-green-600 group-hover:text-purple-600 transition-colors" />,
    title: "Naturaleza",
    description: "Rodeado de un ambiente natural y relajante.",
  },
  {
    icon: <FaUtensils size={40} className="text-amber-600 group-hover:text-purple-600 transition-colors" />,
    title: "Gastronomía",
    description: "Sabores únicos en cada rincón.",
  },
  {
    icon: <FaShieldAlt size={40} className="text-red-600 group-hover:text-purple-600 transition-colors" />,
    title: "Seguridad",
    description: "Personal capacitado para tu tranquilidad.",
  },
  {
    icon: <FaTicketAlt size={40} className="text-blue-600 group-hover:text-purple-600 transition-colors" />,
    title: "Promociones",
    description: "Premios por cada 6 facturas registradas.",
  },
];

export const Benefits = () => {
  useEffect(() => {
    AOS.init({
      duration: 1500,
      easing: 'ease-out-quart',
      once: true,
    });
  }, []);

  const isOdd = benefits.length % 2 !== 0;
  const lastIndex = benefits.length - 1;

  return (
    <section className="py-16 bg-secondary/10 dark:bg-neutral-900 text-center" id="benefits">
      <div className="max-w-full mx-auto px-4">
        <motion.h2
          initial={{ opacity: 0, y: -30 }}
          whileInView={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
          className="text-3xl font-bold mb-6 text-primary dark:text-white"
        >
          ¿Por qué elegir Aqua River Park?
        </motion.h2>

        <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:flex lg:flex-row lg:justify-center lg:items-stretch lg:gap-6 sm:gap-8">
          {benefits.map((item, index) => (
            <div
              key={index}
              data-aos={
                index === 2 ? "fade-up" : (index % 2 === 0 ? "fade-down-left" : "fade-down-right")
              }
              data-aos-delay={index * 100}
              className={`${isOdd && index === lastIndex ? 'sm:col-span-2 sm:justify-self-center lg:w-1/5' : 'lg:w-1/5'}`}
            >
              <motion.div
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.5 }}
                className="h-full"
              >
                <div className="group bg-white dark:bg-neutral-800 shadow-md hover:bg-accent2/15 dark:hover:bg-bgDark cursor-pointer hover:shadow-xl rounded-2xl p-6 h-full flex flex-col transition duration-300">
                  <div className="mb-4 flex justify-center">{item.icon}</div>
                  <h3 className="text-xl font-semibold text-textDark dark:text-white mb-2">{item.title}</h3>
                  <p className="mt-auto text-gray-600 dark:text-gray-300">{item.description}</p>
                </div>
              </motion.div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
};
```

## src\components\home\Hero.tsx

```tsx
import { useEffect, useRef } from "react";
import { Parallax } from "react-scroll-parallax";
import { createTimeline } from "animejs";

export const Hero = () => {
  const titleRef = useRef<HTMLHeadingElement>(null);
  const subtitleRef = useRef<HTMLParagraphElement>(null);
  const buttonRef = useRef<HTMLAnchorElement>(null);

  useEffect(() => {
    if (!titleRef.current || !subtitleRef.current || !buttonRef.current) return;

    const tl = createTimeline();

    tl.add(titleRef.current, {
      opacity: [0, 1],
      translateY: [-50, 0],
      easing: "easeOutExpo",
      duration: 1000,
    })
      .add(
        subtitleRef.current,
        {
          opacity: [0, 1],
          translateY: [30, 0],
          easing: "easeOutExpo",
          duration: 800,
        },
        "-=500"
      )
      .add(
        buttonRef.current,
        {
          opacity: [0, 1],
          scale: [0.9, 1],
          easing: "easeOutBack",
          duration: 600,
        },
        "-=500"
      );
  }, []);

  return (
    <section
      id="hero"
      className="relative min-h-screen flex items-center justify-center text-center px-6 overflow-hidden"
    >
      {/* Fondo con parallax y overlay oscuro */}
      <div className="absolute inset-0 z-0 pointer-events-none">
        <Parallax speed={-100} className="h-full">
          <img
            src="/hero-bg.jpg"
            alt="Fondo Aqua River Park"
            className="w-full h-full object-cover"
          />
          <div className="absolute inset-0 z-10" />
        </Parallax>
      </div>

      {/* Contenido */}
      <div className="relative z-20 max-w-4xl text-textLight bg-bgDark/40 p-16 rounded-lg border-none shadow-md shadow-bgLight/30">
        <h1
          ref={titleRef}
          className="text-4xl md:text-6xl font-bold leading-tight mb-6 opacity-0 drop-shadow-md text-shadow-xs text-shadow-textLight"
        >
          Bienvenido a <span className="text-primary">Aqua River Park</span>
        </h1>
        <p
          ref={subtitleRef}
          className="text-lg md:text-xl mb-8 opacity-0 max-w-2xl mx-auto text-textLight text-shadow-xs text-shadow-textLight"
        >
          Diversión, naturaleza y experiencias inolvidables para toda la
          familia.
        </p>
        <a
          ref={buttonRef}
          href="#register"
          className="inline-block bg-accent2 text-white font-semibold px-8 py-3 rounded-full shadow-xl hover:bg-primary hover:text-white duration-300 opacity-0"
        >
          Registra tus facturas
        </a>
      </div>
    </section>
  );
};

```

## src\components\home\Location.tsx

```tsx
// components/Location.tsx
import { FaMapMarkerAlt, FaClock } from "react-icons/fa";
import { motion } from "framer-motion";

export const Location = () => {
  return (
    <section id="location" className="py-16 bg-bgLight dark:bg-bgDark text-gray-800 dark:text-white">
      <div className="max-w-6xl mx-auto px-4">
        <motion.h2
          initial={{ opacity: 0, y: -30 }}
          whileInView={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
          className="text-3xl font-bold text-center text-primary dark:text-white mb-10"
        >
          Horarios y Ubicación
        </motion.h2>

        <div className="grid md:grid-cols-2 gap-8">
          {/* Información */}
          <motion.div
            initial={{ opacity: 0, x: -30 }}
            whileInView={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.6 }}
            className="flex flex-col justify-center"
          >
            <div className="flex items-start gap-4 mb-6">
              <FaMapMarkerAlt size={28} className="text-secondary dark:text-accent1 mt-1" />
              <div>
                <h3 className="text-xl font-semibold text-textDark dark:text-white">Dirección</h3>
                <p className="text-gray-600 dark:text-gray-300">
                Guayllabamba - Rio Pisque, Quito, Ecuador.
                </p>
              </div>
            </div>

            <div className="flex items-start gap-4">
              <FaClock size={28} className="text-secondary dark:text-accent1 mt-1" />
              <div>
                <h3 className="text-xl font-semibold text-textDark dark:text-white">Horario</h3>
                <p className="text-gray-600 dark:text-gray-300">
                  Lunes a Viernes: 09:00 AM - 06:00 PM <br />
                  Fines de semana y feriados: 08:00 AM - 07:00 PM
                </p>
              </div>
            </div>
          </motion.div>

          {/* Mapa */}
          <motion.div
            initial={{ opacity: 0, x: 30 }}
            whileInView={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.6 }}
            className="rounded-lg overflow-hidden shadow-lg"
          >
            <iframe
              title="Ubicación Aqua River Park"
              src="https://www.google.com/maps/embed?pb=!1m18!1m12!1m3!1d3989.817645657002!2d-78.3380557255235!3d-0.03332053553907081!2m3!1f0!2f0!3f0!3m2!1i1024!2i768!4f13.1!3m3!1m2!1s0x91d58afedd97270f%3A0x2bf40c3d3b842bc8!2sAqua%20River%20Park!5e0!3m2!1ses!2sec!4v1745416434328!5m2!1ses!2sec"
              width="100%"
              height="300"
              style={{ border: 0 }}
              allowFullScreen
              loading="lazy"
              referrerPolicy="no-referrer-when-downgrade"
            />
          </motion.div>
        </div>
      </div>
    </section>
  );
};
```

## src\components\home\RegisterInvoice.tsx

```tsx
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
            initial={{ opacity: 0, y: -30 }}
            whileInView={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6 }}
            className="register-title text-2xl sm:text-3xl font-bold text-primary dark:text-white text-center"
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
            className="register-button w-full bg-accent2/80 hover:bg-primary text-white rounded-xl py-3 px-4 font-medium hover:shadow-lg transition-all duration-200"
          >
            Registrar Factura
          </motion.button>
        </div>
      </motion.form>
    </section>
  );
};

```

## src\components\NavMenu.tsx

```tsx
import { Link } from "react-router-dom";
import { AnimatePresence, motion } from "framer-motion";
import {
  ChevronDownIcon,
  PlusIcon,
  MinusIcon,
} from "@heroicons/react/20/solid";
import { useState, useRef, useEffect } from "react";

interface Props {
  isLoggedIn: boolean;
  userRole: string;
  mobileMenuOpen: boolean;
  handleLinkClick: () => void;
}

export const NavMenu: React.FC<Props> = ({
  isLoggedIn,
  userRole,
  mobileMenuOpen,
  handleLinkClick,
}) => {
  const [hoveredMenu, setHoveredMenu] = useState<string | null>(null);
  const menuRef = useRef<HTMLDivElement>(null);

  const menus = [
    { label: "Inicio", to: "/" },
    { label: "Precios", to: "/precios" },
  ];

  const dropdowns = {
    mas: ["Galeria", "Horarios", "Eventos", "Blog", "Reserva"],
    servicios: [
      "Piscinas y Tobogán",
      "Bosque Perdido de los Dinosaurios",
      "Botes y Juegos de Mesa",
      "Zona VIP",
      "Restaurantes",
    ],
  };

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (
        mobileMenuOpen &&
        menuRef.current &&
        !menuRef.current.contains(event.target as Node)
      ) {
        setHoveredMenu(null);
      }
    };

    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, [mobileMenuOpen]);

  return (
    <div
      ref={menuRef}
      className={`flex transition-all duration-300 ${
        mobileMenuOpen
          ? "flex-col items-center space-y-2 mt-4 text-center"
          : "flex-row items-center gap-6"
      } w-full md:w-auto justify-center`}
    >
      {/* Enlaces simples */}
      {menus.map((item, idx) => (
        <Link
          key={idx}
          to={item.to}
          onClick={handleLinkClick}
          className="hover:text-accent1 font-medium transition-colors duration-200"
        >
          {item.label}
        </Link>
      ))}

      {/* Menús desplegables */}
      {(Object.keys(dropdowns) as Array<keyof typeof dropdowns>).map((key) => (
        <div
          key={key}
          className={`relative group ${mobileMenuOpen ? "w-full" : "w-auto"}`}
          onMouseEnter={() => !mobileMenuOpen && setHoveredMenu(key)}
          onMouseLeave={() => !mobileMenuOpen && setHoveredMenu(null)}
        >
          <button
            onClick={() =>
              mobileMenuOpen
                ? setHoveredMenu((prev) => (prev === key ? null : key))
                : null
            }
            className="flex items-center justify-between gap-1 w-full font-medium capitalize hover:text-accent1 transition duration-200"
          >
            {key}
            {mobileMenuOpen ? (
              hoveredMenu === key ? (
                <MinusIcon className="h-5 w-5 transition-all duration-300 text-accent1" />
              ) : (
                <PlusIcon className="h-5 w-5 transition-all duration-300" />
              )
            ) : (
              <motion.div
                animate={{
                  rotate: hoveredMenu === key ? 180 : 0,
                }}
                style={{
                  color:
                    hoveredMenu === key
                      ? "var(--color-accent1)"
                      : "var(--color-textLight)",
                }}
                transition={{ duration: 0.3 }}
              >
                <ChevronDownIcon className="h-5 w-5 text-current transition-all duration-300" />
              </motion.div>
            )}
          </button>

          <AnimatePresence initial={false}>
            {hoveredMenu === key && (
              <motion.div
                key={key}
                initial={{ height: 0, opacity: 0 }}
                animate={{ height: "auto", opacity: 1 }}
                exit={{ height: 0, opacity: 0 }}
                transition={{ duration: 0.3, ease: "easeInOut" }}
                className={`overflow-hidden ${
                  mobileMenuOpen
                    ? "w-full mt-1"
                    : "absolute left-1/2 -translate-x-1/2 top-full mt-2 w-56"
                } backdrop-blur-md bg-bgLight/30 dark:bg-bgDark/40 text-textDark dark:text-textLight rounded-xl shadow-xl ring-1 ring-bgLight/25 z-50`}
              >
                {dropdowns[key].map((label, idx) => (
                  <Link
                    key={idx}
                    to={`/${key}#${label.toLowerCase().replace(/\s+/g, "-")}`}
                    onClick={handleLinkClick}
                    className="block px-4 py-2 text-sm font-semibold hover:bg-accent2/80 hover:text-textLight/90 dark:hover:bg-bgLight/80 dark:hover:text-textDark/90 transition-all duration-200"
                  >
                    {label}
                  </Link>
                ))}
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      ))}

      {/* Links para cliente logueado */}
      {isLoggedIn && userRole === "client" && (
        <>
          <Link
            to="/compras"
            onClick={handleLinkClick}
            className="hover:text-accent1 transition font-medium"
          >
            Mis Compras
          </Link>
          <Link
            to="/perfil"
            onClick={handleLinkClick}
            className="hover:text-accent1 transition font-medium"
          >
            Mi Perfil
          </Link>
        </>
      )}
    </div>
  );
};

```

## src\components\RouteModalHandler.tsx

```tsx
// src/components/RouteModalHandler.tsx
import { useEffect } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { useAuthModal } from "../store/useAuthModal";

const RouteModalHandler = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const { openModal, isOpen } = useAuthModal();

  // Abre el modal cuando entra a /login o /register
  useEffect(() => {
    if (location.pathname === "/login") {
      openModal("login");
    } else if (location.pathname === "/register") {
      openModal("register");
    }
  }, [location.pathname, openModal]);

  // Si se cierra el modal estando en /login o /register, redirige al home
  useEffect(() => {
    if (
      !isOpen &&
      (location.pathname === "/login" || location.pathname === "/register")
    ) {
      navigate("/");
    }
  }, [isOpen, location.pathname, navigate]);

  return null;
};

export default RouteModalHandler;

```

## src\components\ThemeToggle.tsx

```tsx
import { useTheme } from '../hooks/useTheme';
import { FaSun, FaMoon } from 'react-icons/fa';

export const ThemeToggle = () => {
  const { darkMode, toggleDarkMode } = useTheme();

  return (
    <button
      onClick={toggleDarkMode}
      className="p-2 rounded-lg bg-gray-200 dark:bg-gray-700 transition-colors"
      aria-label={darkMode ? 'Activar modo claro' : 'Activar modo oscuro'}
    >
      {darkMode ? <FaSun className="text-yellow-400" /> : <FaMoon className="text-gray-700" />}
    </button>
  );
};

```

## src\context\AuthContext.tsx

```tsx
// AuthContext.tsx
import { createContext } from 'react';
export const AuthContext = createContext(null);
```

## src\context\ThemeContext.tsx

```tsx
import { createContext } from 'react';

// Definir tipos
export interface ThemeContextType {
  darkMode: boolean;
  toggleDarkMode: () => void;
}

// Crear y exportar el contexto
export const ThemeContext = createContext<ThemeContextType>({
  darkMode: false,
  toggleDarkMode: () => {},
});

```

## src\context\ThemeProvider.tsx

```tsx
import { useState, useEffect, ReactNode } from 'react';
import { ThemeContext } from './ThemeContext';

interface ThemeProviderProps {
  children: ReactNode;
}

export function ThemeProvider({ children }: ThemeProviderProps) {
  const [darkMode, setDarkMode] = useState<boolean>(() => {
    const savedTheme = localStorage.getItem('theme');
    return savedTheme === 'dark';
  });

  useEffect(() => {
    document.documentElement.classList.toggle('dark', darkMode);
    localStorage.setItem('theme', darkMode ? 'dark' : 'light');
  }, [darkMode]);

  const toggleDarkMode = () => {
    setDarkMode(prev => !prev);
  };

  return (
    <ThemeContext.Provider value={{ darkMode, toggleDarkMode }}>
      {children}
    </ThemeContext.Provider>
  );
}

```

## src\hooks\useAuth.ts

```typescript
import { useEffect, useState } from "react";

export const useAuth = () => {
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [userRole, setUserRole] = useState<"admin" | "client">("client");

  useEffect(() => {
    const token = localStorage.getItem("token");
    setIsLoggedIn(!!token);

    // Puedes agregar lógica real aquí con JWT decode, etc.
    if (token) {
      const payload = JSON.parse(atob(token.split(".")[1]));
      setUserRole(payload.role || "client");
    }
  }, []);

  const logout = () => {
    localStorage.removeItem("token");
    window.location.href = "/login";
  };

  return { isLoggedIn, userRole, logout };
};

```

## src\hooks\useTheme.ts

```typescript
import { useContext } from 'react';
import { ThemeContext } from '../context/ThemeContext';

export const useTheme = () => {
  return useContext(ThemeContext);
};
```

## src\index.css

```css
@import "tailwindcss";

@layer theme, base, components, utilities;

/* Ignorar alertas de error, ya que es una versión reciente de TailwindCSS */
@custom-variant dark (&:where(.dark, .dark *));

@theme {
    --color-primary: #00b1e8;
    --color-secondary: #f26c1d;
    --color-hoverSecondary:#fc843d;
    --color-accent1: #ffda00;
    --color-accent2: #4c2882;
    --color-textDark: #333333;
    --color-textLight: #f5f5f5;
    --color-bgLight: #f5f5f5;
    --color-bgDark: #333333;
    --color-facebook: #1877f2;
    --color-instagram: #e1306c;
    --color-whatsapp: #25d366;
    --color-tiktok: #f5f5f5;
    --color-youtube: #ff0000;
}

.input-style {
    @apply mt-1 w-full px-4 py-2 border-2 border-gray-200 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent transition-all duration-300;
}
  
```

## src\layout\Container.tsx

```tsx
const Container = ({ children }: { children: React.ReactNode }) => {
    return <div className="max-w-7xl mx-auto px-4">{children}</div>;
  };
  
  export default Container;
  
```

## src\layout\DashboardLayout.tsx

```tsx
import Sidebar from "../layout/navigation/Sidebar";
import HeaderMobile from "../layout/navigation/HeaderMobile";
import { ReactNode, useState } from "react";
interface Props {
  children: ReactNode;
}

const DashboardLayout = ({ children }: Props) => {
  const [isSidebarOpen, setSidebarOpen] = useState(true);

  return (
    <div className="flex h-screen bg-bgLight dark:bg-bgDark transition-colors">
      <Sidebar isOpen={isSidebarOpen} />
      <div className="flex flex-col flex-1">
        <HeaderMobile onToggleSidebar={() => setSidebarOpen(!isSidebarOpen)} />
        <main className="flex-1 overflow-y-auto p-4">{children}</main>
      </div>
    </div>
  );
};

export default DashboardLayout;
```

## src\layout\navigation\Footer.tsx

```tsx
import {
  FaMapMarkerAlt,
  FaClock,
  FaFacebook,
  FaInstagram,
  FaWhatsapp,
  FaTiktok,
  FaYoutube,
} from "react-icons/fa";
import { Link } from "react-router-dom";

const Footer = () => {
  const socialLinks = [
    {
      icon: FaFacebook,
      color: "facebook",
      title: "Facebook",
      href: "https://www.facebook.com/aquariverpark",
    },
    {
      icon: FaInstagram,
      color: "instagram",
      title: "Instagram",
      href: "https://www.instagram.com/aquariverpark/#",
    },
    {
      icon: FaWhatsapp,
      color: "whatsapp",
      title: "Whatsapp",
      href: "https://wa.me/tunumerodewhatsapp",
    },
    {
      icon: FaTiktok,
      color: "tiktok",
      title: "TikTok",
      href: "https://www.tiktok.com/@aquariverpark1",
    },
    {
      icon: FaYoutube,
      color: "youtube",
      title: "YouTube",
      href: "https://www.youtube.com/aquariverpark",
    },
  ];

  return (
    <footer className="bg-accent2 text-textLight dark:bg-neutral-900 dark:text-gray-200 py-4 pt-8 transition-colors">
      <div className="container mx-auto px-4 grid grid-cols-1 md:grid-cols-4 gap-8 text-center md:text-left">
        {/* Logo + Descripción */}
        <div className="flex flex-col items-center justify-center md:items-start">
          <Link to="/" className="flex items-center gap-2">
            <img
              src="/ARP logo.png"
              alt="Logo de Aqua River Park"
              className="h-20 mb-4 drop-shadow-xl md:px-5"
            />
          </Link>
          <p className="text-sm opacity-90 max-w-xs md:px-8">
            Un parque acuático temático con diversión para toda la familia.
          </p>
        </div>

        {/* Enlaces rápidos */}
        <div>
          <h3 className="text-xl font-bold mb-4 text-accent1">Enlaces Rápidos</h3>
          <ul className="space-y-2">
            {[
              { href: "/", text: "Inicio" },
              { href: "#attractions", text: "Atracciones" },
              { href: "#horarios", text: "Horarios" },
              { href: "#promociones", text: "Promociones" },
            ].map((item, index) => (
              <li key={index}>
                <a
                  href={item.href}
                  className="hover:text-accent1 transition-colors"
                >
                  {item.text}
                </a>
              </li>
            ))}
          </ul>
        </div>

        {/* Información de contacto */}
        <div>
          <h3 className="text-xl font-bold mb-4 text-accent1">Contacto</h3>
          <ul className="space-y-2 text-sm">
            <li className="flex items-center justify-center md:justify-start">
              <FaMapMarkerAlt className="mr-2 text-secondary" />
              Guayllabamba - Rio Pisque, Quito, Ecuador.
            </li>
            <li className="flex items-center justify-center md:justify-start">
              <FaClock className="mr-2 text-secondary" />
              Lunes a Viernes: 09:00 AM - 06:00 PM
            </li>
            <li className="flex items-center justify-center md:justify-start">
              Fines de semana y feriados: 08:00 AM - 07:00 PM
            </li>
          </ul>
        </div>

        {/* Redes Sociales */}
        <div>
          <h3 className="text-xl font-bold mb-4 text-accent1">Redes Sociales</h3>
          <div className="flex justify-center md:justify-start space-x-4">
            {socialLinks.map(({ icon: Icon, color, title, href }, index) => (
              <a
                key={index}
                href={href}
                className="transition-all transform hover:scale-110"
                title={title}
                target="_blank"
                rel="noopener noreferrer"
                style={{
                  color: `var(--color-${color})`,
                  textShadow: `0 0 6px var(--color-${color})`,
                }}
              >
                <Icon size={24} />
              </a>
            ))}
          </div>
        </div>
      </div>

      {/* Pie de página */}
      <div className="mt-10 text-center text-xs text-white/70 dark:text-gray-400">
        © {new Date().getFullYear()} Aqua River Park. Todos los derechos reservados.
      </div>
    </footer>
  );
};

export default Footer;

```

## src\layout\navigation\Header.tsx

```tsx
import { Link, useLocation, useNavigate } from "react-router-dom";
import { FaUserCircle, FaBars, FaTimes } from "react-icons/fa";
import { Menu, MenuButton, MenuItem } from "@headlessui/react";
import { AnimatePresence, motion } from "framer-motion";
import { ThemeToggle } from "../../components/ThemeToggle";
import { useAuth } from "../../hooks/useAuth";
import { useEffect, useState, useRef } from "react";
import { NavMenu } from "../../components/NavMenu";
import { useAuthModal } from "../../store/useAuthModal"; // <-- store Zustand

const Header: React.FC = () => {
  const { isLoggedIn, logout, userRole } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);
  const { openModal } = useAuthModal(); // <-- usar Zustand

  const dropdownItems = {
    client: [
      { label: "Perfil", path: "/perfil" },
      { label: "Ajustes", path: "/ajustes" },
      { label: "Compras", path: "/compras" },
    ],
    admin: [
      { label: "Dashboard", path: "/admin" },
      { label: "Perfil", path: "/perfil" },
      { label: "Ajustes", path: "/ajustes" },
    ],
  };

  useEffect(() => {
    setMobileMenuOpen(false);
  }, [location]);

  useEffect(() => {
    if (isLoggedIn && userRole === "admin") {
      navigate("/admin/dashboard");
    }
  }, [isLoggedIn, userRole, navigate]);

  const handleLinkClick = () => setMobileMenuOpen(false);

  return (
    <header className="bg-primary dark:bg-bgDark text-white shadow-md sticky top-0 z-50 transition-colors duration-300 ease-in-out">
      <div className="max-w-[1400px] mx-auto px-4 md:px-8">
        <div className="flex items-center justify-between h-14 md:h-18">
          {/* Logo y Toggle */}
          <div className="flex items-center gap-3">
            <button
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              className="md:hidden text-2xl transition-transform hover:scale-110"
              aria-label="Abrir menú"
            >
              {mobileMenuOpen ? <FaTimes /> : <FaBars />}
            </button>

            <Link
              to="/"
              className="flex items-center gap-2 transition-transform hover:scale-105"
            >
              <img
                src="/ARP logo.png"
                alt="Logo"
                className="h-16 pb-2 w-auto drop-shadow"
              />
            </Link>
          </div>

          {/* Menú de navegación (desktop) */}
          <nav className="hidden md:flex items-center gap-6 justify-center">
            <NavMenu
              isLoggedIn={isLoggedIn}
              userRole={userRole}
              mobileMenuOpen={false}
              handleLinkClick={handleLinkClick}
            />
          </nav>

          {/* Iconos a la derecha */}
          <div className="flex items-center gap-4">
            <ThemeToggle />
            {isLoggedIn ? (
              <Menu as="div" className="relative">
                <MenuButton className="flex items-center transition-transform hover:scale-110">
                  <FaUserCircle className="text-3xl" />
                </MenuButton>
                <AnimatePresence>
                  <motion.div
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: 10 }}
                    transition={{ duration: 0.2 }}
                    className="absolute right-0 mt-2 w-48 bg-white dark:bg-bgDark rounded-md shadow-lg z-50 ring-1 ring-black/10 divide-y divide-gray-200 dark:divide-gray-700"
                  >
                    <div className="py-1">
                      {(dropdownItems[userRole] || []).map((item, idx) => (
                        <MenuItem key={idx}>
                          {({ active }) => (
                            <Link
                              to={item.path}
                              className={`block px-4 py-2 text-sm transition-all duration-200 ${
                                active
                                  ? "bg-gray-100 dark:bg-gray-700 text-primary"
                                  : "text-gray-700 dark:text-white"
                              }`}
                            >
                              {item.label}
                            </Link>
                          )}
                        </MenuItem>
                      ))}
                    </div>
                    <div className="py-1">
                      <MenuItem>
                        {({ active }) => (
                          <button
                            onClick={logout}
                            className={`block w-full text-left px-4 py-2 text-sm transition-all duration-200 ${
                              active
                                ? "bg-red-100 dark:bg-red-600 text-red-700"
                                : "text-red-500"
                            }`}
                          >
                            Cerrar sesión
                          </button>
                        )}
                      </MenuItem>
                    </div>
                  </motion.div>
                </AnimatePresence>
              </Menu>
            ) : (
              <>
                {/* Mobile icon */}
                <button
                  onClick={() => openModal("login")}
                  aria-label="Iniciar sesión"
                  className="md:hidden text-2xl hover:text-accent1 transition-transform"
                >
                  <FaUserCircle />
                </button>

                {/* Desktop button */}
                <button
                  onClick={() => openModal("login")}
                  className="hidden md:inline-block bg-secondary hover:bg-hoverSecondary px-4 py-2 rounded-md text-white transition-colors duration-300 text-sm"
                >
                  Iniciar sesión
                </button>
              </>
            )}
          </div>
        </div>
      </div>

      {/* Menú móvil deslizable */}
      <AnimatePresence>
        {mobileMenuOpen && (
          <motion.div
            ref={menuRef}
            initial={{ y: -20, opacity: 0 }}
            animate={{ y: 0, opacity: 1 }}
            exit={{ y: -20, opacity: 0 }}
            transition={{ duration: 0.3 }}
            className="md:hidden px-6 py-4 bg-primary dark:bg-bgDark space-y-3 shadow-md"
          >
            <NavMenu
              isLoggedIn={isLoggedIn}
              userRole={userRole}
              mobileMenuOpen={true}
              handleLinkClick={handleLinkClick}
            />
          </motion.div>
        )}
      </AnimatePresence>
    </header>
  );
};

export default Header;

```

## src\layout\navigation\HeaderMobile.tsx

```tsx
import { useEffect } from "react";
import { Link, useLocation } from "react-router-dom";
import { FaBars, FaSun, FaMoon, FaUserCircle } from "react-icons/fa";
import { Menu, MenuButton, MenuItem } from "@headlessui/react";
import { motion, AnimatePresence } from "framer-motion";
import { useAuth } from "../../hooks/useAuth";
import { useTheme } from "../../hooks/useTheme";

interface HeaderMobileProps {
  onToggleSidebar?: () => void;
}

const HeaderMobile: React.FC<HeaderMobileProps> = ({ onToggleSidebar }) => {
  const { darkMode, toggleDarkMode } = useTheme();
  const { isLoggedIn, logout, userRole } = useAuth();
  const location = useLocation();

  const dropdownItems: Record<string, { label: string; path: string }[]> = {
    client: [
      { label: "Perfil", path: "/perfil" },
      { label: "Ajustes", path: "/ajustes" },
    ],
    admin: [
      { label: "Dashboard", path: "/admin" },
      { label: "Perfil", path: "/perfil" },
    ],
  };

  useEffect(() => {
    // Podrías cerrar modales o limpiar algún estado aquí si lo deseas
  }, [location]);

  return (
    <header className="bg-primary dark:bg-bgDark text-textLight px-4 py-3 flex items-center justify-between shadow-md sticky top-0 z-50">
      {/* Sidebar toggle + Logo */}
      <div className="flex items-center gap-3">
        {onToggleSidebar && (
          <button onClick={onToggleSidebar} className="text-white text-xl">
            <FaBars />
          </button>
        )}
        <Link to="/" className="flex items-center gap-2">
          <img src="/ARP logo.png" alt="Logo" className="h-8" />
          <span className="font-semibold text-base">Aqua River Park</span>
        </Link>
      </div>

      {/* Dark mode + Auth */}
      <div className="flex items-center gap-4">
        <button
          onClick={toggleDarkMode}
          className="p-2 rounded-full bg-white/20 hover:bg-white/30 transition"
          title={darkMode ? "Modo claro" : "Modo oscuro"}
        >
          {darkMode ? <FaSun /> : <FaMoon />}
        </button>

        {isLoggedIn ? (
          <Menu as="div" className="relative">
            <MenuButton className="flex items-center">
              <FaUserCircle className="text-2xl" />
            </MenuButton>
            <AnimatePresence>
              <motion.div
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: 10 }}
                transition={{ duration: 0.2 }}
                className="absolute right-0 mt-2 w-44 bg-white dark:bg-bgDark rounded-md shadow-lg z-50 ring-1 ring-black/10"
              >
                <div className="py-1">
                  {(dropdownItems[userRole] || []).map(
                    (item, idx: number) => (
                      <MenuItem key={idx}>
                        {({ active }: { active: boolean }) => (
                          <Link
                            to={item.path}
                            className={`block px-4 py-2 text-sm ${
                              active
                                ? "bg-gray-100 dark:bg-gray-700 text-primary"
                                : "text-gray-800 dark:text-white"
                            }`}
                          >
                            {item.label}
                          </Link>
                        )}
                      </MenuItem>
                    )
                  )}
                </div>
                <div className="py-1">
                  <MenuItem>
                    {({ active }: { active: boolean }) => (
                      <button
                        onClick={logout}
                        className={`block w-full text-left px-4 py-2 text-sm ${
                          active
                            ? "bg-red-100 dark:bg-red-600 text-red-700"
                            : "text-red-500"
                        }`}
                      >
                        Cerrar sesión
                      </button>
                    )}
                  </MenuItem>
                </div>
              </motion.div>
            </AnimatePresence>
          </Menu>
        ) : (
          <Link
            to="/login"
            className="bg-secondary hover:bg-hoverSecondary px-3 py-1.5 rounded-md text-white text-sm transition"
          >
            Acceder
          </Link>
        )}
      </div>
    </header>
  );
};

export default HeaderMobile;

```

## src\layout\navigation\MiniFooter.tsx

```tsx
// src/components/navigation/MiniFooter.tsx

const MiniFooter = () => {
    return (
      <footer className="bg-accent2 text-white text-xs py-3 px-4 text-center shadow-md">
        <span className="block md:inline">
          © {new Date().getFullYear()} Aqua River Park
        </span>
        <span className="hidden md:inline mx-2">|</span>
        <span className="block md:inline text-white/80">
          Todos los derechos reservados
        </span>
      </footer>
    );
  };
  
  export default MiniFooter;
  
```

## src\layout\navigation\Sidebar.tsx

```tsx
// src/layout/navigation/Sidebar.tsx
import { Link, useLocation } from "react-router-dom";
import { FaHome, FaUser, FaCog } from "react-icons/fa";
import classNames from "classnames";

interface SidebarProps {
  isOpen: boolean;
}

const menuItems = [
  { label: "Inicio", path: "/", icon: <FaHome /> },
  { label: "Perfil", path: "/perfil", icon: <FaUser /> },
  { label: "Configuración", path: "/ajustes", icon: <FaCog /> },
];

const Sidebar = ({ isOpen }: SidebarProps) => {
  const location = useLocation();

  return (
    <aside
      className={classNames(
        "h-screen bg-accent2 text-white transition-all duration-300 flex flex-col",
        isOpen ? "w-64" : "w-16"
      )}
    >
      {/* Header */}
      <div className="flex items-center justify-center md:justify-between px-4 py-4 border-b border-white/10">
        {isOpen && <h1 className="text-lg font-bold">Aqua River</h1>}
      </div>

      {/* Menu */}
      <nav className="flex-1 overflow-y-auto mt-4 space-y-2">
        {menuItems.map((item, index) => (
          <Link
            to={item.path}
            key={index}
            className={classNames(
              "flex items-center gap-3 px-4 py-2 rounded-md mx-2 transition-colors",
              location.pathname === item.path
                ? "bg-accent1 text-textDark font-semibold"
                : "hover:bg-white/10"
            )}
          >
            <span className="text-lg">{item.icon}</span>
            {isOpen && <span className="text-sm">{item.label}</span>}
          </Link>
        ))}
      </nav>

      {/* Footer */}
      {isOpen && (
        <div className="px-4 py-4 text-xs text-gray-300 border-t border-white/10">
          © {new Date().getFullYear()} Aqua River Park
        </div>
      )}
    </aside>
  );
};

export default Sidebar;

```

## src\layout\PublicLayout.tsx

```tsx
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

```

## src\main.tsx

```tsx
// frontend/src/main.tsx
import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import "./index.css";
import { ThemeProvider } from "./context/ThemeProvider";
import { ParallaxProvider } from "react-scroll-parallax";

ReactDOM.createRoot(document.getElementById("root")!).render(
<ThemeProvider>
  <React.StrictMode>
  <ParallaxProvider>
    <App />
    </ParallaxProvider>
  </React.StrictMode>
    </ThemeProvider>
);

```

## src\pages\ConfirmAccount.tsx

```tsx

```

## src\pages\ConfirmationMail.tsx

```tsx
import { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import api from "../api/axios";
import { AxiosError } from "axios";
import { FaCheckCircle, FaTimesCircle, FaInfoCircle } from "react-icons/fa";
import { useAuthModal } from "../store/useAuthModal";
import { toast } from "react-toastify";

const ConfirmationMail = () => {
  const { token } = useParams();
  const navigate = useNavigate();
  const { openModal } = useAuthModal();

  const queryParams = new URLSearchParams(window.location.search);
  const emailFromQuery = queryParams.get("email");

  const [message, setMessage] = useState("Confirmando...");
  const [type, setType] = useState<"success" | "info" | "error">("info");
  const [showModal, setShowModal] = useState(false);
  const [email, setEmail] = useState(emailFromQuery || "");
  const [resendMsg, setResendMsg] = useState("");
  const [resendSuccess, setResendSuccess] = useState(false);
  const [isSending, setIsSending] = useState(false); // ✅ Bloqueo de clics

  useEffect(() => {
    const confirmAccount = async () => {
      try {
        const res = await api.get(`/confirm/${token}?email=${emailFromQuery}`);
        const { message } = res.data;

        setMessage(message);
        setType("success");

        if (
          message === "Cuenta confirmada exitosamente." ||
          message === "La cuenta ya ha sido confirmada."
        ) {
          toast.success(message);
          setTimeout(() => {
            navigate("/");
            openModal("login");
          }, 2500);
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
  }, [token, emailFromQuery, navigate, openModal]);

  const handleResend = async (e: React.FormEvent) => {
    e.preventDefault();
    if (isSending) return;

    setIsSending(true);
    setResendMsg("");

    try {
      const res = await api.post("/resend-confirmation", { email });
      toast.success("¡Correo reenviado correctamente!");
      setResendMsg(res.data.message);
      setResendSuccess(true);

      setTimeout(() => {
        setShowModal(false);
        setResendMsg("");
        setEmail("");
        setResendSuccess(false);
        navigate("/");
        openModal("login");
      }, 3000);
    } catch (err) {
      const error = err as AxiosError<{ message: string }>;
      const msg =
        error.response?.data?.message || "Error al reenviar el correo";
      setResendMsg(msg);
      toast.error(msg);
    } finally {
      setIsSending(false);
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
                    disabled={isSending}
                    className={`w-full bg-sky-600 text-white py-2 rounded-md hover:bg-sky-700 transition ${
                      isSending ? "opacity-50 cursor-not-allowed" : ""
                    }`}
                  >
                    {isSending ? "Enviando..." : "Reenviar enlace"}
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

```

## src\pages\Dashboard.tsx

```tsx
import { useEffect, useState } from "react";
import api from "../api/axios";
import { useNavigate } from "react-router-dom";

const Dashboard = () => {
  const [user, setUser] = useState<{ name: string; role: string } | null>(null);
  const [error, setError] = useState("");
  const navigate = useNavigate();

  useEffect(() => {
    const fetchData = async () => {
      try {
        const token = localStorage.getItem("token");
        if (!token) {
          navigate("/login");
          return;
        }

        const res = await api.get("/dashboard", {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        });

        setUser({ name: res.data.message.split(" ")[1], role: res.data.role });
      } catch (err: unknown) {
        if (err instanceof Error && (err as { response?: { status: number } }).response?.status === 403) {
          setError("No tienes permisos para acceder al dashboard.");
        } else {
          setError("Acceso no autorizado. Redirigiendo...");
          setTimeout(() => navigate("/login"), 2000);
        }
      }
    };

    fetchData();
  }, [navigate]);

  const handleLogout = () => {
    localStorage.removeItem("token");
    navigate("/login");
  };

  return (
    <div className="max-w-lg mx-auto mt-20">
      <h1 className="text-3xl font-bold mb-4">Dashboard</h1>
      {error && <p className="text-red-500">{error}</p>}
      {user && (
        <>
          <p className="text-lg mb-4">
            Bienvenido <strong>{user.name}</strong>. Tu rol es:{" "}
            <strong>{user.role}</strong>
          </p>
          <button
            onClick={handleLogout}
            className="bg-red-500 text-white px-4 py-2 rounded"
          >
            Cerrar sesión
          </button>
        </>
      )}
    </div>
  );
};

export default Dashboard;

```

## src\pages\Home.tsx

```tsx
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

```

## src\pages\Login.tsx

```tsx
// import { useEffect, useState } from "react";
// import api from "../api/axios";
// import { useNavigate } from "react-router-dom";
// import { FaEye, FaEyeSlash, FaCheckCircle, FaInfoCircle } from "react-icons/fa";
// import { toast } from "react-toastify";
// import { AxiosError } from "axios";

// const Login = () => {
//   const [email, setEmail] = useState("");
//   const [password, setPassword] = useState("");
//   const [error, setError] = useState("");
//   const [showPassword, setShowPassword] = useState(false);
//   const [showModal, setShowModal] = useState(false);
//   const [modalStep, setModalStep] = useState<"notice" | "form" | "success">(
//     "notice"
//   );
//   const [resendMsg, setResendMsg] = useState("");
//   const navigate = useNavigate();

//   useEffect(() => {
//     const confirmed = sessionStorage.getItem("confirmationSuccess");
//     if (confirmed) {
//       toast.success(
//         "¡Cuenta confirmada con éxito! Ahora puedes iniciar sesión."
//       );
//       sessionStorage.removeItem("confirmationSuccess");
//     }
//   }, []);

//   useEffect(() => {
//     const successMsg = sessionStorage.getItem("toastSuccess");
//     if (successMsg) {
//       toast.success(successMsg);
//       sessionStorage.removeItem("toastSuccess");
//     }
//   }, []);

//   const handleSubmit = async (e: React.FormEvent) => {
//     e.preventDefault();
//     setError("");

//     try {
//       const res = await api.post("/login", { email, password });
//       localStorage.setItem("token", res.data.token);
//       navigate("/dashboard");
//     } catch (err) {
//       const error = err as AxiosError<{
//         message: string;
//         tokenExpired?: boolean;
//       }>;
//       const msg = error.response?.data?.message;

//       if (msg === "Debes confirmar tu cuenta") {
//         const expired = error.response?.data?.tokenExpired;
//         setModalStep(expired ? "form" : "notice");
//         setShowModal(true);
//       } else {
//         setError("Credenciales incorrectas");
//       }
//     }
//   };

//   const handleResend = async (e: React.FormEvent) => {
//     e.preventDefault();
//     setResendMsg("");

//     try {
//       const res = await api.post("/resend-confirmation", { email });
//       setResendMsg(res.data.message);
//       setModalStep("success");

//       setTimeout(() => {
//         toast.success("¡Correo reenviado!, Revisa tu bandeja...");
//         setShowModal(false);
//         setResendMsg("");
//         setEmail("");
//         setPassword("");
//       }, 5000);
//     } catch (err) {
//       const error = err as AxiosError<{ message: string }>;
//       const msg = error.response?.data?.message;

//       if (msg === "La cuenta ya está confirmada") {
//         toast.info("La cuenta ya ha sido confirmada.");
//         setShowModal(false);
//       } else {
//         setResendMsg("Error al reenviar el enlace.");
//       }
//     }
//   };

//   return (
//     <>
//       <div className="max-w-sm mx-auto mt-8">
//         <h1 className="text-2xl font-bold mb-4">Iniciar sesión</h1>
//         <form onSubmit={handleSubmit} className="space-y-4">
//           <input
//             type="email"
//             placeholder="Correo"
//             className="w-full border p-2"
//             value={email}
//             onChange={(e) => setEmail(e.target.value)}
//             required
//           />
//           <div className="relative">
//             <input
//               type={showPassword ? "text" : "password"}
//               placeholder="Contraseña"
//               className="w-full border p-2 pr-10"
//               value={password}
//               onChange={(e) => setPassword(e.target.value)}
//               required
//             />
//             <button
//               type="button"
//               onClick={() => setShowPassword(!showPassword)}
//               className="absolute top-1/2 right-3 transform -translate-y-1/2 text-gray-500"
//             >
//               {showPassword ? <FaEyeSlash /> : <FaEye />}
//             </button>
//           </div>
//           <button
//             type="submit"
//             className="w-full bg-blue-500 text-white p-2 rounded"
//           >
//             Entrar
//           </button>
//           {error && <p className="text-red-500 text-sm">{error}</p>}
//           <p className="text-sm mt-2">
//             ¿No tienes una cuenta?{" "}
//             <a href="/register" className="text-blue-500 underline">
//               Regístrate aquí
//             </a>
//           </p>
//         </form>
//       </div>

//       {showModal && (
//         <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50">
//           <div className="bg-white rounded-lg shadow-lg p-6 w-full max-w-md relative text-center">
//             <button
//               onClick={() => setShowModal(false)}
//               className="absolute top-2 right-3 text-gray-500 hover:text-red-500 text-lg font-bold"
//             >
//               &times;
//             </button>

//             {modalStep === "notice" && (
//               <>
//                 <FaInfoCircle className="text-yellow-500 text-4xl mx-auto mb-2" />
//                 <h2 className="text-xl font-bold mb-2 text-sky-600">
//                   Verifica tu cuenta
//                 </h2>
//                 <p className="text-sm text-gray-600 mb-4">
//                   Aún no has confirmado tu cuenta. Revisa tu correo para
//                   activarla.
//                 </p>
//               </>
//             )}

//             {modalStep === "form" && (
//               <>
//                 <h2 className="text-xl font-bold mb-2 text-sky-600">
//                   Reenviar Enlace
//                 </h2>
//                 <form onSubmit={handleResend} className="space-y-4">
//                   <input
//                     type="email"
//                     placeholder="Tu correo"
//                     className="w-full px-4 py-2 border rounded-md"
//                     value={email}
//                     onChange={(e) => setEmail(e.target.value)}
//                     required
//                   />
//                   <button
//                     type="submit"
//                     className="w-full bg-sky-600 text-white py-2 rounded-md hover:bg-sky-700"
//                   >
//                     Reenviar
//                   </button>
//                   {resendMsg && (
//                     <p className="text-sm text-red-500">{resendMsg}</p>
//                   )}
//                 </form>
//               </>
//             )}

//             {modalStep === "success" && (
//               <>
//                 <FaCheckCircle className="text-green-500 text-4xl mx-auto mb-2" />
//                 <p className="text-green-600 text-sm font-medium">
//                   {resendMsg}
//                 </p>
//                 <p className="text-sm text-gray-500 mt-2">
//                   Serás redirigido al login...
//                 </p>
//               </>
//             )}
//           </div>
//         </div>
//       )}
//     </>
//   );
// };

// export default Login;

```

## src\pages\NotFound.tsx

```tsx
import { Link } from "react-router-dom";
import { motion } from "framer-motion";
import { useCallback, useEffect, useState } from "react";
import Particles from "react-tsparticles";
import { loadSlim } from "tsparticles-slim"; // ✅ MÁS LIVIANO Y FUNCIONAL
import type { Engine } from "tsparticles-engine";

const NotFound = () => {
  const [isDark, setIsDark] = useState(false);

  useEffect(() => {
    const match = window.matchMedia("(prefers-color-scheme: dark)");
    setIsDark(match.matches);
    const listener = (e: MediaQueryListEvent) => setIsDark(e.matches);
    match.addEventListener("change", listener);
    return () => match.removeEventListener("change", listener);
  }, []);

  const particlesInit = useCallback(async (engine: Engine) => {
    await loadSlim(engine); // ✅ Ya no usamos loadFull
  }, []);

  return (
    <div className="relative h-screen w-full flex items-center justify-center px-4 bg-white dark:bg-gray-900 text-gray-800 dark:text-white overflow-hidden">
      <Particles
        id="tsparticles"
        init={particlesInit}
        className="absolute inset-0 z-0"
        options={{
          fullScreen: false,
          background: { color: { value: "transparent" } },
          particles: {
            number: { value: 60 },
            color: { value: isDark ? "#ffffff" : "#0ea5e9" },
            shape: { type: "circle" },
            opacity: { value: 0.4 },
            size: { value: 3 },
            move: {
              enable: true,
              speed: 1.5,
              direction: "none",
              outModes: "out",
            },
          },
        }}
      />

      <div className="z-10 text-center mt-2">
        <motion.h1
          className="text-[8rem] sm:text-[10rem] font-black tracking-tight leading-none"
          initial={{ scale: 0 }}
          animate={{ scale: 1 }}
          transition={{ duration: 0.6 }}
        >
          404
        </motion.h1>

        <motion.h2
          className="text-3xl sm:text-4xl font-semibold mt-2"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
        >
          ¡Ups! Página no encontrada 😢
        </motion.h2>

        <motion.p
          className="mt-4 max-w-md mx-auto text-gray-600 dark:text-gray-300 text-base sm:text-lg"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.5 }}
        >
          Tal vez escribiste mal la dirección o esta página ya no existe.
        </motion.p>

        <motion.div
          className="mt-6 flex gap-4 justify-center flex-col sm:flex-row"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.8 }}
        >
          <Link
            to="/"
            className="px-6 py-3 bg-gradient-to-r from-blue-600 to-purple-600 text-white font-semibold rounded-md hover:scale-105 transition-transform"
          >
            Ir al inicio
          </Link>
          <Link
            to="/dashboard"
            className="px-6 py-3 border border-gray-400 text-gray-700 dark:text-gray-200 dark:border-gray-500 rounded-md hover:bg-gray-200 dark:hover:bg-gray-700 transition-all"
          >
            Ir al panel
          </Link>
        </motion.div>

        <motion.div
          className="mt-4"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 1.2 }}
        >
          <img
            src="https://illustrations.popsy.co/violet/crashed-error.svg"
            alt="Ilustración de error"
            className="w-64 sm:w-96 mx-auto fill-indigo-500 drop-shadow-2xl drop-shadow-indigo-500/50"
          />
        </motion.div>
      </div>
    </div>
  );
};

export default NotFound;

```

## src\pages\Register.tsx

```tsx
// import { useState } from "react";
// import api from "../api/axios";
// import { useNavigate } from "react-router-dom";

// const Register = () => {
//   const [name, setName] = useState("");
//   const [email, setEmail] = useState("");
//   const [password, setPassword] = useState("");
//   const [phone, setPhone] = useState("");
//   const [error, setError] = useState("");
//   const navigate = useNavigate();

//   const handleSubmit = async (e: React.FormEvent) => {
//     e.preventDefault();
//     try {
//       await api.post("/register", { name, email, password, phone });
//       alert("Registro exitoso. Revisa tu correo para confirmar tu cuenta.");
//       navigate("/login");
//     } catch (err) {
//       console.error(err);
//       setError("Error al registrarse. Puede que el correo ya exista.");
//     }
//   };

//   return (
//     <div className="max-w-sm mx-auto mt-8">
//       <h1 className="text-2xl font-bold mb-4">Registro</h1>
//       <form onSubmit={handleSubmit} className="space-y-4">
//         <input
//           type="text"
//           placeholder="Nombre"
//           className="w-full border p-2"
//           value={name}
//           onChange={(e) => setName(e.target.value)}
//         />
//         <input
//           type="email"
//           placeholder="Correo"
//           className="w-full border p-2"
//           value={email}
//           onChange={(e) => setEmail(e.target.value)}
//         />
//         <input
//           type="tel"
//           placeholder="Teléfono"
//           className="w-full border p-2"
//           value={phone}
//           onChange={(e) => setPhone(e.target.value)}
//         />
//         <input
//           type="password"
//           placeholder="Contraseña"
//           className="w-full border p-2"
//           value={password}
//           onChange={(e) => setPassword(e.target.value)}
//         />
//         <button
//           type="submit"
//           className="w-full bg-green-600 text-white p-2 rounded"
//         >
//           Registrarse
//         </button>
//         {error && <p className="text-red-500 text-sm">{error}</p>}
//         <p className="text-sm mt-2">
//           ¿Ya tienes una cuenta?{" "}
//           <a href="/login" className="text-blue-500 underline">
//             Inicia sesión aquí
//           </a>
//         </p>
//       </form>
//     </div>
//   );
// };

// export default Register;

```

## src\pages\ResetPassword.tsx

```tsx
import { useEffect, useState } from "react";
import { useSearchParams, useNavigate } from "react-router-dom";
import { toast } from "react-toastify";
import api from "../api/axios";
import { useAuthModal } from "../store/useAuthModal";
import {
  validatePasswordSecurity,
} from "../utils/validationHelpersForm";
import PasswordWithStrengthInput from "../components/common/PasswordWithStrengthInputForm";
import InputWithLabel from "../components/common/InputWithLabel";

export default function ResetPassword() {
  const [searchParams] = useSearchParams();
  const token = searchParams.get("token") || "";
  const email = searchParams.get("email") || "";
  const navigate = useNavigate();
  const { openModal } = useAuthModal();

  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [passwordError, setPasswordError] = useState("");
  const [confirmPasswordError, setConfirmPasswordError] = useState("");
  const [loading, setLoading] = useState(true);
  const [valid, setValid] = useState(false);
  const [error, setError] = useState("");
  const [resend, setResend] = useState(false);
  const [isSending, setIsSending] = useState(false);

  useEffect(() => {
    const validateToken = async () => {
      try {
        const res = await api.post("/check-token-status", { token });
        setValid(res.data.valid);
        if (!res.data.valid) setError("El enlace ha expirado o es inválido.");
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

  const handlePasswordChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const newPassword = e.target.value;
    setPassword(newPassword);

    const errors = validatePasswordSecurity(newPassword, email);
    setPasswordError(errors.length > 0 ? errors.join(" ") : "");

    if (confirmPassword && confirmPassword !== newPassword) {
      setConfirmPasswordError("Las contraseñas no coinciden.");
    } else {
      setConfirmPasswordError("");
    }
  };

  const handleConfirmPasswordChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const newConfirm = e.target.value;
    setConfirmPassword(newConfirm);
    if (password !== newConfirm) {
      setConfirmPasswordError("Las contraseñas no coinciden.");
    } else {
      setConfirmPasswordError("");
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (isSending) return;
    setIsSending(true);

    const passwordErrors = validatePasswordSecurity(password, email);
    if (passwordErrors.length > 0) {
      toast.warning(passwordErrors.join(" "));
      setIsSending(false);
      return;
    }

    if (password !== confirmPassword) {
      toast.error("Las contraseñas no coinciden");
      setIsSending(false);
      return;
    }

    try {
      await api.post(`/reset-password/${token}`, { password });
      toast.success("Contraseña actualizada correctamente");

      setTimeout(() => {
        navigate("/");
        openModal("login");
      }, 2000);
    } catch {
      toast.error("Error al actualizar la contraseña");
    } finally {
      setIsSending(false);
    }
  };

  const handleResend = async () => {
    if (isSending) return;
    setIsSending(true);

    try {
      await api.post("/send-recovery", { email });
      toast.success("Se envió un nuevo enlace de recuperación");
      setResend(true);
    } catch {
      toast.error("No se pudo reenviar el correo");
    } finally {
      setIsSending(false);
    }
  };

  if (loading) return <p className="text-center mt-8 dark:text-white">Cargando...</p>;

  if (!valid) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-100 dark:bg-bgDark px-4">
        <div className="bg-white dark:bg-bgLight/10 shadow-md rounded-lg p-6 w-full max-w-md text-center">
          <h2 className="text-xl font-semibold text-red-600 dark:text-red-400 mb-4">{error}</h2>
          {!resend && email ? (
            <>
              <p className="text-sm text-gray-600 dark:text-gray-300 mb-4">
                Puedes reenviar el enlace a: <strong>{email}</strong>
              </p>
              <button
                onClick={handleResend}
                disabled={isSending}
                className={`bg-sky-600 text-white px-4 py-2 rounded hover:bg-sky-700 transition ${
                  isSending ? "opacity-50 cursor-not-allowed" : ""
                }`}
              >
                {isSending ? "Enviando..." : "Reenviar enlace"}
              </button>
            </>
          ) : resend ? (
            <p className="text-green-600 dark:text-green-400">
              Enlace reenviado. Revisa tu correo.
            </p>
          ) : (
            <p className="text-sm text-gray-500 dark:text-gray-300">
              Solicita un nuevo enlace desde "Olvidé mi contraseña".
            </p>
          )}
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-100 dark:bg-bgDark px-4">
      <form
        onSubmit={handleSubmit}
        className="bg-white dark:bg-bgLight/10 shadow-md rounded-lg p-6 w-full max-w-md"
      >
        <h2 className="text-2xl font-bold mb-4 text-center text-sky-600 dark:text-textLight">
          Nueva Contraseña
        </h2>
        <p className="text-sm text-gray-600 dark:text-gray-300 mb-4 text-center">
          Ingresa una nueva contraseña para tu cuenta.
        </p>

        <PasswordWithStrengthInput
          value={password}
          onChange={handlePasswordChange}
          error={passwordError}
          showTooltip={true}
          showStrengthBar={true}
        />

        <InputWithLabel
          label="Confirmar contraseña"
          name="confirmPassword"
          type="password"
          value={confirmPassword}
          onChange={handleConfirmPasswordChange}
          placeholder="Confirma tu contraseña"
          error={confirmPasswordError}
        />

        <button
          type="submit"
          disabled={isSending || passwordError !== "" || confirmPasswordError !== ""}
          className={`w-full bg-sky-600 text-white py-2 rounded hover:bg-sky-700 transition ${
            isSending ? "opacity-50 cursor-not-allowed" : ""
          }`}
        >
          {isSending ? "Actualizando..." : "Actualizar contraseña"}
        </button>
      </form>
    </div>
  );
}

```

## src\router\AppRouter.tsx

```tsx
// src/router/AppRouter.tsx
import { Routes, Route } from "react-router-dom";
import Home from "../pages/Home";
import Dashboard from "../pages/Dashboard";
import ConfirmationMail from "../pages/ConfirmationMail";
import ResetPassword from "../pages/ResetPassword";
import NotFound from "../pages/NotFound";
import PublicLayout from "../layout/PublicLayout";
import DashboardLayout from "../layout/DashboardLayout";
import PrivateRoute from "../utils/PrivateRoute";

const AppRouter = () => (
  <Routes>
    <Route
      path="/"
      element={
        <PublicLayout>
          <Home />
        </PublicLayout>
      }
    />
    <Route
      path="/login"
      element={
        <PublicLayout>
          <Home />
        </PublicLayout>
      }
    />
    <Route
      path="/register"
      element={
        <PublicLayout>
          <Home />
        </PublicLayout>
      }
    />
    <Route
      path="/confirm/:token"
      element={
        <PublicLayout>
          <ConfirmationMail />
        </PublicLayout>
      }
    />
    <Route
      path="/reset-password"
      element={
        <PublicLayout>
          <ResetPassword />
        </PublicLayout>
      }
    />

    <Route
      path="/dashboard"
      element={
        <PrivateRoute>
          <DashboardLayout>
            <Dashboard />
          </DashboardLayout>
        </PrivateRoute>
      }
    />

    <Route path="*" element={<NotFound />} />
  </Routes>
);

export default AppRouter;

```

## src\store\useAuthModal.ts

```typescript
import { create } from "zustand";

interface AuthModalState {
  isOpen: boolean;
  view: "login" | "register";
  openModal: (view?: "login" | "register") => void;
  closeModal: () => void;
  toggleView: () => void;
}

export const useAuthModal = create<AuthModalState>((set) => ({
  isOpen: false,
  view: "login",
  openModal: (view = "login") => set({ isOpen: true, view }),
  closeModal: () => set({ isOpen: false }),
  toggleView: () =>
    set((state) => ({
      view: state.view === "login" ? "register" : "login",
    })),
}));

```

## src\types\simple-parallax-js.d.ts

```typescript
declare module "simple-parallax-js" {
  interface SimpleParallaxOptions {
    scale?: number;
    delay?: number;
    transition?: string;
    orientation?: "up" | "down" | "left" | "right";
  }

  export default function simpleParallax(
    el: Element | Element[] | NodeListOf<Element>,
    options?: SimpleParallaxOptions
  ): void;
}

```

## src\utils\PrivateRoute.tsx

```tsx
import { Navigate } from 'react-router-dom';

import { ReactNode } from 'react';

const PrivateRoute = ({ children }: { children: ReactNode }) => {
  const token = localStorage.getItem('token');
  return token ? children : <Navigate to="/login" replace />;
};

export default PrivateRoute;
```

## src\utils\validationHelpersForm.ts

```typescript
// Capitaliza cada palabra
export const capitalizeName = (name: string) => {
    return name
        .toLowerCase()
        .split(" ")
        .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
        .join(" ");
};


// Devuelve el puntaje de seguridad de la contraseña
export const getPasswordScore = (password: string) => {
    let score = 0;
    if (password.length >= 8) score++;
    if (/[A-Z]/.test(password)) score++;
    if (/[0-9]/.test(password)) score++;
    if (/[^A-Za-z0-9]/.test(password)) score++;
    return score;
};


// Valida el formato de la dirección de correo electrónico
export const validateEmailFormat = (email: string): boolean => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
};

// Valida la seguridad de la contraseña
export const validatePasswordSecurity = (password: string, email: string): string[] => {
    const errors: string[] = [];

    if (password.length < 8) {
        errors.push("Debe tener al menos 8 caracteres.");
    }
    if (!/[A-Z]/.test(password)) {
        errors.push("Debe incluir al menos una letra mayúscula.");
    }
    if (!/[a-z]/.test(password)) {
        errors.push("Debe incluir al menos una letra minúscula.");
    }
    if (!/[0-9]/.test(password)) {
        errors.push("Debe incluir al menos un número.");
    }
    if (!/[^A-Za-z0-9]/.test(password)) {
        errors.push("Debe incluir al menos un símbolo.");
    }
    if (password.toLowerCase() === email.toLowerCase()) {
        errors.push("La contraseña no puede ser igual al correo electrónico.");
    }

    return errors;
};

// Devuelve el texto, color y clase CSS según el puntaje de la contraseña
export const getStrengthLabel = (score: number) => {
    switch (score) {
      case 0:
      case 1:
        return {
          text: "Débil",
          color: "text-red-500 dark:text-red-400",
          bar: "bg-red-500 dark:bg-red-400",
        };
      case 2:
        return {
          text: "Media",
          color: "text-yellow-500 dark:text-yellow-400",
          bar: "bg-yellow-400 dark:bg-yellow-300",
        };
      case 3:
        return {
          text: "Fuerte",
          color: "text-blue-500 dark:text-blue-400",
          bar: "bg-blue-500 dark:bg-blue-400",
        };
      case 4:
        return {
          text: "Muy fuerte",
          color: "text-green-600 dark:text-green-400",
          bar: "bg-green-500 dark:bg-green-400",
        };
      default:
        return {
          text: "",
          color: "",
          bar: "bg-gray-200 dark:bg-gray-600",
        };
    }
  };
  


```

## src\vite-env.d.ts

```typescript
/// <reference types="vite/client" />

```

## tsconfig.app.json

```json
{
  "compilerOptions": {
    "tsBuildInfoFile": "./node_modules/.tmp/tsconfig.app.tsbuildinfo",
    "target": "ES2020",
    "useDefineForClassFields": true,
    "lib": ["ES2020", "DOM", "DOM.Iterable"],
    "module": "ESNext",
    "skipLibCheck": true,
    "baseUrl": "./src",
    "paths": {
      "@/*": ["*"]
    },

    /* Bundler mode */
    "moduleResolution": "bundler",
    "allowImportingTsExtensions": true,
    "isolatedModules": true,
    "moduleDetection": "force",
    "noEmit": true,
    "jsx": "react-jsx",

    /* Linting */
    "strict": true,
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "noFallthroughCasesInSwitch": true,
    "noUncheckedSideEffectImports": true
  },
  "include": ["src", "../backend/src/utils/sanitize.ts"]
}

```

## tsconfig.node.json

```json
{
  "compilerOptions": {
    "tsBuildInfoFile": "./node_modules/.tmp/tsconfig.node.tsbuildinfo",
    "target": "ES2022",
    "lib": ["ES2023"],
    "module": "ESNext",
    "skipLibCheck": true,

    /* Bundler mode */
    "moduleResolution": "bundler",
    "allowImportingTsExtensions": true,
    "isolatedModules": true,
    "moduleDetection": "force",
    "noEmit": true,

    /* Linting */
    "strict": true,
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "noFallthroughCasesInSwitch": true,
    "noUncheckedSideEffectImports": true
  },
  "include": ["vite.config.ts"]
}

```

## vite.config.ts

```typescript
// import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { defineConfig } from "vitest/config";

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      "@": "/src",
    },
  },
  test: {
    globals: true,
    environment: "node",
  },
});

```


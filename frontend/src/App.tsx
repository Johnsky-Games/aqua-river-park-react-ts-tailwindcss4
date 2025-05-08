// src/App.tsx
import React from "react";
import { BrowserRouter as Router } from "react-router-dom";
import AppRouter from "./router/AppRouter";
import { ToastContainer } from "react-toastify";
import { useAuthModal } from "./store/useAuthModal";
import AuthModal from "./components/auth/AuthModal";
import RouteModalHandler from "./components/RouteModalHandler";
import { LoginRedirectHandler } from "./components/LoginRedirectHandler";
import { AutoTokenManager } from "./components/AutoTokenManager";
import { UserInitializer } from "./components/UserInitializer";
import { GlobalLoadingOverlay } from "./components/GlobalLoadingOverlay";
import { GoogleReCaptchaProvider } from "react-google-recaptcha-v3";
import "react-toastify/dist/ReactToastify.css";

const App: React.FC = () => {
  const isOpen = useAuthModal((state) => state.isOpen);

  return (
    <Router>
      {/* Inicializadores y handlers globales */}
      <UserInitializer />
      <AutoTokenManager />
      <LoginRedirectHandler />
      <GlobalLoadingOverlay />
      <RouteModalHandler />

      {/* Rutas */}
      <AppRouter />

      {/* Modal de Auth — solo aquí cargamos reCAPTCHA */}
      {isOpen ? (
        <GoogleReCaptchaProvider
          reCaptchaKey={import.meta.env.VITE_RECAPTCHA_SITE_KEY}
          useRecaptchaNet
        >
          <AuthModal />
        </GoogleReCaptchaProvider>
      ) : null}

      {/* Toasts */}
      <ToastContainer position="top-right" autoClose={3000} />
    </Router>
  );
};

export default App;

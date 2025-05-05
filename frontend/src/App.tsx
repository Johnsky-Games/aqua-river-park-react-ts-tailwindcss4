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
import "react-toastify/dist/ReactToastify.css";

const App: React.FC = () => {
  const isOpen = useAuthModal((state) => state.isOpen);

  return (
    <Router>
      {/* Primero tratamos de hidratar el user existente via /me */}
      <UserInitializer />

      {/* Luego arrancamos el refresco automático de token por cookie */}
      <AutoTokenManager />

      {/* Manejadores globales */}
      <LoginRedirectHandler />
      <GlobalLoadingOverlay />
      <RouteModalHandler />

      {/* Rutas */}
      <AppRouter />

      {/* Modal de Auth */}
      {isOpen && <AuthModal />}

      {/* Toasts */}
      <ToastContainer position="top-right" autoClose={3000} />
    </Router>
  );
};

export default App;

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

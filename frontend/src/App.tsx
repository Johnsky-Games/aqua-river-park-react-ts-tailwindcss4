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

// src/App.tsx
import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import Home from "./pages/Home";
import Login from "./pages/Login";
import Register from "./pages/Register";
import ConfirmationMail from "./pages/ConfirmationMail";
import Dashboard from "./pages/Dashboard";
import PublicLayout from "./layout/PublicLayout";
import DashboardLayout from "./layout/DashboardLayout";
import PrivateRoute from "./utils/PrivateRoute";
import { ToastContainer } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";
import AuthModal from "./components/auth/authModal";
import { useAuthModal } from "./store/useAuthModal";
import 'react-toastify/dist/ReactToastify.css';


function App() {
  const { isOpen } = useAuthModal();

  return (
    <Router>
      <Routes>
        <Route path="/" element={<PublicLayout><Home /></PublicLayout>} />
        <Route path="/login" element={<PublicLayout><Login /></PublicLayout>} />
        <Route path="/register" element={<PublicLayout><Register /></PublicLayout>} />
        <Route path="/confirm/:token" element={<PublicLayout><ConfirmationMail /></PublicLayout>} />
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
      </Routes>

      <ToastContainer position="top-right" autoClose={3000} />

      {/* Modal global */}
      {isOpen && <AuthModal/>}
    </Router>
  );
}

export default App;

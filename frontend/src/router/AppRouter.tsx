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
      path="admin/dashboard"
      element={
        <PrivateRoute allowedRoles={["admin"]}>
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

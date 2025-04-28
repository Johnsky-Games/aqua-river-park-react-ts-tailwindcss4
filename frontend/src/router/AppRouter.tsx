// src/router/AppRouter.tsx
import { Routes, Route } from "react-router-dom";
import PublicLayout from "@/layout/PublicLayout";
import DashboardLayout from "@/layout/DashboardLayout";
import Home from "@/pages/Home";
import ConfirmationMail from "@/pages/ConfirmationMail";
import ResetPassword from "@/pages/ResetPassword";
import Dashboard from "@/pages/Dashboard";
import NotFound from "@/pages/NotFound";
import PrivateRoute from "@/utils/PrivateRoute";

const AppRouter: React.FC = () => {
  return (
    <Routes>
      {/*
        RUTAS PÚBLICAS
        Se agrupan todas bajo PublicLayout para no repetirlo en cada ruta.
      */}
      <Route element={<PublicLayout />}>
        <Route path="/" element={<Home />} />
        <Route path="/login" element={<Home />} />
        <Route path="/register" element={<Home />} />
        <Route path="/confirm/:token" element={<ConfirmationMail />} />
        <Route path="/reset-password" element={<ResetPassword />} />
      </Route>

      {/*
        RUTA PROTEGIDA
        Sólo usuarios con rol "admin" pueden acceder.
      */}
      <Route
        path="/admin/dashboard"
        element={
          <PrivateRoute allowedRoles={["admin"]}>
            <DashboardLayout>
              <Dashboard />
            </DashboardLayout>
          </PrivateRoute>
        }
      />

      {/*
        Cualquiera otra ruta → 404
      */}
      <Route path="*" element={<NotFound />} />
    </Routes>
  );
};

export default AppRouter;

import React from "react";
import { Routes, Route, Navigate } from "react-router-dom";
import PublicLayout from "@/layout/PublicLayout";
import DashboardLayout from "@/layout/DashboardLayout";
import Home from "@/pages/Home";
import ConfirmationMail from "@/pages/ConfirmationMail";
import ResetPassword from "@/pages/ResetPassword";
import DashboardView from "@/pages/admin/DashboardView";
import InvoicesView from "@/pages/admin/InvoicesView";
import EntriesView from "@/pages/admin/EntriesView";
import UsersView from "@/pages/admin/UsersView";
import SettingsView from "@/pages/admin/SettingsView";
import NotFound from "@/pages/NotFound";
import PrivateRoute from "@/router/PrivateRoute";

const AppRouter: React.FC = () => (
  <Routes>
    <Route element={<PublicLayout />}>
      <Route path="/" element={<Home />} />
      <Route path="/login" element={<Home />} />
      <Route path="/register" element={<Home />} />
      <Route path="/confirm/:token" element={<ConfirmationMail />} />
      <Route path="/reset-password" element={<ResetPassword />} />
    </Route>

    <Route
      path="/admin/*"
      element={
        <PrivateRoute allowedRoles={["admin"]}>
          <DashboardLayout />
        </PrivateRoute>
      }
    >
      <Route index element={<Navigate to="dashboard" replace />} />
      <Route path="dashboard" element={<DashboardView />} />
      <Route path="invoices" element={<InvoicesView />} />
      <Route path="entries" element={<EntriesView />} />
      <Route path="users" element={<UsersView />} />
      <Route path="settings" element={<SettingsView />} />
    </Route>

    <Route path="*" element={<NotFound />} />
  </Routes>
);

export default AppRouter;

// src/pages/admin/AdminDashboard.tsx
import React, { useState } from "react";
import DashboardView  from "./DashboardView";
import InvoicesView   from "./InvoicesView";
import EntriesView    from "./EntriesView";
import UsersView      from "./UsersView";
import SettingsView   from "./SettingsView";
import DashboardLayout from "@/layout/DashboardLayout";

const AdminDashboard: React.FC = () => {
  // <-- levanto aquí el estado y lo pasaré al Sidebar
  const [activeTab, setActiveTab] = useState<
    "dashboard" | "invoices" | "entries" | "users" | "settings"
  >("dashboard");

  return (
    <DashboardLayout
      activeTab={activeTab}
      onTabChange={setActiveTab}
    >
      {activeTab === "dashboard" && <DashboardView />}
      {activeTab === "invoices"  && <InvoicesView  />}
      {activeTab === "entries"   && <EntriesView   />}
      {activeTab === "users"     && <UsersView     />}
      {activeTab === "settings"  && <SettingsView  />}
    </DashboardLayout>
  );
};

export default AdminDashboard;

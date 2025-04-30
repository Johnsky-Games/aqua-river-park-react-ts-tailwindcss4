// src/pages/admin/SettingsView.tsx
import React, { useState } from "react";

const SettingsView: React.FC = () => {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const [notificationSettings, setNotificationSettings] = useState({
    email: true,
    push: false,
    weekly: true,
    marketing: false
  });
  const [accountSettings, setAccountSettings] = useState({
    name: "John Doe",
    email: "john@example.com",
    language: "en",
    timezone: "UTC"
  });
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const [securitySettings, setSecuritySettings] = useState({
    twoFactor: false,
    sessionTimeout: "30"
  });

  return (
    <div className="space-y-8">
      <h2 className="text-2xl font-bold dark:text-white">Settings</h2>

      {/* Profile */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow-lg">
          <h3 className="text-lg font-semibold mb-4 dark:text-white">Profile Settings</h3>
          <div className="space-y-4">
            {/* Nombre */}
            <div>
              <label className="block text-sm font-medium dark:text-gray-300 mb-1">Name</label>
              <input
                type="text"
                value={accountSettings.name}
                onChange={e => setAccountSettings(s => ({ ...s, name: e.target.value }))}
                className="w-full px-3 py-2 border rounded-md dark:bg-gray-700 dark:border-gray-600"
              />
            </div>
            {/* Email */}
            <div>
              <label className="block text-sm font-medium dark:text-gray-300 mb-1">Email</label>
              <input
                type="email"
                value={accountSettings.email}
                onChange={e => setAccountSettings(s => ({ ...s, email: e.target.value }))}
                className="w-full px-3 py-2 border rounded-md dark:bg-gray-700 dark:border-gray-600"
              />
            </div>
            {/* Language */}
            <div>
              <label className="block text-sm font-medium dark:text-gray-300 mb-1">Language</label>
              <select
                value={accountSettings.language}
                onChange={e => setAccountSettings(s => ({ ...s, language: e.target.value }))}
                className="w-full px-3 py-2 border rounded-md dark:bg-gray-700 dark:border-gray-600"
              >
                <option value="en">English</option>
                <option value="es">Spanish</option>
                <option value="fr">French</option>
              </select>
            </div>
            {/* Timezone */}
            <div>
              <label className="block text-sm font-medium dark:text-gray-300 mb-1">Timezone</label>
              <select
                value={accountSettings.timezone}
                onChange={e => setAccountSettings(s => ({ ...s, timezone: e.target.value }))}
                className="w-full px-3 py-2 border rounded-md dark:bg-gray-700 dark:border-gray-600"
              >
                <option value="UTC">UTC</option>
                <option value="EST">EST</option>
                <option value="PST">PST</option>
              </select>
            </div>
            <button className="bg-indigo-600 text-white px-4 py-2 rounded-lg hover:bg-indigo-700 transition">
              Save Changes
            </button>
          </div>
        </div>

        {/* Notifications */}
        <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow-lg">
          <h3 className="text-lg font-semibold mb-4 dark:text-white">Notifications</h3>
          {/* Aquí irán los toggles que usen notificationSettings */}
        </div>

        {/* Security */}
        <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow-lg">
          <h3 className="text-lg font-semibold mb-4 dark:text-white">Security</h3>
          {/* Aquí irán los toggles que usen securitySettings */}
        </div>
      </div>
    </div>
  );
};

export default SettingsView;

import React from "react";
import { BsPencil, BsTrash } from "react-icons/bs";

interface User {
  id: string;
  name: string;
  email: string;
  role: "Admin" | "Editor" | "User";
  lastActive: string;
}

const usersData: User[] = [
  { id: "USR-001", name: "John Smith",    email: "john.smith@example.com",  role: "Admin",  lastActive: "2023-11-10" },
  { id: "USR-002", name: "Sarah Johnson", email: "sarah.j@example.com",    role: "Editor", lastActive: "2023-11-09" },
  { id: "USR-003", name: "Michael Brown", email: "m.brown@example.com",   role: "User",   lastActive: "2023-11-08" },
  { id: "USR-004", name: "Emma Wilson",   email: "emma.w@example.com",    role: "User",   lastActive: "2023-11-07" }
];

const UsersView: React.FC = () => (
  <div className="space-y-6">
    <div className="flex justify-between items-center">
      <h2 className="text-2xl font-bold dark:text-white">Users</h2>
      <button className="bg-indigo-600 text-white px-4 py-2 rounded-lg hover:bg-indigo-700 transition-colors">
        Add User
      </button>
    </div>
    <div className="bg-white dark:bg-gray-800 rounded-lg shadow-lg overflow-hidden">
      <table className="w-full">
        <thead className="bg-gray-50 dark:bg-gray-700">
          <tr>
            {["ID","Name","Email","Role","Last Active","Actions"].map(h => (
              <th key={h} className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
          {usersData.map(u => (
            <tr key={u.id} className="hover:bg-gray-50 dark:hover:bg-gray-700">
              <td className="px-6 py-4 dark:text-white">{u.id}</td>
              <td className="px-6 py-4 dark:text-gray-300">{u.name}</td>
              <td className="px-6 py-4 dark:text-gray-300">{u.email}</td>
              <td className="px-6 py-4">
                <span className={`
                  px-2 inline-flex text-xs leading-5 font-semibold rounded-full
                  ${u.role === "Admin" ? "bg-purple-100 text-purple-800":""}
                  ${u.role === "Editor"? "bg-blue-100 text-blue-800":""}
                  ${u.role === "User"  ? "bg-green-100 text-green-800":""}
                `}>
                  {u.role}
                </span>
              </td>
              <td className="px-6 py-4 dark:text-gray-300">{u.lastActive}</td>
              <td className="px-6 py-4 dark:text-gray-300">
                <div className="flex space-x-3">
                  <BsPencil className="w-5 h-5 cursor-pointer" />
                  <BsTrash  className="w-5 h-5 cursor-pointer" />
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  </div>
);

export default UsersView;

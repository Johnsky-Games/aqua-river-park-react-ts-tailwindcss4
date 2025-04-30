// src/pages/admin/EntriesView.tsx
import React from "react";
import { BsPencil, BsTrash } from "react-icons/bs";

interface Entry {
  id: string;
  title: string;
  category: string;
  date: string;
  status: "Active" | "In Progress" | "Completed" | "Pending";
}

const entriesData: Entry[] = [
  { id: "ENT-001", title: "New Product Launch", category: "Marketing", date: "2023-11-10", status: "Active" },
  { id: "ENT-002", title: "Website Redesign", category: "Development", date: "2023-11-09", status: "In Progress" },
  { id: "ENT-003", title: "Customer Survey", category: "Research", date: "2023-11-08", status: "Completed" },
  { id: "ENT-004", title: "Q4 Financial Report", category: "Finance", date: "2023-11-07", status: "Pending" },
];

const EntriesView: React.FC = () => (
  <div className="space-y-6">
    <div className="flex justify-between items-center">
      <h2 className="text-2xl font-bold dark:text-white">Entries</h2>
      <button className="bg-indigo-600 text-white px-4 py-2 rounded-lg hover:bg-indigo-700 transition-colors">
        New Entry
      </button>
    </div>

    <div className="bg-white dark:bg-gray-800 rounded-lg shadow-lg overflow-hidden">
      <table className="w-full">
        <thead className="bg-gray-50 dark:bg-gray-700">
          <tr>
            {["ID", "Title", "Category", "Date", "Status", "Actions"].map((th) => (
              <th
                key={th}
                className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider"
              >
                {th}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
          {entriesData.map((e) => (
            <tr key={e.id} className="hover:bg-gray-50 dark:hover:bg-gray-700">
              <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900 dark:text-white">
                {e.id}
              </td>
              <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-300">
                {e.title}
              </td>
              <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-300">
                {e.category}
              </td>
              <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-300">
                {e.date}
              </td>
              <td className="px-6 py-4 whitespace-nowrap">
                <span
                  className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full
                    ${e.status === "Active" ? "bg-green-100 text-green-800" : ""}
                    ${e.status === "In Progress" ? "bg-blue-100 text-blue-800" : ""}
                    ${e.status === "Completed" ? "bg-purple-100 text-purple-800" : ""}
                    ${e.status === "Pending" ? "bg-yellow-100 text-yellow-800" : ""}`}
                >
                  {e.status}
                </span>
              </td>
              <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-300">
                <div className="flex space-x-3">
                  <button><BsPencil className="w-5 h-5 hover:text-blue-900 transition" /></button>
                  <button><BsTrash  className="w-5 h-5 hover:text-red-900  transition" /></button>
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  </div>
);

export default EntriesView;

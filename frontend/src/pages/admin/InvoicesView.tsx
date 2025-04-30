// src/pages/admin/InvoicesView.tsx
import React from "react";
import { BsDownload, BsPencil, BsTrash } from "react-icons/bs";

interface Invoice {
  id: string;
  client: string;
  amount: number;
  date: string;
  status: "Paid" | "Pending" | "Overdue";
}

const invoicesData: Invoice[] = [
  { id: "INV-001", client: "Tech Corp", amount: 1500, date: "2023-11-01", status: "Paid" },
  { id: "INV-002", client: "Design Studios", amount: 2300, date: "2023-11-03", status: "Pending" },
  { id: "INV-003", client: "Marketing Pro", amount: 890, date: "2023-11-05", status: "Paid" },
  { id: "INV-004", client: "Global Solutions", amount: 3200, date: "2023-11-07", status: "Overdue" },
];

const InvoicesView: React.FC = () => (
  <div className="space-y-6">
    <div className="flex justify-between items-center">
      <h2 className="text-2xl font-bold dark:text-white">Invoices</h2>
      <button className="bg-indigo-600 text-white px-4 py-2 rounded-lg hover:bg-indigo-700 transition-colors">
        New Invoice
      </button>
    </div>

    <div className="bg-white dark:bg-gray-800 rounded-lg shadow-lg overflow-hidden">
      <table className="w-full">
        <thead className="bg-gray-50 dark:bg-gray-700">
          <tr>
            {["Invoice ID", "Client", "Amount", "Date", "Status", "Actions"].map((th) => (
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
          {invoicesData.map((inv) => (
            <tr key={inv.id} className="hover:bg-gray-50 dark:hover:bg-gray-700">
              <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900 dark:text-white">
                {inv.id}
              </td>
              <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-300">
                {inv.client}
              </td>
              <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-300">
                ${inv.amount.toFixed(2)}
              </td>
              <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-300">
                {inv.date}
              </td>
              <td className="px-6 py-4 whitespace-nowrap">
                <span
                  className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full
                    ${inv.status === "Paid" ? "bg-green-100 text-green-800" : ""}
                    ${inv.status === "Pending" ? "bg-yellow-100 text-yellow-800" : ""}
                    ${inv.status === "Overdue" ? "bg-red-100 text-red-800" : ""}`}
                >
                  {inv.status}
                </span>
              </td>
              <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-300">
                <div className="flex space-x-3">
                  <button>
                    <BsDownload className="w-5 h-5 hover:text-indigo-900 transition-colors" />
                  </button>
                  <button>
                    <BsPencil className="w-5 h-5 hover:text-blue-900 transition-colors" />
                  </button>
                  <button>
                    <BsTrash className="w-5 h-5 hover:text-red-900 transition-colors" />
                  </button>
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  </div>
);

export default InvoicesView;

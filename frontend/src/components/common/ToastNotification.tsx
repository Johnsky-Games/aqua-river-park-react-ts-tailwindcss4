import { ToastContainer } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";

const ToastNotification = () => {
  return (
    <ToastContainer
      position="top-right"
      autoClose={5000}
      hideProgressBar={false}
      newestOnTop={false}
      closeOnClick
      rtl={false}
      pauseOnFocusLoss
      draggable
      pauseOnHover
      theme="colored" // Puedes cambiar a "light" o "dark"
      toastClassName={() =>
        "bg-white dark:bg-bgDark text-textDark dark:text-textLight rounded shadow-md px-4 py-3"
      }
      className="text-sm font-medium"
      progressClassName={() => "bg-[var(--color-primary)]"}
    />
  );
};

export default ToastNotification;

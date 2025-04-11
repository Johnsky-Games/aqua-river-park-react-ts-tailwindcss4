import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { AxiosError } from "axios";
import api from "../../api/axios";
import { toast } from "react-toastify";
import { useAuthModal } from "../../store/useAuthModal";
import AuthResendModal from "./AuthResendModal";

interface Props {
  modalStep: "notice" | "form" | "success";
  showModal: boolean;
  modalType: "confirm" | "recover";
  setFormEmail: React.Dispatch<React.SetStateAction<string>>;
  setModalStep: React.Dispatch<React.SetStateAction<"notice" | "form" | "success">>;
  setShowModal: React.Dispatch<React.SetStateAction<boolean>>;
  setModalType: React.Dispatch<React.SetStateAction<"confirm" | "recover">>;
}

const initialForm = {
  fullName: "",
  email: "",
  phone: "",
  password: "",
  confirmPassword: "",
};

export default function AuthForm({
  modalStep,
  showModal,
  modalType,
  setFormEmail,
  setModalStep,
  setShowModal,
  setModalType,
}: Props) {
  const { view, closeModal, toggleView } = useAuthModal();
  const isLogin = view === "login";
  const navigate = useNavigate();

  const [formData, setFormData] = useState(initialForm);
  const [errors, setErrors] = useState<{ [key: string]: string }>({});
  const [passwordStrength, setPasswordStrength] = useState(0);
  const [showPassword, setShowPassword] = useState(false);
  const [resendMsg, setResendMsg] = useState("");

  const handleInput = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    setFormData((prev) => ({ ...prev, [name]: value }));

    if (name === "password") setPasswordStrength(validatePassword(value));
    setErrors((prev) => ({ ...prev, [name]: "" }));
  };

  const validatePassword = (password: string) => {
    let score = 0;
    if (password.length >= 8) score++;
    if (/[A-Z]/.test(password)) score++;
    if (/[0-9]/.test(password)) score++;
    if (/[^A-Za-z0-9]/.test(password)) score++;
    return score;
  };

  const validate = () => {
    const errs: { [key: string]: string } = {};
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(formData.email)) {
      errs.email = "Enter a valid email address";
    }
    if (formData.password.length < 8) {
      errs.password = "Password must be at least 8 characters";
    }
    if (!isLogin) {
      if (!formData.fullName || formData.fullName.length < 2) {
        errs.fullName = "Name must be at least 2 characters";
      }
      if (!/^[0-9]{10}$/.test(formData.phone)) {
        errs.phone = "Phone must be a valid 10-digit number";
      }
      if (formData.password !== formData.confirmPassword) {
        errs.confirmPassword = "Passwords do not match";
      }
    }
    setErrors(errs);
    return Object.keys(errs).length === 0;
  };

  const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!validate()) return;

    try {
      if (isLogin) {
        const res = await api.post("/login", {
          email: formData.email,
          password: formData.password,
        });

        if (!res.data.user.isConfirmed) {
          const tokenExpired = res.data.tokenExpired;
          setModalType("confirm");
          setModalStep(tokenExpired ? "form" : "notice");
          setShowModal(true);
          return;
        }

        closeModal();
        toast.success("Login exitoso!");
        navigate("/");
      } else {
        const res = await api.post("/register", {
          name: formData.fullName,
          email: formData.email,
          phone: formData.phone,
          password: formData.password,
        });

        if (res.status === 200 || res.status === 201) {
          toast.success("Registro exitoso. Revisa tu correo.");
          toggleView();
        }
      }
    } catch (err) {
      const error = err as AxiosError<{ message: string; tokenExpired?: boolean }>;
      const msg = error.response?.data?.message;

      if (msg === "Debes confirmar tu cuenta") {
        const tokenExpired = error.response?.data?.tokenExpired;
        setModalType("confirm");
        setModalStep(tokenExpired ? "form" : "notice");
        setShowModal(true);
      } else if (msg) {
        toast.error(msg);
      } else {
        toast.error("Ocurrió un error inesperado.");
      }
    }
  };

  const handleResend = async (e: React.FormEvent) => {
    e.preventDefault();
    setResendMsg("");
  
    const endpoint =
      modalType === "recover"
        ? "/send-recovery"
        : "/resend-confirmation";
  
    try {
      const res = await api.post(endpoint, {
        email: formData.email,
      });
  
      setResendMsg(res.data.message);
      setModalStep("success");
  
      setTimeout(() => {
        toast.success(
          modalType === "recover"
            ? "¡Enlace de recuperación enviado!"
            : "¡Correo de confirmación reenviado!"
        );
        setShowModal(false);
        setResendMsg("");
        setFormData((prev) => ({ ...prev, email: "", password: "" }));
      }, 5000);
    } catch (err) {
      const error = err as AxiosError<{ message: string }>;
      const msg = error.response?.data?.message;
  
      if (msg === "La cuenta ya está confirmada") {
        toast.info("La cuenta ya ha sido confirmada.");
        setShowModal(false);
      } else {
        setResendMsg("Error al enviar el enlace.");
      }
    }
  };
  

  return (
    <>
      <form onSubmit={handleSubmit} className="space-y-4">
        {!isLogin && (
          <>
            <input
              name="fullName"
              value={formData.fullName}
              onChange={handleInput}
              placeholder="Full Name"
              className="input-style"
            />
            {errors.fullName && <p className="text-red-500 text-sm">{errors.fullName}</p>}
          </>
        )}

        <input
          name="email"
          value={formData.email}
          onChange={handleInput}
          placeholder="Email"
          className="input-style"
        />
        {errors.email && <p className="text-red-500 text-sm">{errors.email}</p>}

        {!isLogin && (
          <>
            <input
              name="phone"
              value={formData.phone}
              onChange={handleInput}
              placeholder="Phone"
              className="input-style"
            />
            {errors.phone && <p className="text-red-500 text-sm">{errors.phone}</p>}
          </>
        )}

        <div className="relative">
          <input
            type={showPassword ? "text" : "password"}
            name="password"
            value={formData.password}
            onChange={handleInput}
            placeholder="Password"
            className="input-style pr-10"
          />
          <button
            type="button"
            onClick={() => setShowPassword(!showPassword)}
            className="absolute right-3 top-[10px]"
          >
            {showPassword ? "🙈" : "👁️"}
          </button>
          {errors.password && <p className="text-red-500 text-sm">{errors.password}</p>}
          {!isLogin && (
            <div className="mt-2 flex gap-1">
              {[...Array(4)].map((_, i) => (
                <div
                  key={i}
                  className={`h-2 flex-1 rounded ${i < passwordStrength ? "bg-green-500" : "bg-gray-200"}`}
                />
              ))}
            </div>
          )}
        </div>

        {!isLogin && (
          <>
            <input
              type="password"
              name="confirmPassword"
              value={formData.confirmPassword}
              onChange={handleInput}
              placeholder="Confirm Password"
              className="input-style"
            />
            {errors.confirmPassword && (
              <p className="text-red-500 text-sm">{errors.confirmPassword}</p>
            )}
          </>
        )}

        {isLogin && (
          <div className="flex justify-end text-sm text-blue-600">
            <button
              type="button"
              className="hover:underline"
              onClick={() => {
                setModalType("recover");
                setModalStep("form");
                setShowModal(true);
                setFormEmail(formData.email); // importante para usar en el modal
              }}
            >
              Forgot Password?
            </button>
          </div>
        )}

        <button
          type="submit"
          className="w-full bg-gradient-to-r from-indigo-500 via-purple-500 to-pink-500 text-white py-2 rounded-lg hover:opacity-90 transition-all"
        >
          {isLogin ? "Sign In" : "Sign Up"}
        </button>

        <p className="text-center text-sm text-gray-600 mt-4">
          {isLogin ? "Don’t have an account?" : "Already have an account?"}{" "}
          <button
            type="button"
            onClick={toggleView}
            className="text-blue-600 font-semibold hover:underline"
          >
            {isLogin ? "Sign Up" : "Sign In"}
          </button>
        </p>
      </form>

      <AuthResendModal
        modalStep={modalStep}
        showModal={showModal}
        email={formData.email}
        resendMsg={resendMsg}
        onClose={() => setShowModal(false)}
        onEmailChange={(email) => setFormData((prev) => ({ ...prev, email }))}
        onResend={handleResend}
        type={modalType}
      />
    </>
  );
}

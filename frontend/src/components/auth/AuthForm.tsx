// src/components/auth/AuthForm.tsx
import React, { useState } from "react";
import { AxiosError } from "axios";
import api from "@/api/axios";
import { toast } from "react-toastify";
import { useAuthModal } from "@/store/useAuthModal";
import { useAuthStore, User } from "@/store/useAuthStore";
import { useGoogleReCaptcha } from "react-google-recaptcha-v3";
import AuthResendModal from "@/components/auth/AuthResendModal";
import {
  getPasswordScore,
  capitalizeName,
  validateEmailFormat,
  validatePasswordSecurity,
} from "@/utils/validationHelpersForm";
import InputWithLabel from "@/components/common/InputWithLabel";
import PasswordWithStrengthInput from "@/components/common/PasswordWithStrengthInputForm";

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
  const login = useAuthStore((s) => s.login);
  const isLogin = view === "login";
  const { executeRecaptcha } = useGoogleReCaptcha();

  const [formData, setFormData] = useState(initialForm);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [passwordStrength, setPasswordStrength] = useState(0);
  const [resendMsg, setResendMsg] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [rememberMe, setRememberMe] = useState(false);

  const handleInput = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    const formatted = name === "fullName" ? capitalizeName(value) : value;
    if (name === "password") {
      setPasswordStrength(getPasswordScore(value));
    }
    setFormData((p) => ({ ...p, [name]: formatted }));
    setErrors((p) => ({ ...p, [name]: "" }));
  };

  const validate = () => {
    const errs: Record<string, string> = {};
    if (!validateEmailFormat(formData.email)) {
      errs.email = "Correo no válido";
    }
    const pwdErrs = validatePasswordSecurity(formData.password, formData.email);
    if (pwdErrs.length) {
      errs.password = pwdErrs.join(" ");
    }
    if (!isLogin) {
      if (formData.fullName.trim().length < 2) {
        errs.fullName = "El nombre debe tener al menos 2 caracteres.";
      }
      if (!/^[0-9]{10}$/.test(formData.phone)) {
        errs.phone = "El teléfono debe tener 10 dígitos.";
      }
      if (formData.password !== formData.confirmPassword) {
        errs.confirmPassword = "Las contraseñas no coinciden.";
      }
    }
    setErrors(errs);
    return Object.keys(errs).length === 0;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (isSubmitting) return;
    setIsSubmitting(true);

    if (!validate()) {
      setIsSubmitting(false);
      return;
    }

    if (!executeRecaptcha) {
      toast.error("reCAPTCHA no disponible");
      setIsSubmitting(false);
      return;
    }

    try {
      // Ejecutar reCAPTCHA v3
      const recaptchaToken = await executeRecaptcha("auth");
      api.defaults.headers["X-ReCaptcha-Token"] = recaptchaToken;

      if (isLogin) {
        // Login: cookies set by server → returns { success, user }
        const { data } = await api.post<{ success: boolean; user: User }>(
          "/login",
          {
            email: formData.email,
            password: formData.password,
            rememberMe,
          }
        );
        login({
          id: data.user.id,
          name: data.user.name,
          role: data.user.role,
        });
        closeModal();
        toast.success("¡Login exitoso!");
      } else {
        await api.post("/register", {
          name: formData.fullName,
          email: formData.email,
          phone: formData.phone,
          password: formData.password,
        });
        toast.success(
          "Registro exitoso. Revisa tu correo para confirmar tu cuenta."
        );
        toggleView();
      }
    } catch (err) {
      const error = err as AxiosError<{
        message: string;
        tokenExpired?: boolean;
      }>;
      const msg = error.response?.data?.message;
      if (msg === "Debes confirmar tu cuenta") {
        setModalType("confirm");
        setModalStep(error.response!.data.tokenExpired ? "form" : "notice");
        setShowModal(true);
      } else {
        toast.error(msg || "Ocurrió un error inesperado.");
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleResend = async (e: React.FormEvent) => {
    e.preventDefault();
    if (isSubmitting) return;
    setIsSubmitting(true);
    setResendMsg("");

    const endpoint =
      modalType === "recover" ? "/send-recovery" : "/resend-confirmation";
    try {
      const res = await api.post<{ message: string }>(endpoint, {
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
        setFormData((p) => ({ ...p, email: "", password: "" }));
      }, 5000);
    } catch {
      setResendMsg("Error al enviar el enlace.");
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <>
      <form onSubmit={handleSubmit} className="space-y-4">
        {!isLogin && (
          <>
            <InputWithLabel
              label="Nombre completo"
              name="fullName"
              value={formData.fullName}
              onChange={handleInput}
              placeholder="Tu nombre completo"
              error={errors.fullName}
            />
            <InputWithLabel
              label="Teléfono"
              name="phone"
              value={formData.phone}
              onChange={handleInput}
              placeholder="Teléfono"
              error={errors.phone}
            />
          </>
        )}

        <InputWithLabel
          label="Correo electrónico"
          name="email"
          type="email"
          value={formData.email}
          onChange={handleInput}
          placeholder="Correo electrónico"
          error={errors.email}
          autoFocus
        />

        <PasswordWithStrengthInput
          value={formData.password}
          onChange={handleInput}
          error={errors.password}
          showTooltip={!isLogin}
          showStrengthBar={!isLogin}
          name="password"
          placeholder="Contraseña"
        />

        {!isLogin && (
          <InputWithLabel
            label="Confirma tu contraseña"
            name="confirmPassword"
            type="password"
            value={formData.confirmPassword}
            onChange={handleInput}
            placeholder="Confirma tu contraseña"
            error={errors.confirmPassword}
          />
        )}

        {isLogin && (
          <>
            <div className="flex items-center">
              <input
                id="rememberMe"
                type="checkbox"
                checked={rememberMe}
                onChange={(e) => setRememberMe(e.target.checked)}
                className="mr-2"
              />
              <label htmlFor="rememberMe" className="text-sm">
                Recuérdame
              </label>
            </div>
            <div className="flex justify-end text-sm text-blue-600">
              <button
                type="button"
                className="hover:underline"
                onClick={() => {
                  setModalType("recover");
                  setModalStep("form");
                  setShowModal(true);
                  setFormEmail(formData.email);
                }}
              >
                Forgot Password?
              </button>
            </div>
          </>
        )}

        <button
          type="submit"
          disabled={isSubmitting || (!isLogin && passwordStrength < 3)}
          className={`w-full bg-gradient-to-r from-indigo-500 via-purple-500 to-pink-500 text-white py-2 rounded-lg hover:opacity-90 transition-all ${
            isSubmitting ? "opacity-50 cursor-not-allowed" : ""
          }`}
        >
          {isSubmitting ? "Conectando..." : isLogin ? "Sign In" : "Sign Up"}
        </button>

        <p className="text-center text-sm text-gray-600 mt-4">
          {isLogin ? "¿No tienes cuenta?" : "¿Ya tienes cuenta?"}{" "}
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
        onEmailChange={(email) => setFormData((p) => ({ ...p, email }))}
        onResend={handleResend}
        type={modalType}
      />
    </>
  );
}

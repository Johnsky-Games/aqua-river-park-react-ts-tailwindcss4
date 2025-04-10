import { useEffect, useRef, useState } from "react";
import { motion } from "framer-motion";
import { FaEye, FaEyeSlash, FaFacebook, FaTimes } from "react-icons/fa";
import { FcGoogle } from "react-icons/fc";
import { useAuthModal } from "../store/useAuthModal";
import { useNavigate } from "react-router-dom";
import api from "../api/axios";

const messages = {
  login: {
    title: "Welcome Back! 👋",
    description: "We're so excited to see you again! Enter your details to access your account.",
    sideTitle: "New Here? 🌟",
    sideDescription: "Join our community and discover amazing features!",
    sideButton: "Create Account",
    submit: "Sign In",
  },
  register: {
    title: "Join Our Community! 🎉",
    description: "Create an account and start your journey with us today.",
    sideTitle: "One of Us? 🎈",
    sideDescription: "Already have an account? Sign in and continue your journey!",
    sideButton: "Sign In",
    submit: "Sign Up",
  },
};

const AuthModal = () => {
  const { view, isOpen, closeModal, toggleView } = useAuthModal();
  const isLogin = view === "login";
  const modalRef = useRef<HTMLDivElement>(null);
  const navigate = useNavigate();

  const [showPassword, setShowPassword] = useState(false);
  const [formData, setFormData] = useState({
    fullName: "",
    email: "",
    password: "",
    confirmPassword: "",
  });
  const [errors, setErrors] = useState<{ [key: string]: string }>({});
  const [passwordStrength, setPasswordStrength] = useState(0);

  useEffect(() => {
    const handleOutside = (e: MouseEvent) => {
      if (modalRef.current && !modalRef.current.contains(e.target as Node)) closeModal();
    };
    const handleEsc = (e: KeyboardEvent) => {
      if (e.key === "Escape") closeModal();
    };
    document.addEventListener("mousedown", handleOutside);
    document.addEventListener("keydown", handleEsc);
    return () => {
      document.removeEventListener("mousedown", handleOutside);
      document.removeEventListener("keydown", handleEsc);
    };
  }, [closeModal]);

  const validatePassword = (password: string) => {
    let score = 0;
    if (password.length >= 8) score++;
    if (/[A-Z]/.test(password)) score++;
    if (/[0-9]/.test(password)) score++;
    if (/[^A-Za-z0-9]/.test(password)) score++;
    return score;
  };

  const handleInput = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    setFormData(prev => ({ ...prev, [name]: value }));
    if (name === "password") setPasswordStrength(validatePassword(value));
    setErrors(prev => ({ ...prev, [name]: "" }));
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
      if (formData.password !== formData.confirmPassword) {
        errs.confirmPassword = "Passwords do not match";
      }
    }
    setErrors(errs);
    return Object.keys(errs).length === 0;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!validate()) return;
    try {
      if (isLogin) {
        await api.post("/login", {
          email: formData.email,
          password: formData.password,
        });
        closeModal();
        navigate("/");
      } else {
        await api.post("/register", {
          name: formData.fullName,
          email: formData.email,
          password: formData.password,
          phone: "0000000000",
        });
        alert("Registro exitoso. Revisa tu correo.");
        toggleView();
      }
    } catch {
      setErrors({ email: "Check credentials or server" });
    }
  };

  if (!isOpen) return null;

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="fixed inset-0 bg-black/40 backdrop-blur-sm z-[999] flex items-center justify-center p-4"
    >
      <button
        onClick={closeModal}
        className="absolute top-4 right-4 z-[1000] text-white text-2xl bg-black/50 hover:bg-black/70 p-2 rounded-full"
        aria-label="Cerrar modal"
      >
        <FaTimes />
      </button>

      <motion.div
        ref={modalRef}
        initial={{ scale: 0.95, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        exit={{ scale: 0.9, opacity: 0 }}
        transition={{ duration: 0.3 }}
        className={`bg-white/95 backdrop-blur-md rounded-3xl shadow-2xl w-full max-w-4xl flex flex-col md:flex-row overflow-hidden transition-all ease-in-out duration-700 ${
          isLogin ? "md:flex-row-reverse" : "md:flex-row"
        }`}
      >
        {/* Side Content */}
        <div className="w-full md:w-1/2 p-6 md:p-8 flex flex-col justify-center text-center space-y-6 bg-white">
          <h2 className="text-3xl md:text-4xl font-bold bg-gradient-to-r from-indigo-500 via-purple-500 to-pink-500 text-transparent bg-clip-text">
            {messages[view].sideTitle}
          </h2>
          <p className="text-gray-600">{messages[view].sideDescription}</p>
          <button
            onClick={toggleView}
            className="px-6 py-3 rounded-full bg-gradient-to-r from-indigo-500 via-purple-500 to-pink-500 text-white font-semibold hover:scale-105 transition-all"
          >
            {messages[view].sideButton}
          </button>
        </div>

        {/* Form Section */}
        <div className="w-full md:w-1/2 p-6 md:p-8">
          <h2 className="text-3xl font-bold text-center mb-2 bg-gradient-to-r from-indigo-500 via-purple-500 to-pink-500 text-transparent bg-clip-text">
            {messages[view].title}
          </h2>
          <p className="text-center text-sm text-gray-600 mb-4">{messages[view].description}</p>

          <form onSubmit={handleSubmit} className="space-y-4">
            {!isLogin && (
              <input
                name="fullName"
                value={formData.fullName}
                onChange={handleInput}
                placeholder="Full Name"
                className="input-style"
              />
            )}
            <input
              name="email"
              value={formData.email}
              onChange={handleInput}
              placeholder="Email"
              className="input-style"
            />
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
                {showPassword ? <FaEyeSlash className="text-gray-500" /> : <FaEye className="text-gray-500" />}
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
              <input
                type="password"
                name="confirmPassword"
                value={formData.confirmPassword}
                onChange={handleInput}
                placeholder="Confirm Password"
                className="input-style"
              />
            )}

            <button
              type="submit"
              className="w-full bg-gradient-to-r from-indigo-500 via-purple-500 to-pink-500 text-white py-2 rounded-lg hover:opacity-90 transition-all"
            >
              {messages[view].submit}
            </button>

            {/* Dynamic Links */}
            {isLogin ? (
              <>
                <div className="relative my-4">
                  <div className="absolute inset-0 flex items-center">
                    <div className="w-full border-t border-gray-300" />
                  </div>
                  <div className="relative flex justify-center text-sm">
                    <span className="bg-white px-2 text-gray-500">Or continue with</span>
                  </div>
                </div>
                <div className="grid grid-cols-2 gap-4">
                  <button className="flex items-center justify-center gap-2 border py-2 rounded-lg hover:bg-gray-100">
                    <FcGoogle className="text-xl" />
                    Google
                  </button>
                  <button className="flex items-center justify-center gap-2 border py-2 rounded-lg hover:bg-gray-100">
                    <FaFacebook className="text-xl text-blue-600" />
                    Facebook
                  </button>
                </div>
                <p className="text-center text-sm text-gray-600 mt-4">
                  Don’t have an account?{" "}
                  <button
                    type="button"
                    onClick={toggleView}
                    className="text-blue-600 font-semibold hover:underline"
                  >
                    Sign Up
                  </button>
                </p>
              </>
            ) : (
              <p className="text-center text-sm text-gray-600 mt-4">
                Already have an account?{" "}
                <button
                  type="button"
                  onClick={toggleView}
                  className="text-blue-600 font-semibold hover:underline"
                >
                  Sign In
                </button>
              </p>
            )}
          </form>
        </div>
      </motion.div>
    </motion.div>
  );
};

export default AuthModal;

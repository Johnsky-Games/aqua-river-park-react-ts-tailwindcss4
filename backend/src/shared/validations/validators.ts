import bcrypt from "bcryptjs";

// Validación de email
export const validateEmail = (email: string) => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    throw new Error("Correo electrónico inválido.");
  }
};

// Solo valida que sea fuerte (para el registro)
export const validateNewPassword = (password: string): void => {
  const minLength = 8;
  const hasUpperCase = /[A-Z]/.test(password);
  const hasLowerCase = /[a-z]/.test(password);
  const hasNumber = /\d/.test(password);
  const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);

  if (password.length < minLength)
    throw new Error("La contraseña debe tener al menos 8 caracteres.");

  if (!hasUpperCase)
    throw new Error("La contraseña debe tener al menos una letra mayúscula.");

  if (!hasLowerCase)
    throw new Error("La contraseña debe tener al menos una letra minúscula.");

  if (!hasNumber)
    throw new Error("La contraseña debe incluir al menos un número.");

  if (!hasSpecialChar)
    throw new Error("La contraseña debe incluir un carácter especial.");
};

// Valida que no sea igual a la anterior ni al correo
export const validatePasswordChange = async (
  newPassword: string,
  email: string,
  currentPasswordHash: string
): Promise<void> => {
  validateNewPassword(newPassword);

  if (newPassword === email)
    throw new Error("La contraseña no debe ser igual al correo.");

  const isSameAsOld = await bcrypt.compare(newPassword, currentPasswordHash);
  if (isSameAsOld)
    throw new Error("La nueva contraseña no puede ser igual a la anterior.");
};


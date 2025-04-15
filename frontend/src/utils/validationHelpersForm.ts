// Capitaliza cada palabra
export const capitalizeName = (name: string) => {
    return name
        .toLowerCase()
        .split(" ")
        .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
        .join(" ");
};


// Devuelve el puntaje de seguridad de la contraseña
export const getPasswordScore = (password: string) => {
    let score = 0;
    if (password.length >= 8) score++;
    if (/[A-Z]/.test(password)) score++;
    if (/[0-9]/.test(password)) score++;
    if (/[^A-Za-z0-9]/.test(password)) score++;
    return score;
};


// Valida el formato de la dirección de correo electrónico
export const validateEmailFormat = (email: string): boolean => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
};

// Valida la seguridad de la contraseña
export const validatePasswordSecurity = (password: string, email: string): string[] => {
    const errors: string[] = [];

    if (password.length < 8) {
        errors.push("Debe tener al menos 8 caracteres.");
    }
    if (!/[A-Z]/.test(password)) {
        errors.push("Debe incluir al menos una letra mayúscula.");
    }
    if (!/[a-z]/.test(password)) {
        errors.push("Debe incluir al menos una letra minúscula.");
    }
    if (!/[0-9]/.test(password)) {
        errors.push("Debe incluir al menos un número.");
    }
    if (!/[^A-Za-z0-9]/.test(password)) {
        errors.push("Debe incluir al menos un símbolo.");
    }
    if (password.toLowerCase() === email.toLowerCase()) {
        errors.push("La contraseña no puede ser igual al correo electrónico.");
    }

    return errors;
};

// Devuelve el texto, color y clase CSS según el puntaje de la contraseña
export const getStrengthLabel = (score: number) => {
    switch (score) {
      case 0:
      case 1:
        return {
          text: "Débil",
          color: "text-red-500 dark:text-red-400",
          bar: "bg-red-500 dark:bg-red-400",
        };
      case 2:
        return {
          text: "Media",
          color: "text-yellow-500 dark:text-yellow-400",
          bar: "bg-yellow-400 dark:bg-yellow-300",
        };
      case 3:
        return {
          text: "Fuerte",
          color: "text-blue-500 dark:text-blue-400",
          bar: "bg-blue-500 dark:bg-blue-400",
        };
      case 4:
        return {
          text: "Muy fuerte",
          color: "text-green-600 dark:text-green-400",
          bar: "bg-green-500 dark:bg-green-400",
        };
      default:
        return {
          text: "",
          color: "",
          bar: "bg-gray-200 dark:bg-gray-600",
        };
    }
  };
  


// frontend/src/api/axios.ts
import axios from "axios";

const api = axios.create({
  baseURL: "http://localhost:3000/api",
  withCredentials: true, // si usas cookies
  headers: {
    "Content-Type": "application/json",
  },
});

// Solo interceptores o configuración global, nunca llamadas aquí

export default api;


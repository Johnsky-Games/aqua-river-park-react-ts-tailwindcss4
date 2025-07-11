// src/api/axios.ts
import axios from "axios";

const api = axios.create({
  baseURL: "http://localhost:3000/api", // aquí tu URL fija
  withCredentials: true,
  headers: { "Content-Type": "application/json" },
});

export default api;

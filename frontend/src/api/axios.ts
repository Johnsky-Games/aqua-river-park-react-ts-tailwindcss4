// frontend/src/api/axios.ts
import axios from 'axios';

const api = axios.create({
  baseURL: 'http://localhost:3000/api', // 👈 Este debe apuntar al backend
});

export default api;

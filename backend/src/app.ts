import express from 'express';
import dashboardRoutes from './routes/dashboard.routes';
import authRoutes from './routes/auth.routes';
import cors from 'cors';
import notFound from "./middlewares/notFound.middleware";
import errorHandler from "./middlewares/errorHandler.middleware";
import xss from "xss-clean";


const app = express();
app.use(cors({
    origin: 'http://localhost:5173', // 👈 Asegúrate que coincida con el frontend
    credentials: true
}));
app.use(express.json());
app.use(xss());

// Agrupar rutas protegidas bajo /api
app.use('/api', dashboardRoutes);
app.use('/api', authRoutes);
app.use(notFound);      // 👉 Para rutas no encontradas
app.use(errorHandler);  // 👉 Para manejar errores de forma centralizada

export default app;
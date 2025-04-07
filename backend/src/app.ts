import express from 'express';
import dashboardRoutes from './routes/dashboard.routes';
import authRoutes from './routes/auth.routes';
import cors from 'cors';

const app = express();
app.use(cors({
    origin: 'http://localhost:5173', // 👈 Asegúrate que coincida con el frontend
    credentials: true
}));
app.use(express.json());

// Agrupar rutas protegidas bajo /api
app.use('/api', dashboardRoutes);
app.use('/api', authRoutes);

export default app;
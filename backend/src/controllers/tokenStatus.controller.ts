// backend/src/controllers/tokenStatus.controller.ts
import { Request, Response } from 'express';
import db from '../config/db';
import { RowDataPacket } from 'mysql2';

export const checkTokenStatus = async (req: Request, res: Response): Promise<void> => {
  const { email } = req.body;

  try {
    const [rows] = await db.query<RowDataPacket[]>(
      'SELECT is_confirmed, confirmation_expires FROM users WHERE email = ?',
      [email]
    );

    if (rows.length === 0) {
      res.status(404).json({ message: 'Correo no encontrado' });
      return;
    }

    const user = rows[0];
    const now = new Date();

    const isExpired = new Date(user.confirmation_expires) < now;

    res.status(200).json({
      is_confirmed: user.is_confirmed,
      is_expired: isExpired,
    });
  } catch (error) {
    console.error('❌ Error verificando estado del token:', error);
    res.status(500).json({ message: 'Error en el servidor' });
  }
};

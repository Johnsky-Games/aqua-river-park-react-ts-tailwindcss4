// backend/src/controllers/confirm.controller.ts
import { Request, Response } from 'express';
import db from '../config/db';
import { RowDataPacket } from 'mysql2';

export const confirmUser = async (req: Request, res: Response): Promise<void> => {
  const { token } = req.params;

  try {
    const [rows] = await db.query<RowDataPacket[]>(
      'SELECT * FROM users WHERE confirmation_token = ? AND confirmation_expires > NOW()',
      [token]
    );

    if (rows.length === 0) {
      res.status(400).json({ message: 'El enlace ya fue utilizado o ha expirado.' });
      return;
    }

    await db.query(
      'UPDATE users SET is_confirmed = 1, confirmation_token = NULL, confirmation_expires = NULL WHERE id = ?',
      [rows[0].id]
    );

    res.status(200).json({ message: '✅ Tu cuenta ha sido confirmada exitosamente.' });
  } catch (error) {
    console.error('❌ Error al confirmar:', error);
    res.status(500).json({ message: 'Ocurrió un error al confirmar tu cuenta.' });
  }
};

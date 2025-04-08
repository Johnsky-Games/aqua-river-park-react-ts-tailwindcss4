import { Request, Response } from 'express';
import db from '../config/db';
import crypto from 'crypto';
import sendConfirmationEmail from '../utils/mailerConfirmation';
import { RowDataPacket } from 'mysql2';

export const resendConfirmation = async (req: Request, res: Response): Promise<void> => {
    const { email } = req.body;

    try {
        const [rows] = await db.query<RowDataPacket[]>(
            'SELECT id, is_confirmed FROM users WHERE email = ?',
            [email]
        );

        if (rows.length === 0) {
            res.status(404).json({ message: 'Correo no encontrado' });
            return;
        }

        const user = rows[0];
        if (user.is_confirmed) {
            res.status(400).json({ message: 'La cuenta ya está confirmada' });
            return;
        }

        const newToken = crypto.randomBytes(32).toString('hex');
        const newExpires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24h

        await db.query(
            'UPDATE users SET confirmation_token = ?, confirmation_expires = ? WHERE id = ?',
            [newToken, newExpires, user.id]
        );

        await sendConfirmationEmail(email, newToken);

        res.status(200).json({ message: 'Se envió un nuevo enlace de confirmación a tu correo' });
    } catch (error) {
        console.error('❌ Error al reenviar confirmación:', error);
        res.status(500).json({ message: 'Error en el servidor' });
    }
};

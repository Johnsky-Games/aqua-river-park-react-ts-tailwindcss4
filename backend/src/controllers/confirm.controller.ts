import { Request, Response } from 'express';
import db from '../config/db';
import { RowDataPacket } from 'mysql2';

export const confirmUser = async (req: Request, res: Response): Promise<void> => {
    const { token } = req.params;
    const { email } = req.query;

    try {
        // Primero intenta encontrar al usuario por token
        const [rows] = await db.query<RowDataPacket[]>(
            'SELECT * FROM users WHERE confirmation_token = ?',
            [token]
        );

        const user = rows[0];

        if (!user) {
            // Si no encuentra por token, busca por email
            if (email) {
                const [emailRows] = await db.query<RowDataPacket[]>(
                    'SELECT is_confirmed FROM users WHERE email = ?',
                    [email]
                );

                if (emailRows.length > 0 && emailRows[0].is_confirmed === 1) {
                    res.status(200).json({ message: 'La cuenta ya ha sido confirmada.' });
                    return;
                }
            }

            res.status(400).json({ message: 'Token inválido o expirado' });
            return;
        }

        // Si ya está confirmado
        if (user.is_confirmed === 1) {
            res.status(200).json({ message: 'La cuenta ya ha sido confirmada.' });
            return;
        }

        // Verifica expiración del token
        const now = new Date();
        if (new Date(user.confirmation_expires) < now) {
            res.status(400).json({ message: 'Token inválido o expirado' });
            return;
        }

        // Confirmar cuenta
        await db.query(
            'UPDATE users SET is_confirmed = 1, confirmation_token = NULL, confirmation_expires = NULL WHERE id = ?',
            [user.id]
        );

        res.status(200).json({ message: 'Cuenta confirmada exitosamente.' });
    } catch (error) {
        console.error('❌ Error al confirmar:', error);
        res.status(500).json({ message: 'Error en el servidor' });
    }
};


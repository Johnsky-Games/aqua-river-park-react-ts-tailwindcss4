// backend/utils/mailerConfirmation.ts
import { transporter } from '../config/mailer';

const sendConfirmationEmail = async (email: string, token: string) => {
  const link = `${process.env.FRONTEND_URL}/confirm/${token}`;

  await transporter.sendMail({
    from: '"Aqua River Park" <no-reply@aquariverpark.com>',
    to: email,
    subject: 'Confirma tu cuenta',
    html: `
      <h2>Bienvenido a Aqua River Park</h2>
      <p>Haz clic en el siguiente enlace para confirmar tu cuenta:</p>
      <a href="${link}">Confirmar cuenta</a>
    `
  });
};

export default sendConfirmationEmail;

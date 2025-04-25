// src/infraestructure/mail/mailService.ts
import { transporter } from "@/config/mailer";
import logger from "@/infraestructure/logger/logger";

export const sendEmail = async ({
  to,
  subject,
  html,
}: {
  to: string;
  subject: string;
  html: string;
}) => {
  try {
    await transporter.sendMail({
      from: '"Aqua River Park" <no-reply@aquariverpark.com>',
      to,
      subject,
      html,
    });
    logger.info(`📨 Correo enviado a ${to}: ${subject}`);
  } catch (error: any) {
    logger.error(`❌ Error enviando correo a ${to}: ${error.message}`);
    throw new Error("Error al enviar correo");
  }
};

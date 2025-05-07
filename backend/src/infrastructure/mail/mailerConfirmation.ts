// backend/utils/mailerConfirmation.ts
import { sendEmail } from "@/infrastructure/mail/mailService";

const sendConfirmationEmail = async (email: string, token: string) => {
  const link = `${process.env.FRONTEND_URL}/confirm/${token}?email=${encodeURIComponent(email)}`;

  const html = `
 <div style="margin: 0; padding: 0; background-color: #e0f7fa; font-family: 'Segoe UI', sans-serif;">
      <table role="presentation" cellpadding="0" cellspacing="0" width="100%">
        <tr>
          <td align="center" style="padding: 40px 10px;">
            <table cellpadding="0" cellspacing="0" style="max-width: 600px; width: 100%; background-color: #ffffff; border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); padding: 40px;">
              <tr>
                <td align="center" style="padding-bottom: 20px;">
                  <h2 style="font-size: 26px; color: #0ea5e9; margin: 0;">🌊 ¡Bienvenido a Aqua River Park!</h2>
                </td>
              </tr>
              <tr>
                <td style="font-size: 16px; color: #444; text-align: center; padding-bottom: 20px;">
                   Gracias por registrarte. Estamos felices de tenerte en nuestra comunidad. Para completar tu registro, por favor confirma tu cuenta haciendo clic a continuación.
                </td>
              </tr>
              <tr>
                <td align="center" style="padding: 20px 0;">
                  <a href="${link}" style="background-color: #0ea5e9; color: white; text-decoration: none; padding: 14px 30px; border-radius: 8px; font-size: 16px; display: inline-block;">
                    Confirmar cuenta
                  </a>
                </td>
              </tr>
              <tr>
                <td style="font-size: 14px; color: #666; text-align: center; padding-top: 20px;">
                  Si no solicitaste este registro, puedes ignorar este mensaje.
                </td>
              </tr>
              <tr>
                <td style="border-top: 1px solid #eee; padding-top: 30px; text-align: center; font-size: 12px; color: #999;">
                  © ${new Date().getFullYear()} Aqua River Park. Todos los derechos reservados.<br><br>
                  Síguenos en nuestras redes sociales:
                  <div style="margin-top: 10px;">
                    <a href="https://www.instagram.com/aquariverpark/" target="_blank" style="margin: 0 10px;">
                      <img src="https://img.icons8.com/color/48/instagram-new.png" alt="Instagram" width="24" height="24" style="vertical-align: middle;" />
                    </a>
                    <a href="https://www.facebook.com/aquariverpark/" target="_blank" style="margin: 0 10px;">
                      <img src="https://img.icons8.com/color/48/facebook-new.png" alt="Facebook" width="24" height="24" style="vertical-align: middle;" />
                    </a>
                    <a href="https://www.tiktok.com/@aquariverpark" target="_blank" style="margin: 0 10px;">
                      <img src="https://img.icons8.com/color/48/tiktok--v1.png" alt="TikTok" width="24" height="24" style="vertical-align: middle;" />
                    </a>
                    <a href="https://www.youtube.com/@aquariverpark" target="_blank" style="margin: 0 10px;">
                      <img src="https://img.icons8.com/color/48/youtube-play.png" alt="YouTube" width="24" height="24" style="vertical-align: middle;" />
                    </a>
                  </div>
                </td>
              </tr>
            </table>
          </td>
        </tr>
      </table>
    </div>
  `;

  await sendEmail({
    to: email,
    subject: "Confirma tu cuenta",
    html,
  });
};

export default sendConfirmationEmail;



// const sendConfirmationEmail = async (email: string, token: string) => {
//   const link = `${process.env.FRONTEND_URL}/confirm/${token}?email=${encodeURIComponent(email)}`;
//   logger.info(`📨 Enviando correo de confirmación a ${email}`);

//   await transporter.sendMail({
//     from: '"Aqua River Park" <no-reply@aquariverpark.com>',
//     to: email,
//     subject: "Confirma tu cuenta",
//     html: `
//     <div style="margin: 0; padding: 0; background-color: #e0f7fa; font-family: 'Segoe UI', sans-serif;">
//       <table role="presentation" cellpadding="0" cellspacing="0" width="100%">
//         <tr>
//           <td align="center" style="padding: 40px 10px;">
//             <table cellpadding="0" cellspacing="0" style="max-width: 600px; width: 100%; background-color: #ffffff; border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); padding: 40px;">
//               <tr>
//                 <td align="center" style="padding-bottom: 20px;">
//                   <h2 style="font-size: 26px; color: #0ea5e9; margin: 0;">🌊 ¡Bienvenido a Aqua River Park!</h2>
//                 </td>
//               </tr>
//               <tr>
//                 <td style="font-size: 16px; color: #444; text-align: center; padding-bottom: 20px;">
//                    Gracias por registrarte. Estamos felices de tenerte en nuestra comunidad. Para completar tu registro, por favor confirma tu cuenta haciendo clic a continuación.
//                 </td>
//               </tr>
//               <tr>
//                 <td align="center" style="padding: 20px 0;">
//                   <a href="${link}" style="background-color: #0ea5e9; color: white; text-decoration: none; padding: 14px 30px; border-radius: 8px; font-size: 16px; display: inline-block;">
//                     Confirmar cuenta
//                   </a>
//                 </td>
//               </tr>
//               <tr>
//                 <td style="font-size: 14px; color: #666; text-align: center; padding-top: 20px;">
//                   Si no solicitaste este registro, puedes ignorar este mensaje.
//                 </td>
//               </tr>
//               <tr>
//                 <td style="border-top: 1px solid #eee; padding-top: 30px; text-align: center; font-size: 12px; color: #999;">
//                   © ${new Date().getFullYear()} Aqua River Park. Todos los derechos reservados.<br><br>
//                   Síguenos en nuestras redes sociales:
//                   <div style="margin-top: 10px;">
//                     <a href="https://www.instagram.com/aquariverpark/" target="_blank" style="margin: 0 10px;">
//                       <img src="https://img.icons8.com/color/48/instagram-new.png" alt="Instagram" width="24" height="24" style="vertical-align: middle;" />
//                     </a>
//                     <a href="https://www.facebook.com/aquariverpark/" target="_blank" style="margin: 0 10px;">
//                       <img src="https://img.icons8.com/color/48/facebook-new.png" alt="Facebook" width="24" height="24" style="vertical-align: middle;" />
//                     </a>
//                     <a href="https://www.tiktok.com/@aquariverpark" target="_blank" style="margin: 0 10px;">
//                       <img src="https://img.icons8.com/color/48/tiktok--v1.png" alt="TikTok" width="24" height="24" style="vertical-align: middle;" />
//                     </a>
//                     <a href="https://www.youtube.com/@aquariverpark" target="_blank" style="margin: 0 10px;">
//                       <img src="https://img.icons8.com/color/48/youtube-play.png" alt="YouTube" width="24" height="24" style="vertical-align: middle;" />
//                     </a>
//                   </div>
//                 </td>
//               </tr>
//             </table>
//           </td>
//         </tr>
//       </table>
//     </div>
//   `,
//   });
// };

// export default sendConfirmationEmail;

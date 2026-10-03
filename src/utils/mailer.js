import nodemailer from 'nodemailer';

// Every email is sent from the SMTP mailbox (SMTP_USER), the Titan business address.
export const send = (mail) => {
  const port = Number(process.env.SMTP_PORT) || 465;
  return nodemailer
    .createTransport({
      host: process.env.SMTP_HOST,
      port,
      secure: port === 465, // 465 is TLS from the start; 587 upgrades via STARTTLS
      auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
    })
    .sendMail({ from: process.env.SMTP_USER, ...mail });
};

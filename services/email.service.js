const nodemailer = require('nodemailer');
const logger = require('../utils/logger');

const sendEmail = async ({ to, subject, text, html }) => {
  // ✅ Create transporter with explicit Gmail SMTP settings
  const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',    // Gmail SMTP server
    port: 587,                 // TLS port
    secure: false,             // false for TLS
    auth: {
      user: process.env.EMAIL_USER, // your Gmail address
      pass: process.env.EMAIL_PASS, // your Google App Password (16 chars, no spaces)
    },
    logger: false,   // logs SMTP connection info
    debug: false,    // prints raw SMTP messages
    tls: {
      rejectUnauthorized: false, // allows self-signed certs
    },
  });

  const mailOptions = {
    from: process.env.EMAIL_USER,
    to,
    subject,
    text,
    html,
  };

  try {
    await transporter.sendMail(mailOptions);
    logger.info(`📧 Email sent to ${to}: ${subject}`);
  } catch (err) {
    logger.error('📧 Email sending failed:', err.message);
    throw err; // throw original error to see what failed
  }
};

module.exports = sendEmail;

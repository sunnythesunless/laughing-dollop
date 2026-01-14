require('dotenv').config({ path: '../.env' });
const sendEmail = require('../services/email.service');

(async () => {
  try {
    await sendEmail({
      to: 'goneboneper@gmail.com',
      subject: 'Test Email',
      text: 'Hello from Nodemailer!',
      html: '<h1>Hello from Nodemailer time 2!</h1>',
    });
    console.log('✅ Email sent successfully');
  } catch (err) {
    console.error('❌ Email failed:', err.message);
  }
})();

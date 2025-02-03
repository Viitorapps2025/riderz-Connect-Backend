// emailService.js
const nodemailer = require('nodemailer');
require('dotenv').config();


// Create the transporter using environment variables
const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com', 
  port: 587, // SMTP port (587 is common for TLS)
  secure: false, // Use TLS
  auth: {
    user: process.env.NODE_CODE_SENDING_EMAIL_ADDRESS, // Your email address
    pass: process.env.NODE_CODE_SENDING_EMAIL_PASSWORD, // Your email password
  },
});

// Function to send an email
const sendEmail = async (to, subject, text, html) => {
  const mailOptions = {
    from: process.env.NODE_CODE_SENDING_EMAIL_ADDRESS, // Sender address
    to: to, // Recipient address
    subject: subject, // Subject line
    text: text, // Plain text body
    html: html, // HTML body (optional)
  };

  try {
    const info = await transporter.sendMail(mailOptions);
    console.log('Message sent: %s', info.messageId);
  } catch (error) {
    console.error('Error sending email:', error);
  }
};

module.exports = sendEmail;

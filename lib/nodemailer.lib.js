import nodemailer from 'nodemailer'

//! This code is written for ethereal test email that send verification link in console
// const testAccount = await nodemailer.createTestAccount()  //it can access auth field of 'nodemailer.createTransport'

// //? Create a test account or replace with real credentials.
// const transporter = nodemailer.createTransport({
//   host: "smtp.ethereal.email",    //smtp.google.email but we are using ethereal testing mail
//   port: 587,
//   secure: false, // true for 465, false for other ports
//   auth: {
//     user: "mercedes.rath74@ethereal.email",  //this value is taken from ethereal website -> create account
//     pass: "41zaDqPs9ZRfqKNGAN",
//   },
// });



// //?now we are using our own created sendEmail function(auth.services.js -> resendVerificationLink)
// export const sendEmail = async ({to, subject, html}) => {
//   const info = await transporter.sendMail({
//       from : `Shrinkify <${testAccount.user}>`,
//       to, 
//       subject, 
//       html
//   })
  
//   const testEmailUrl = nodemailer.getTestMessageUrl(info)
//   console.log('verify email ',testEmailUrl);
    
// }
// //?after this go to auth.services.js and change import of sendMail from 'nodemailer' to 'resend'


//!This code is written for smtp google mail server........................
// --- Gmail SMTP Configuration ---
// IMPORTANT: You MUST generate an "App Password" for your Gmail account.
// 1. Go to your Google Account (myaccount.google.com).
// 2. Navigate to "Security".
// 3. Under "How you sign in to Google", enable "2-Step Verification".
// 4. Once 2-Step Verification is on, an "App passwords" option will appear. Click it.
// 5. Select "Mail" for the app and "Other (Custom name)" for the device. Give it a name like "Shrinkify App".
// 6. A 16-character password will be generated. This is your App Password.
//    You will use this in `process.env.GMAIL_APP_PASSWORD`.
// 7. Store your Gmail address in `process.env.GMAIL_USER_EMAIL`.
const transporter = nodemailer.createTransport({
  service: 'gmail', // Specifies to use Gmail's well-known SMTP server
  auth: {
    user: process.env.GMAIL_USER_EMAIL, // Your actual Gmail address from .env
    pass: process.env.GMAIL_APP_PASSWORD // The generated 16-character App Password from .env
  }
});

// --- sendEmail Function ---
// This function sends an email using the configured Gmail SMTP transporter.
export const sendEmail = async ({to, subject, html}) => {
  try {
    // The 'from' field MUST be your exact Gmail address for the email to send successfully.
    // The display name ("Shrinkify") is optional but good for branding.
    const info = await transporter.sendMail({
      from: `Shrinkify <${process.env.GMAIL_USER_EMAIL}`, // Use your Gmail address here
      to: to,      // Recipient email address
      subject: subject, // Email subject line
      html: html   // HTML content of the email
    });

    console.log('Email sent successfully via Gmail! Message ID: %s', info.messageId);
    // Emails go to the actual recipient's inbox.

    return info; // Return the info object for potential further use
  } catch (error) {
    console.error('Error sending email via Gmail SMTP:', error);
    // Re-throw the error for higher-level error handling
    throw error;
  }
};
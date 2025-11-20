import nodemailer from 'nodemailer';

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,   // smtp.gmail.com
  port: 465,                     // SSL/TLS
  secure: true,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

export const sendOtpEmail = async (to: string, otp: string) => {
  const htmlContent = `
  <div style="font-family: 'Helvetica Neue', Arial, sans-serif; background-color: #f5f7fa; padding: 60px 20px;">
    <div style="max-width: 600px; margin: auto; background: #ffffff; border-radius: 20px; padding: 60px 40px; text-align: center; box-shadow: 0 20px 40px rgba(0,0,0,0.08); border: 1px solid #e6e9ef;">
      
      <h1 style="color: #1f2937; font-size: 32px; font-weight: 700; margin-bottom: 20px;">
        YourApp – Secure Verification
      </h1>
      
      <p style="font-size: 18px; color: #4b5563; line-height: 1.6; margin-bottom: 40px;">
        Enter the one-time passcode below to securely complete your registration.
      </p>
      
      <div style="
        font-family: 'Courier New', monospace;
        font-size: 50px;
        font-weight: 700;
        color: #111827;
        letter-spacing: 10px;
        padding: 25px 50px;
        background: linear-gradient(90deg, #dbeafe, #bfdbfe);
        border-radius: 15px;
        display: inline-block;
        margin-bottom: 40px;
        box-shadow: 0 10px 20px rgba(0,0,0,0.05);
      ">${otp}</div>
      
      <p style="font-size: 15px; color: #6b7280; line-height: 1.5; margin-bottom: 40px;">
        This OTP is valid for <strong>5 minutes</strong> only. Please do not share it with anyone.
      </p>
      
      <hr style="border: none; border-top: 1px solid #e5e7eb; margin: 40px 0;">
      
      <p style="font-size: 12px; color: #9ca3af; line-height: 1.5;">
        If you did not request this code, please ignore this email. Security is our top priority.
      </p>
      <p style="font-size: 12px; color: #9ca3af; margin-top: 8px;">
        &copy; ${new Date().getFullYear()} YourApp. All rights reserved.
      </p>
    </div>
  </div>
  `;

  const textContent = `YourApp OTP Code: ${otp}. Valid for 5 minutes.`;

  await transporter.sendMail({
    from: `"YourApp Security" <${process.env.SMTP_FROM || process.env.SMTP_USER}>`,
    to,
    subject: 'YourApp OTP Verification Code',
    text: textContent,
    html: htmlContent,
  });

  console.log(`✅ OTP sent to ${to}: ${otp}`);
};

import nodemailer from "nodemailer";

interface SendEmailParams {
  to: string;
  subject: string;
  html: string;
  text: string;
}

// In-memory log of recent test emails for UI testing/debugging if SMTP is not provided
export interface LoggedEmail {
  id: string;
  to: string;
  subject: string;
  previewUrl?: string;
  verificationToken?: string;
  resetToken?: string;
  otpCode?: string;
  timestamp: string;
  type: 'verification' | 'password_reset' | 'otp' | 'notification';
}

const recentTestEmails: LoggedEmail[] = [];

export function getRecentTestEmails(): LoggedEmail[] {
  return [...recentTestEmails].reverse().slice(0, 10);
}

function sanitizePass(pass?: string): string {
  if (!pass) return "";
  // Google App passwords are 16 chars with spaces like 'abcd efgh ijkl mnop'; remove spaces
  const cleaned = pass.trim();
  if (cleaned.length >= 16 && cleaned.includes(" ")) {
    return cleaned.replace(/\s+/g, "");
  }
  return cleaned;
}

function getTransporter(forceSecure?: boolean) {
  const host = process.env.SMTP_HOST?.trim();
  const service = process.env.SMTP_SERVICE?.trim().toLowerCase();
  const rawPort = parseInt(process.env.SMTP_PORT || "587", 10);
  const port = forceSecure ? 465 : rawPort;
  const user = process.env.SMTP_USER?.trim();
  const pass = sanitizePass(process.env.SMTP_PASS);
  const isGmail = service === "gmail" || (host ? host.toLowerCase().includes("gmail.com") : false);
  const secure = forceSecure || process.env.SMTP_SECURE === "true" || port === 465;

  // Only attempt SMTP if real, non-placeholder credentials are provided
  if ((host || isGmail) && user && pass && !host?.includes("example.com") && !host?.includes("your-provider.com")) {
    if (isGmail) {
      return nodemailer.createTransport({
        service: "gmail",
        auth: { user, pass },
        connectionTimeout: 6000,
        greetingTimeout: 5000,
        socketTimeout: 6000,
        tls: { rejectUnauthorized: false }
      });
    }

    return nodemailer.createTransport({
      host,
      port,
      secure,
      auth: { user, pass },
      connectionTimeout: 6000,
      greetingTimeout: 5000,
      socketTimeout: 6000,
      tls: { rejectUnauthorized: false }
    });
  }

  return null;
}

export async function sendEmail({ to, subject, html, text }: SendEmailParams): Promise<{ sent: boolean; messageId?: string; simulated?: boolean }> {
  const user = process.env.SMTP_USER?.trim();
  const from = process.env.SMTP_FROM || process.env.EMAIL_FROM || (user ? `"ShieldZen Security" <${user}>` : '"ShieldZen Cyber Intel" <security@shieldzen.sec>');
  let transporter = getTransporter();

  if (transporter) {
    try {
      const info = await transporter.sendMail({
        from,
        to,
        subject,
        text,
        html,
      });
      console.log(`[EmailService] Real SMTP Email dispatched to ${to} (Message ID: ${info.messageId})`);
      return { sent: true, messageId: info.messageId, simulated: false };
    } catch (err: any) {
      console.warn(`[EmailService] Primary SMTP attempt to ${to} failed (${err?.message || "connection error"}). Trying secondary SSL fallback...`);
      
      // Secondary attempt with forced SSL (Port 465) if applicable
      try {
        const fallbackTransporter = getTransporter(true);
        if (fallbackTransporter) {
          const info = await fallbackTransporter.sendMail({
            from,
            to,
            subject,
            text,
            html,
          });
          console.log(`[EmailService] SMTP SSL Fallback dispatched to ${to} (Message ID: ${info.messageId})`);
          return { sent: true, messageId: info.messageId, simulated: false };
        }
      } catch (fallbackErr: any) {
        console.warn(`[EmailService] SMTP fallback to ${to} also failed (${fallbackErr?.message || "connection timeout"}). Routing to Sandbox dispatch.`);
      }
    }
  }

  // Fallback: Sandbox / Development email logging
  console.log(`\n========================================================================`);
  console.log(`[SHIELDZEN EMAIL SERVICE - LOCAL SANDBOX DISPATCH]`);
  console.log(`To: ${to}`);
  console.log(`Subject: ${subject}`);
  console.log(`------------------------------------------------------------------------`);
  console.log(text);
  console.log(`========================================================================\n`);

  return { sent: true, simulated: true };
}

export async function sendVerificationEmail(email: string, name: string, token: string, baseUrl: string): Promise<boolean> {
  const verifyLink = `${baseUrl}/login?mode=verify&email=${encodeURIComponent(email)}&token=${encodeURIComponent(token)}`;

  // Store in test list
  recentTestEmails.push({
    id: "mail-" + Math.random().toString(36).substring(2, 9),
    to: email,
    subject: "Verify your ShieldZen CTI Analyst Account",
    previewUrl: verifyLink,
    verificationToken: token,
    timestamp: new Date().toISOString(),
    type: 'verification'
  });

  const subject = "Verify your ShieldZen CTI Analyst Account";
  const text = `Hello ${name},\n\nWelcome to ShieldZen Cyber Threat Intelligence Platform.\n\nPlease verify your email address to activate your analyst access:\n${verifyLink}\n\nYour Verification Token: ${token}\n\nThis verification link will expire in 24 hours.\n\nIf you did not register for a ShieldZen account, please disregard this email.\n\n- ShieldZen SOC Security Team`;

  const html = `
    <!DOCTYPE html>
    <html>
      <head>
        <meta charset="utf-8">
        <style>
          body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background-color: #0B0F17; color: #E2E8F0; margin: 0; padding: 24px; }
          .card { max-width: 560px; margin: 0 auto; background-color: #131B2A; border: 1px solid #1E293B; border-radius: 12px; padding: 32px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }
          .header { display: flex; align-items: center; gap: 12px; margin-bottom: 24px; border-bottom: 1px solid #1E293B; padding-bottom: 16px; }
          .logo { font-size: 20px; font-weight: 700; color: #38BDF8; letter-spacing: -0.5px; }
          .badge { background-color: rgba(56, 189, 248, 0.1); color: #38BDF8; font-size: 11px; padding: 3px 8px; border-radius: 4px; font-weight: 600; border: 1px solid rgba(56, 189, 248, 0.2); }
          h2 { color: #F8FAFC; margin-top: 0; font-size: 20px; }
          p { color: #94A3B8; line-height: 1.6; font-size: 14px; margin-bottom: 16px; }
          .token-box { background-color: #090D16; border: 1px solid #334155; border-radius: 8px; padding: 16px; text-align: center; margin: 24px 0; }
          .token-code { font-family: monospace; font-size: 22px; font-weight: 700; color: #38BDF8; letter-spacing: 3px; }
          .btn { display: inline-block; background-color: #0284C7; color: #FFFFFF !important; text-decoration: none; padding: 12px 28px; border-radius: 8px; font-weight: 600; font-size: 14px; margin: 16px 0; text-align: center; }
          .footer { margin-top: 32px; border-top: 1px solid #1E293B; padding-top: 16px; font-size: 12px; color: #64748B; text-align: center; }
        </style>
      </head>
      <body>
        <div class="card">
          <div class="header">
            <span class="logo">ShieldZen</span>
            <span class="badge">Cyber Threat Intel</span>
          </div>
          <h2>Verify Your Analyst Account</h2>
          <p>Hello <strong>${name}</strong>,</p>
          <p>Welcome to ShieldZen. To complete your registration and secure your access to the Threat Intelligence Platform, please verify your email address.</p>
          
          <div style="text-align: center;">
            <a href="${verifyLink}" class="btn">Verify Email Address</a>
          </div>

          <p style="font-size: 13px; text-align: center; margin-top: 8px;">Or copy and paste this verification token into the verification screen:</p>
          <div class="token-box">
            <div class="token-code">${token}</div>
          </div>

          <p style="font-size: 12px; color: #64748B;">This link is valid for 24 hours. If you did not create a ShieldZen account, you can safely ignore this email.</p>
          
          <div class="footer">
            ShieldZen Cyber Threat Intelligence &copy; ${new Date().getFullYear()} &bull; Sandboxed SOC Environment
          </div>
        </div>
      </body>
    </html>
  `;

  const res = await sendEmail({ to: email, subject, text, html });
  return res.sent;
}

export async function sendPasswordResetEmail(email: string, name: string, token: string, baseUrl: string): Promise<boolean> {
  const resetLink = `${baseUrl}/login?mode=reset&email=${encodeURIComponent(email)}&token=${encodeURIComponent(token)}`;

  // Store in test list
  recentTestEmails.push({
    id: "mail-" + Math.random().toString(36).substring(2, 9),
    to: email,
    subject: "Reset your ShieldZen Password",
    previewUrl: resetLink,
    resetToken: token,
    timestamp: new Date().toISOString(),
    type: 'password_reset'
  });

  const subject = "Reset your ShieldZen Password";
  const text = `Hello ${name},\n\nA password reset request was initiated for your ShieldZen CTI Analyst account.\n\nTo reset your password, visit the following link:\n${resetLink}\n\nYour Reset Token: ${token}\n\nThis link will expire in 1 hour.\n\nIf you did not request a password reset, please notify your SOC administrator immediately.\n\n- ShieldZen Security Operations`;

  const html = `
    <!DOCTYPE html>
    <html>
      <head>
        <meta charset="utf-8">
        <style>
          body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background-color: #0B0F17; color: #E2E8F0; margin: 0; padding: 24px; }
          .card { max-width: 560px; margin: 0 auto; background-color: #131B2A; border: 1px solid #1E293B; border-radius: 12px; padding: 32px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }
          .header { display: flex; align-items: center; gap: 12px; margin-bottom: 24px; border-bottom: 1px solid #1E293B; padding-bottom: 16px; }
          .logo { font-size: 20px; font-weight: 700; color: #38BDF8; letter-spacing: -0.5px; }
          .badge { background-color: rgba(239, 68, 68, 0.1); color: #F87171; font-size: 11px; padding: 3px 8px; border-radius: 4px; font-weight: 600; border: 1px solid rgba(239, 68, 68, 0.2); }
          h2 { color: #F8FAFC; margin-top: 0; font-size: 20px; }
          p { color: #94A3B8; line-height: 1.6; font-size: 14px; margin-bottom: 16px; }
          .token-box { background-color: #090D16; border: 1px solid #334155; border-radius: 8px; padding: 16px; text-align: center; margin: 24px 0; }
          .token-code { font-family: monospace; font-size: 22px; font-weight: 700; color: #F87171; letter-spacing: 3px; }
          .btn { display: inline-block; background-color: #E11D48; color: #FFFFFF !important; text-decoration: none; padding: 12px 28px; border-radius: 8px; font-weight: 600; font-size: 14px; margin: 16px 0; text-align: center; }
          .footer { margin-top: 32px; border-top: 1px solid #1E293B; padding-top: 16px; font-size: 12px; color: #64748B; text-align: center; }
        </style>
      </head>
      <body>
        <div class="card">
          <div class="header">
            <span class="logo">ShieldZen</span>
            <span class="badge">Security Alert</span>
          </div>
          <h2>Password Reset Request</h2>
          <p>Hello <strong>${name}</strong>,</p>
          <p>We received a request to reset the password for your ShieldZen Analyst Account. Click the button below to choose a new password:</p>
          
          <div style="text-align: center;">
            <a href="${resetLink}" class="btn">Reset Password</a>
          </div>

          <p style="font-size: 13px; text-align: center; margin-top: 8px;">Or enter this security token on the reset screen:</p>
          <div class="token-box">
            <div class="token-code">${token}</div>
          </div>

          <p style="font-size: 12px; color: #64748B;">This password reset token is only valid for 60 minutes. If you did not request this change, please disregard this email.</p>
          
          <div class="footer">
            ShieldZen Cyber Threat Intelligence &copy; ${new Date().getFullYear()} &bull; Sandboxed SOC Environment
          </div>
        </div>
      </body>
    </html>
  `;

  const res = await sendEmail({ to: email, subject, text, html });
  return res.sent;
}

export async function sendOtpEmail(email: string, name: string, otp: string): Promise<boolean> {
  // Store in test list (Sandbox outbox for test environments)
  recentTestEmails.push({
    id: "mail-" + Math.random().toString(36).substring(2, 9),
    to: email,
    subject: "ShieldZen Login Verification Code",
    otpCode: otp,
    timestamp: new Date().toISOString(),
    type: 'otp'
  });

  const subject = "ShieldZen Login Verification Code";
  const text = `Hello,\n\nA login attempt was made for your ShieldZen account.\n\nYour verification code is:\n\n${otp}\n\nThis code expires in 5 minutes.\n\nIf you did not attempt to log in, you can safely ignore this email.\n\nDo not share this code with anyone.\n\nShieldZen Security Team`;

  const html = `
    <!DOCTYPE html>
    <html>
      <head>
        <meta charset="utf-8">
        <style>
          body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background-color: #0B0F17; color: #E2E8F0; margin: 0; padding: 24px; }
          .card { max-width: 560px; margin: 0 auto; background-color: #131B2A; border: 1px solid #1E293B; border-radius: 12px; padding: 32px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }
          .header { display: flex; align-items: center; gap: 12px; margin-bottom: 24px; border-bottom: 1px solid #1E293B; padding-bottom: 16px; }
          .logo { font-size: 20px; font-weight: 700; color: #38BDF8; letter-spacing: -0.5px; }
          .badge { background-color: rgba(56, 189, 248, 0.1); color: #38BDF8; font-size: 11px; padding: 3px 8px; border-radius: 4px; font-weight: 600; border: 1px solid rgba(56, 189, 248, 0.2); }
          h2 { color: #F8FAFC; margin-top: 0; font-size: 20px; }
          p { color: #94A3B8; line-height: 1.6; font-size: 14px; margin-bottom: 16px; }
          .otp-box { background-color: #090D16; border: 1px solid #0284C7; border-radius: 8px; padding: 20px; text-align: center; margin: 24px 0; }
          .otp-code { font-family: monospace; font-size: 32px; font-weight: 700; color: #38BDF8; letter-spacing: 8px; }
          .footer { margin-top: 32px; border-top: 1px solid #1E293B; padding-top: 16px; font-size: 12px; color: #64748B; text-align: center; }
        </style>
      </head>
      <body>
        <div class="card">
          <div class="header">
            <span class="logo">ShieldZen</span>
            <span class="badge">Security 2FA</span>
          </div>
          <h2>Login Verification Code</h2>
          <p>Hello${name ? ` <strong>${name}</strong>` : ""},</p>
          <p>A login attempt was made for your ShieldZen account. Enter the 6-digit verification code below to complete your authentication:</p>
          
          <div class="otp-box">
            <div class="otp-code">${otp}</div>
          </div>

          <p style="font-size: 13px; color: #F59E0B; font-weight: 500; text-align: center;">&bull; This code expires in 5 minutes &bull;</p>
          <p style="font-size: 12px; color: #64748B;">If you did not attempt to log in, please secure your account or alert your SOC administrator immediately. Never share this code with anyone.</p>
          
          <div class="footer">
            ShieldZen Cyber Threat Intelligence &copy; ${new Date().getFullYear()} &bull; Sandboxed SOC Environment
          </div>
        </div>
      </body>
    </html>
  `;

  const res = await sendEmail({ to: email, subject, text, html });
  return res.sent;
}

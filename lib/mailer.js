// Sending the sign-in code email, over SMTP (iCloud Mail's, in
// production: smtp.mail.me.com, port 587, STARTTLS, the Apple ID's address
// and an app-specific password). Everything about mail is in this file, so
// moving to another provider is this file and the SMTP_* settings.
//
//   SMTP_HOST, SMTP_PORT (587), SMTP_USER, SMTP_PASS
//   MAIL_FROM   e.g. "Canopy <account@canopysf.com>" -- with iCloud, one
//               of the domain's real addresses (not a wildcard one)
//
// With no SMTP_HOST outside production, codes are printed to the console
// instead, so it can be run locally. In production that's refused.

const nodemailer = require('nodemailer');

const HOST = process.env.SMTP_HOST;
const PRODUCTION = process.env.NODE_ENV === 'production';
const FROM = process.env.MAIL_FROM || process.env.SMTP_USER;

const transport = HOST
  ? nodemailer.createTransport({
      host: HOST,
      port: parseInt(process.env.SMTP_PORT || '587', 10),
      secure: process.env.SMTP_PORT === '465',
      requireTLS: process.env.SMTP_PORT !== '465',
      auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
    })
  : null;

function configured() {
  return !!transport || !PRODUCTION;
}

if (!transport) {
  console.warn(
    PRODUCTION
      ? '[canopy-account] SMTP_HOST is not set: sign-in codes cannot be emailed, so new sign-ups and email recovery will fail.'
      : '[canopy-account] SMTP_HOST not set: sign-in codes will be printed here instead of emailed.'
  );
}

// The code in the subject too, so it can be read off a lock-screen
// notification -- and iOS offers codes from Mail as one-tap fill-ins.
async function sendCode(to, code) {
  const subject = `${code} is your Canopy code`;
  const text =
    `Your Canopy code is ${code}\n\n` +
    "Type it on the page where you entered your email. It works for 10 minutes.\n\n" +
    "If you didn't ask for this, someone typed your email by mistake and you can ignore it.";
  const html =
    '<div style="font-family:-apple-system,BlinkMacSystemFont,Helvetica,Arial,sans-serif;font-size:15px;color:#222">' +
    '<p>Your Canopy code is</p>' +
    `<p style="font-size:30px;font-weight:700;letter-spacing:4px;margin:8px 0 18px">${code}</p>` +
    '<p>Type it on the page where you entered your email. It works for 10 minutes.</p>' +
    '<p style="color:#888;font-size:13px">If you didn\'t ask for this, someone typed your email by mistake and you can ignore it.</p>' +
    '</div>';
  if (!transport) {
    if (PRODUCTION) throw new Error('mail is not configured');
    console.log(`[canopy-account] code for ${to}: ${code}`);
    return;
  }
  await transport.sendMail({ from: FROM, to, subject, text, html });
}

module.exports = { sendCode, configured };

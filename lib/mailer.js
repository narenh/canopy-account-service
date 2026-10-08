// Sending the sign-in code email, and two notices about changing an email,
// over SMTP (iCloud Mail's, in production: smtp.mail.me.com, port 587,
// STARTTLS, the Apple ID's address and an app-specific password).
// Everything about mail is in this file, so moving to another provider is
// this file and the SMTP_* settings.
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

// The code email: a white card under a dark green band with the logo (the
// logo is white on transparent, so it needs the band to show on a white
// email). Tables and inline styles, because that's what mail apps render
// consistently. The code is in the subject too, so it can be read off a
// lock-screen notification, and in the hidden preview line; iOS offers
// codes from Mail as one-tap fill-ins. `logoUrl` is an absolute URL (mail
// apps fetch it from the open web).
function codeEmail(code, logoUrl) {
  const subject = `${code} is your Canopy code`;
  const text =
    `Your Canopy code is ${code}\n\n` +
    'Type it on the page where you entered your email. It works for 10 minutes.\n\n' +
    "Didn't ask for this? Someone typed your email by mistake. You can ignore it.";
  const font = "-apple-system,BlinkMacSystemFont,'Helvetica Neue',Arial,sans-serif";
  const html = `<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#eef3ef;">
<div style="display:none;max-height:0;overflow:hidden;opacity:0;">Your Canopy code is ${code}</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#eef3ef;padding:24px 12px;">
<tr><td align="center">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:480px;background:#ffffff;border-radius:16px;overflow:hidden;font-family:${font};">
  <tr><td align="center" style="background:#1f3b2d;padding:22px 24px 18px;"><img src="${logoUrl}" width="132" alt="Canopy" style="display:block;border:0;width:132px;height:auto;color:#ffffff;font-size:20px;font-weight:700;"></td></tr>
  <tr><td style="padding:28px 28px 8px;color:#1b2a21;font-size:16px;line-height:1.5;">Here's your Canopy code:</td></tr>
  <tr><td align="center" style="padding:8px 28px;">
    <div style="background:#e7f6ea;border:1px solid #bfe5c8;border-radius:12px;padding:16px 0;font-size:36px;font-weight:700;letter-spacing:8px;color:#0f3a1c;font-family:'SF Mono',Menlo,Consolas,monospace;">${code}</div>
  </td></tr>
  <tr><td style="padding:12px 28px 28px;color:#4a5b50;font-size:14px;line-height:1.5;">Type it on the page where you entered your email. It works for 10 minutes.</td></tr>
  <tr><td style="padding:16px 28px 22px;border-top:1px solid #e3ebe5;color:#7b8b80;font-size:12px;line-height:1.5;">Didn't ask for this? Someone typed your email by mistake. You can ignore it.</td></tr>
</table>
</td></tr></table>
</body></html>`;
  return { subject, text, html };
}

async function sendCode(to, code, logoUrl) {
  if (!/^\d{6}$/.test(String(code))) throw new Error('a code is 6 digits');
  const { subject, text, html } = codeEmail(code, logoUrl);
  if (!transport) {
    if (PRODUCTION) throw new Error('mail is not configured');
    // Development only (production never gets here): the address is in the
    // line so a developer, and the tests, can tell whose code it is. These
    // three lines are the only ones in the service that print an email.
    console.log(`[canopy-account] code for ${to}: ${code}`);
    return;
  }
  await transport.sendMail({ from: FROM, to, subject, text, html });
}

// a.b@gmail.com -> a•••@gmail.com: enough for the owner to recognise, not
// enough to hand an address to whoever reads the old inbox.
function maskEmail(email) {
  const [name, domain] = String(email).split('@');
  return `${name.charAt(0)}\u2022\u2022\u2022@${domain}`;
}

// Sent to the OLD address when someone changes their email: the only
// warning its owner gets if it wasn't them. Same look as the code email.
function emailChangedEmail(newEmail, logoUrl) {
  const masked = maskEmail(newEmail);
  const subject = 'Your Canopy email was changed';
  const text =
    `The email on your Canopy Account was changed to ${masked}. Sign-in codes go there now.\n\n` +
    "If that wasn't you, reply to this email or tell the person who runs Canopy, right away.";
  const font = "-apple-system,BlinkMacSystemFont,'Helvetica Neue',Arial,sans-serif";
  const html = `<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#eef3ef;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#eef3ef;padding:24px 12px;">
<tr><td align="center">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:480px;background:#ffffff;border-radius:16px;overflow:hidden;font-family:${font};">
  <tr><td align="center" style="background:#1f3b2d;padding:22px 24px 18px;"><img src="${logoUrl}" width="132" alt="Canopy" style="display:block;border:0;width:132px;height:auto;color:#ffffff;font-size:20px;font-weight:700;"></td></tr>
  <tr><td style="padding:28px 28px 8px;color:#1b2a21;font-size:16px;line-height:1.5;">The email on your Canopy Account was changed to <strong>${masked}</strong>. Sign-in codes go there now.</td></tr>
  <tr><td style="padding:12px 28px 28px;color:#4a5b50;font-size:14px;line-height:1.5;">If that wasn't you, reply to this email or tell the person who runs Canopy, right away.</td></tr>
</table>
</td></tr></table>
</body></html>`;
  return { subject, text, html };
}

async function sendEmailChanged(oldEmail, newEmail, logoUrl) {
  const { subject, text, html } = emailChangedEmail(newEmail, logoUrl);
  if (!transport) {
    if (PRODUCTION) throw new Error('mail is not configured');
    console.log(`[canopy-account] email-changed notice for ${oldEmail}: now ${maskEmail(newEmail)}`);
    return;
  }
  await transport.sendMail({ from: FROM, to: oldEmail, subject, text, html });
}

// Sent instead of a code when someone signed in asks to change their
// email to an address that already has an account. The one asking gets the
// same answer as for any address (server.js, "Changing your own email"),
// and this inbox's owner hears that someone tried. Nothing about who.
function addressInUseEmail(logoUrl) {
  const subject = 'Someone tried to use this email on Canopy';
  const text =
    'Someone signed in to Canopy asked to change their account\'s email to this one. ' +
    'This email already has a Canopy Account, so nothing was changed.\n\n' +
    "If it was you, sign in with this email to use the account it already has. If it wasn't, you can ignore this.";
  const font = "-apple-system,BlinkMacSystemFont,'Helvetica Neue',Arial,sans-serif";
  const html = `<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#eef3ef;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#eef3ef;padding:24px 12px;">
<tr><td align="center">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:480px;background:#ffffff;border-radius:16px;overflow:hidden;font-family:${font};">
  <tr><td align="center" style="background:#1f3b2d;padding:22px 24px 18px;"><img src="${logoUrl}" width="132" alt="Canopy" style="display:block;border:0;width:132px;height:auto;color:#ffffff;font-size:20px;font-weight:700;"></td></tr>
  <tr><td style="padding:28px 28px 8px;color:#1b2a21;font-size:16px;line-height:1.5;">Someone signed in to Canopy asked to change their account's email to this one. This email already has a Canopy Account, so nothing was changed.</td></tr>
  <tr><td style="padding:12px 28px 28px;color:#4a5b50;font-size:14px;line-height:1.5;">If it was you, sign in with this email to use the account it already has. If it wasn't, you can ignore this.</td></tr>
</table>
</td></tr></table>
</body></html>`;
  return { subject, text, html };
}

async function sendAddressInUse(to, logoUrl) {
  const { subject, text, html } = addressInUseEmail(logoUrl);
  if (!transport) {
    if (PRODUCTION) throw new Error('mail is not configured');
    console.log(`[canopy-account] address-in-use notice for ${to}`);
    return;
  }
  await transport.sendMail({ from: FROM, to, subject, text, html });
}

module.exports = {
  sendCode, codeEmail, sendEmailChanged, emailChangedEmail, sendAddressInUse, addressInUseEmail, maskEmail, configured
};

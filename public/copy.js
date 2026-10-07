// Every sentence the account pages say out loud, in one place -- the same
// arrangement as tickets' public/copy.js.
//
// EDITING: change the text between the quotes, save, reload the page.
// There's no build step.
//
// {braces} are placeholders the code fills in. Keep the name spelled
// exactly as it appears ({email}, {name}) or it'll show through to the
// page verbatim; move it anywhere in the sentence, or drop it.
//
// NOT here, on purpose: one- and two-word button labels (Save, Cancel,
// Remove), which live next to the buttons they name, and anything only a
// developer sees.
const COPY = {

  // ---------------- Sign in / sign up, at / ----------------
  welcome: {
    title: 'Canopy',
    tagline: 'Sign in with your passkey, or enter your email to get started.',
    // Arriving from another Canopy page's "Continue with email" (?email).
    taglineEmail: "New here, or no passkey on this phone? Enter your email and we'll send you a code.",
    // First run: the setup password is ADMIN_PASSWORD from the server's settings.
    adminSetupHeading: 'Set up your admin account',
    adminSetupHint: 'Enter the setup password to set up your admin account.',
    adminSetupLink: 'Admin setup',
    back: 'Back',
    wrongSetupPassword: "That isn't the setup password.",
    taglineAdmin: 'Now sign in with your passkey, or enter your email to create your account. That account becomes the admin.',
    signIn: 'Sign in with passkey',
    or: 'or',
    continueEmail: 'Continue with email',
    // The emailed code.
    codeHeading: 'Check your email',
    codeHint: 'We sent a 6-digit code to {email}. It works for 10 minutes.',
    codePlaceholder: '6-digit code',
    wrongCode: "That isn't the code. Check the email and try again.",
    codeExpired: 'That code has run out. Send a new one.',
    resend: 'Send a new code',
    resent: 'Sent. Check your email.',
    mailFailed: "Couldn't send the email. Try again in a minute.",
    // A new account.
    profileHeading: 'Create Account',
    signUpHint: "Next, your phone will offer to save a passkey for Canopy. That's how you'll sign in.",
    // An email that already has an account.
    welcomeBack: 'Welcome back, {name}',
    existingHint: "Save a passkey on this phone and you're in. It'll work on every Canopy site.",
    existingHintHasPasskey: 'Sign in with your passkey, or save a new one on this phone (a new phone, or a lost one).',
    newPasskey: 'Save a passkey on this phone',
    // Passkey trouble.
    tooMany: 'Too many tries. Wait a few minutes.',
    passkeyExists: 'This phone already has a passkey for this account. Sign in with it instead.',
    unknownPasskey: "That passkey isn't linked to an account anymore. Continue with your email to set up a new one.",
    expired: 'That took too long. Try again.',
    noPasskeys: "This browser can't use passkeys. Open this page in Safari or Chrome.",
    badEmail: "That doesn't look like an email address.",
    emailTaken: 'That email already has an account. Go back and continue with it.',
    failed: 'Something went wrong. Try again.',
    unreachable: 'Could not reach the server. Try again.',
    // The photo.
    cropHint: 'Pinch and drag to fit your face in the circle.',
    photoLoading: 'Loading photo… (one stored in iCloud can take a moment)',
    photoUnreadable: "Couldn't open that photo. If it's stored in iCloud, open it in Photos so it downloads, then try again — or pick another.",
    photoRequired: 'A profile picture is required.',
    nameRequired: 'Enter your first and last name.',
    badVenmo: 'A Venmo username is letters, numbers, - and _ only.'
  },

  // ---------------- A setup link from the admin, at /setup/<code> ----------------
  setup: {
    heading: 'Hi, {name}',
    hint: "Save a passkey on this phone and you're in. It's how you'll sign in to every Canopy site.",
    button: 'Save a passkey',
    badLink: 'This link has been used or has run out. Ask for a new one, or sign in with your email.',
    goSignIn: 'Go to sign in'
  },

  // ---------------- Your profile, at /profile ----------------
  profile: {
    heading: 'Your Account',
    changeEmail: 'Change',
    changeEmailHeading: 'Change your email',
    changeEmailPasskeyHint: "First, confirm it's you with your passkey.",
    changeEmailPasskey: 'Confirm with passkey',
    changeEmailPasskeyFailed: "That passkey couldn't be checked. Try again.",
    changeEmailAgain: "That took a while. Confirm it's you again.",
    changeEmailAddressHint: "Your new email. We'll send a code to it, and tell your old one about the change.",
    changeEmailSend: 'Send code',
    sameEmail: "That's already your email.",
    emailUnavailable: "That email can't be used.",
    emailChanged: 'Email changed.',
    firstName: 'First name',
    lastName: 'Last name',
    // US and Canadian numbers don't need the +1.
    phone: 'Phone',
    instagram: 'Instagram',
    venmo: 'Venmo',
    cashapp: 'Cash App',
    badInstagram: 'An Instagram username is letters, numbers, . and _ only.',
    badCashapp: 'A $cashtag is letters, numbers, - and _ only, with at least one letter.',
    badPhone: "That doesn't look like a phone number. Outside the US and Canada, start with + and the country code.",
    saved: 'Saved.',
    failed: "Couldn't save. Try again.",
    photoHint: 'Tap your photo to change it.',
    passkeysHeading: 'Passkeys',
    passkeyAdded: 'Added {date}',
    passkeyUsed: 'last used {date}',
    passkeyNeverUsed: 'not used yet',
    passkeySynced: 'synced',
    passkeyDeviceOnly: 'this device only',
    removeConfirm: 'Remove this passkey? The device it’s on won’t be able to sign in with it any more.',
    lastPasskey: "That's your only passkey. Add another before removing it.",
    addPasskey: 'Add a passkey',
    added: 'Passkey added.',
    signOut: 'Sign out of all Canopy sites',
    // The admin's way back from their own profile.
    admin: 'Back to manager'
  },

  // ---------------- The admin, at /admin ----------------
  admin: {
    heading: 'Account Manager',
    myProfile: 'My Profile',
    peopleTab: 'People',
    sitesTab: 'Sites',
    settingsTab: 'Settings',
    peopleHint: 'Everyone with a Canopy account. Deleting someone keeps their history on every site, as a former member.',
    adminTag: 'Admin',
    noPasskey: 'no passkey',
    passkeysOne: '1 passkey',
    passkeysMany: '{count} passkeys',
    editProfile: 'Edit profile',
    editHeading: 'Edit {name}',
    email: 'Email',
    emailHint: "Changing someone's email counts it as unconfirmed until they next get a code there.",
    emailTaken: 'That email already has an account.',
    resetPasskeys: 'Reset passkeys',
    setupLink: 'Setup link',
    resetConfirm: "Reset {name}'s passkeys? They'll be signed out everywhere, and you'll get a link to send them to set up a new one.",
    deleteConfirm: "Delete {name}'s account? Every Canopy site keeps their history, shown as a former member. This can't be undone.",
    linkHeading: 'Setup link for {name}',
    linkHint: 'Send them this. It works once, for 24 hours, and only the newest link works.',
    copy: 'Copy',
    copied: 'Copied',
    sitesHint: 'Each Canopy site that asks who is signed in has its own key. A key is shown once, when it’s made.',
    siteName: 'Site name (e.g. tickets)',
    addSite: 'Add site',
    keyHeading: 'Key for {name}',
    keyHint: 'Set this as CANOPY_ACCOUNT_KEY on that site. It won’t be shown again.',
    rekey: 'New key',
    rekeyConfirm: "Make a new key for {name}? The old one stops working right away, until the site has the new one.",
    revoke: 'Cut off',
    revokeConfirm: "Cut {name} off? It won't be able to see who's signed in until it gets a new key.",
    revoked: 'cut off',
    lastUsed: 'last used {date}',
    neverUsed: 'not used yet',
    logoHeading: 'Logo',
    logoHint: 'Shown at the top of the sign-in page. A PNG with a transparent background works best.',
    backdropHeading: 'Sign-in backdrop',
    backdropHint: 'Fills the screen behind the sign-in card, in place of the green background.',
    upload: 'Upload',
    removeImage: 'Remove',
    removeImageConfirm: 'Remove this image? The logo goes back to the Canopy logo; the sign-in page goes back to its plain background.',
    failed: 'Something went wrong. Try again.'
  }
};

// COPY.welcome.codeHint, with {braces} swapped for values:
//   t('welcome.codeHint', { email: 'a@b.co' })
// A missing key returns the path itself rather than "undefined", so a
// typo shows up on the page as the thing to go and fix.
function t(path, vars){
  let node = COPY;
  for (const key of path.split('.')){
    if (node == null || typeof node !== 'object') return path;
    node = node[key];
  }
  if (typeof node !== 'string') return path;
  if (!vars) return node;
  return node.replace(/\{(\w+)\}/g, (whole, name) =>
    Object.prototype.hasOwnProperty.call(vars, name) ? String(vars[name]) : whole);
}

// Fills every <element data-copy="some.path"> with its line.
function applyCopy(root){
  (root || document).querySelectorAll('[data-copy]').forEach(el => {
    el.textContent = t(el.getAttribute('data-copy'));
  });
}

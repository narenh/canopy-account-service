# Canopy Accounts

`account.canopysf.com`. It answers the same three questions for every
Canopy site (canopy-tickets first, whatever comes next after it): **who
is this**, **what's their name and photo**, and **are they signed in**.

- At **`/`** people sign in with a **passkey** (Face ID / Touch ID / the
  phone's screen lock), or type their **email** and get a 6-digit code.
  A new email goes on to make an account: first and last name, a photo,
  an optional Venmo username, and a passkey. An email that already has
  an account goes on to make a new passkey on this phone. That's what a
  lost or new phone does, and nobody has to ask the admin for it.
- At **`/?quick=1`**, the **quick sign-up**, someone new gives their
  first and last name and email and makes a passkey, with no code and no
  photo. The account is **unverified** until they prove the email with a
  code, and only sites the admin marks as allowing it treat them as
  signed in until then (see "Quick sign-up").
- At **`/profile`** they change their name, photo, phone, Instagram,
  Venmo and Cash App, choose whether **people who know their phone number
  or Instagram can find them** (on unless they turn it off), see their
  passkeys (add one, remove one they've
  lost), see **where they're signed in** (each browser and app, with
  **Sign out** on any of them, and **Sign out everywhere**) and sign out.
  **Changing their email** takes three steps: their
  passkey (Face ID or the like, so a borrowed unlocked phone or a stolen
  cookie isn't enough; good for 15 minutes and one change), a code sent
  to the new address and typed back, and then a notice to the old
  address with the new one masked (`a•••@domain`), the only warning its
  owner gets if it wasn't them. A new address that already has an
  account answers exactly like one that doesn't (see "With an email and
  a code"), and only the code step says it's taken. An unverified
  account gets a banner that can't be closed, with **Confirm email** (a
  code sent there, typed back). `/profile?verify=1&return=…` opens straight into that and goes
  back afterwards. The admin lands on the Account Manager
  after signing in, with **My Profile** to their own and **Back to
  manager** from it.
- At **`/admin`**, the **Account Manager**, the admin sees everyone (the
  admin first, then by name, with an **Unverified** badge on anyone whose
  email isn't proven) and can **Edit profile** (every field above except
  the photo, plus the email: a changed email is unverified until its
  owner types a code sent there), reset passkeys, send a setup link or
  delete; the **Sites** allowed to ask about people, each with switches
  for whether it **allows quick (unverified) accounts** and whether it
  **can find people by phone number or Instagram**; and the sign-in
  page's logo and backdrop (each can be removed again).
- The **iOS and Android apps** sign in through `/api/native/v1`, with
  the same passkeys, codes and quick sign-up, and get a token to send as
  `Authorization: Bearer` (see "Apps").
- Every Canopy site asks it, server to server, who the visitor is
  (`GET /api/session`), what other people are called
  (`GET /api/people`), and, if it's allowed to, who has a phone number or
  Instagram someone typed (`GET /api/people/lookup`). `client/canopy-account.js` is the one file a site
  copies in to do that.

Signing in on one Canopy site signs you in on all of them, because the
session cookie belongs to `canopysf.com` rather than to any one
subdomain. Signing out signs you out of all of them, for the same reason.

**What this isn't.** It isn't an OAuth / OpenID Connect provider. There
are no redirect dances, no tokens handed to other domains, no consent
screens. It only works for sites under `canopysf.com`, because it relies
on the browser sharing one cookie between them. (The apps get a token,
but it's the same session a cookie names, for Canopy's own apps only.) There are no passwords
for anyone (the one setup password is for the admin and the server, see
"The first admin"). The only emails it sends are sign-in codes and, when
someone changes their email, a notice to the old address (or, for an
address that already has an account, a notice there instead of a code). It doesn't
hold any site's own data either: tickets' seats, orders and calendar
feeds stay in tickets, keyed by the person ids from here.

## How it works

- `server.js` is the Express app, every route in one file: sign-in and
  sign-up, the first admin and recovery, signing out, the profile,
  photos, the apps' routes (the same handlers again, under
  `/api/native/v1`), the admin's JSON, the site API, and the pages. It also has the
  two checks every request goes through, the response headers (no
  framing, no MIME sniffing, no full URLs in `Referer`) and the Origin
  check (below), and it holds the guess limits with their exact numbers.
- `lib/db.js` is persistence: one SQLite file, `DATA_DIR/account.db`.
  Its tables are `people`, `passkeys`, `sessions` (one per browser, keyed
  by the hash of its cookie), `setup_links` (hashed), `apps` (the sites,
  with hashed keys) and `meta` (who the admin is). The schema version
  lives in SQLite's `user_version`. A database from a version this code
  doesn't know is refused at startup rather than opened. It also takes
  the daily snapshots (see "Storage & backups").
- `lib/session.js` is the `canopy_session` cookie: reading it, the
  `Set-Cookie` that makes or renews it, and when it's due for renewal.
  It also reads an app's `Authorization: Bearer` token, and names a
  browser from its `User-Agent`.
- `lib/domain.js` is the one answer to "is this a Canopy address?": who
  may make changes here (the Origin check), where `?return=` may send
  someone, the cookie's `Domain`, which domain passkeys belong to, and
  which apps may use them (`ANDROID_APK_KEY_HASHES`).
- `lib/limits.js` holds the in-memory try counters behind the guess
  limits, and `clientIp()`, the visitor's address (Cloudflare's
  `CF-Connecting-IP` when it's there).
- `lib/mailer.js` sends the code email and the two email-change notices
  over SMTP (iCloud Mail, see "Email: iCloud SMTP"). Everything about
  mail is in this one file, so
  moving to another provider means changing this file and the `SMTP_*`
  settings.
- `lib/photoStore.js` stores profile photos, one square JPEG per person
  in `DATA_DIR/photos/<id>.jpg`. The browser has already cropped and
  shrunk it (`public/photo-crop.js`), so what's on disk is small and
  carries none of the original's EXIF, location included. An app crops
  its own, so every JPEG's metadata is also taken out here before it's
  saved (`withoutMetadata`).
- `lib/uploadedImage.js` stores the admin's uploaded logo and sign-in
  backdrop as files in `DATA_DIR`.
- `client/canopy-account.js` is the file Canopy sites copy in (see "For
  Canopy sites").
- `openapi.yaml` is the apps' contract (OpenAPI 3.1, served at
  `/api/native/v1/openapi.yaml`), and `docs/native-api.md` the guide for
  the people writing the apps. `docs/well-known/` has the two files
  `canopysf.com` serves so the apps may use its passkeys (see "The
  association files").
- `views/` and `public/` are the pages: `welcome.html` (sign in / sign
  up), `profile.html`, `setup.html` (a setup link), `admin.html`, and
  the shared `account.js`, `account.css`, `copy.js` (every sentence the
  pages say, as in tickets) and `photo-crop.js`. Cropper.js and the
  SimpleWebAuthn browser library are vendored in `public/vendor/`. The
  server puts each page's scripts and stylesheet inline when it sends
  the page. Tickets learned why: Cloudflare gives `.js` files a 4-hour
  browser cache whatever the server says, and during a deploy a phone
  could get the old script with the new page. With no logo uploaded,
  pages show the Canopy logo that ships in `public/canopy-logo.png`.
- `test/` uses `node:test`. Each file starts the real server in a child
  process on a scratch `DATA_DIR`. `test/softAuthenticator.js` is a
  software passkey, so the real `@simplewebauthn/server` checks run end
  to end with no browser, and it signs as a page or as the iOS or
  Android app. `test/docs.test.js` fails if a route under
  `/api/native/v1` is missing from `openapi.yaml` or the other way
  around (its one dev dependency, `yaml`, reads the spec). `npm test`
  runs them all.

`GET /healthz` answers `{"ok":true}`, and `GET /favicon.ico` answers an
empty 204, so pages don't log a 404 for the icon they don't have.

## Signing in

Passkeys are the way in. Everything else here exists to get someone a
passkey.

**Passkeys belong to `canopysf.com`** (override with `PASSKEY_RP_ID`), not
to `account.canopysf.com`. So one passkey signs in from any Canopy
subdomain. Phones list them as "Canopy". On any other host (localhost, in development) they're made for
that host. The server keeps only each passkey's public key. Nothing in
the database can sign anyone in.

### With a passkey

"Sign in with passkey" asks for no email. The phone offers whichever
Canopy passkey it has, and iCloud Keychain or Google Password Manager
will have synced it to the person's other devices. A passkey that's been
removed or reset, or that belongs to a deleted account, is told it's no
longer linked to an account.

### With an email and a code

Type an email and a 6-digit code is sent to it. **Every** email gets a
code, account or not. The page says nothing about whether an account
exists until the code has been typed, so it can't be used to find out
who has an account here.

**The quick sign-up doesn't hold to that.** It sends no code, so when an
email already has an account (verified or not) the only honest answers
are to say so or to fail without a reason. It says so: "this email has
an account, sign in instead". That tells anyone who tries an email
whether it has a Canopy account. We accept that leak in exchange for a
sign-up with no code. The tries are counted and limited (see "Guess
limits"), so it can't be run down a long list of emails.

**Changing an email holds to it.** Someone signed in who changes their
email to an address that already has an account gets exactly the answer
anyone else gets (`200`, "we sent a code"), from exactly the same work:
the try is counted, a code is set up on their session, and one email
goes out. For an address with no account that email is the code. For one
with an account it's a short notice instead ("someone tried to change
their Canopy account's email to this one; this email already has an
account, so nothing was changed"), with no code in it. Only the code
step says the address is taken (`409 email_unavailable`), and the code
only ever went to that inbox, so whoever can type it is its owner and
already knew. This used to answer `409 "can't be used"` straight away,
before any limit, which made one passkey check good for 15 minutes of
unlimited "does this email have an account?" questions.

Why a notice rather than sending nothing: sending nothing would be
quicker to answer than an SMTP round trip, and that difference in timing
could say what the answer doesn't. With a notice the work is one email
either way, and a mail outage fails both the same way (`502`). It also
tells the address's owner that someone tried, and if that was them (with
two accounts), why nothing happened. It can't be used to flood an inbox:
it's counted with the codes, 5 an hour per address (see "Guess limits"),
the same as anyone can already send by typing that address on the
sign-in page.

- A code is good for **10 minutes** and **5 wrong tries**, after which
  only a new code works. Sending a new one replaces the old one on that
  browser. Only a hash of the code is stored, salted with the browser's
  session.
- The right code proves the address **on this browser for 15 minutes**.
  That's the time it takes to fill in a profile and make a passkey.
- **A new email** goes on to first and last name (both required), an
  optional Venmo username, and a passkey. The account is only made once
  the passkey exists, so there's never an account nobody can get into.
  The photo is uploaded right after.
- **An email with an account** goes on to make **a new passkey** for that
  account, on this phone. That covers a new phone, a lost phone, a
  browser that doesn't sync, and anyone whose passkeys the admin reset. It's self-serve on purpose: whoever can read the
  account's email can get in, and the admin doesn't have to be awake.
  It also proves the email, so an unverified account becomes verified
  (see "Proving the email").

That last point is the real security boundary. **An account is exactly
as safe as its email inbox**, plus the odds of guessing a 6-digit code
inside the limits below. Those odds are worked out under "Guess limits".

### Quick sign-up

For someone opening a link from a site that allows it (events), who has
never used Canopy. Sites link to `/?quick=1&return=…`
(`canopy.quickSignUpUrl()`). The page asks for first name, last name
and email, then the phone offers to save a passkey, and they're back at
`?return=`. There's no code and no photo. Under the form, "Already have a
Canopy account? Sign in" goes to the usual page.

- **The passkey is still required.** The account is made only once the
  passkey verifies, the same as every other sign-up, so there's never an
  account nobody can get into.
- **An email that already has an account**, verified or not, is told so,
  with **Sign in with passkey** and **Email me a code** (the usual code
  flow, already filled in). That's the accepted leak above.
- **The account is unverified** (`email_verified_at` is null) until its
  owner proves the email with a code. Until then it's signed in only on
  sites the admin has marked **Allows quick (unverified) accounts**.
  Every other site sees `{"person": null, "unverified": true}` and sends
  them to prove it (see "For Canopy sites"). That's decided here, from
  the site's key, and never trusted to the site.
- Unverified people can still use their own profile here. They can never
  open `/admin`.
- It only works once there's an admin.
- The usual page at `/` doesn't link to it. It already makes accounts,
  with a code, and pointing people from there to a weaker account would
  only make more unverified ones. Sites that want quick sign-ups link to
  `?quick=1` themselves.

### Proving the email

An account's email is proven when someone types a code sent to it. That
happens three ways, and each one marks the account verified:

- **Confirm email on the profile.** An unverified account's profile has
  a banner that can't be closed. **Confirm email** sends a code to the
  account's own address, and typing it back marks it verified. Sites send
  people to `/profile?verify=1&return=…` (`canopy.verifyUrl()`), which
  opens straight into it and goes back to `return` afterwards (straight
  back, if they're already verified). Signed out, they sign in first and
  come back to it. It uses the same codes and the same limits as signing
  in.
- **Signing in by code** ("an email with an account" above).
- **Changing their email** from the profile. The new address is proven
  by its code, so the account ends up verified whether it was before or
  not.

**Signing in by code takes an unverified account over.** Anyone can make
a quick sign-up with someone else's email, keep the passkey, and wait.
If the real owner later signs in by code and gets a new passkey added
next to the squatter's, the squatter would be in a verified account,
reading whatever the owner puts in it. So when a code proves the email
of an account that wasn't verified, every passkey it had is removed and
every other browser is signed out, and the inbox's owner is left with
the only passkey. The page says so before they make it. The cost falls
on a real quick sign-up who signs in by code on a second device instead
of using their passkey: their first phone is signed out and needs a code
too. Confirming from the profile doesn't do this, because that's someone
already signed in to the account.

**An email the admin changes is unverified** until its owner types a code
sent there. The admin can't vouch for an address on someone's behalf, and
an address typed by someone else is exactly the one that hasn't been
shown to work. Until then sites that don't allow unverified accounts see
them as signed out, and their profile asks them to confirm it. The
admin's own email isn't changed from Edit profile (`409`, `"reason":
"own_email"`): that would leave the admin unverified and shut out of
`/admin`. They change it from their own profile, with a passkey and a
code, like anyone.

### Setup links

The fallback, for when someone can't get the email. In the admin's
People tab:

- **Reset passkeys** (a lost phone, and the person wants the old one cut
  off): deletes all their passkeys, signs them out on every browser, and
  gives the admin a setup link to send them.
- **Setup link** makes a link without taking anything away, for someone
  who never made a passkey or whose link ran out.

A link is `https://account.canopysf.com/setup/<code>`. It's good for **24
hours** and **one use**, and **only the newest one works**: making a
new link for someone kills any earlier one they still had. The code is
32 random bytes and only its hash is stored. Opening it makes a passkey
for the person it was made for, and signs that browser in as them.
Pages send `Referrer-Policy: same-origin`, so the link's address doesn't
leak to other sites through `Referer`.

The admin's own row can't be reset or deleted. Either would lock the
admin out of the admin page.

### After any of these

The browser is signed in under a **new session token**. Whatever cookie
it had before is worthless afterwards, so a token someone saw before
sign-in (on a shared computer, say) doesn't become a signed-in one.

### The first admin, and recovery

The admin is a person like anyone else, with the same passkeys and the
same sign-in, marked in `meta` as `admin_person_id`. This works the same
way as tickets.

- **There is never an account without an admin.** On a brand-new install
  the sign-in page asks only for the **setup
  password**, `ADMIN_PASSWORD`, and the server refuses every other
  sign-in and sign-up until it's been entered. Entering it is good for
  15 minutes on that browser. Whoever then signs up there is the admin.
  The email for that first account needs no code, because the setup
  password is the stronger proof, and mail may not be set up yet. With
  no `ADMIN_PASSWORD` set, the server makes up a random one at startup
  and prints it in the log.
- **After that** the setup password does nothing, unless:
- **`ADMIN_RECOVERY=1`**, for an admin who has lost every passkey **and**
  can't get the emailed code. Set it in Coolify and redeploy. The sign-in
  page shows a small **Admin setup** link. After the setup password,
  the admin's own email counts as proven without a code, and they make a
  new passkey. It only ever adds a passkey to the admin's own account. It
  can't make anyone else the admin or skip the code for anyone else's
  email. Remove the setting afterwards. It takes access to the server's
  settings, which is the right bar for the keys to everything.
- Wrong setup passwords are limited (see "Guess limits").

An admin who has only lost their phone doesn't need any of that. Their
email gets a code like anyone's.

### Deleted accounts

Deleting someone from the admin deletes their passkeys, every session
(signed out everywhere), any setup links, and their photo. Their id
simply stops existing here. Each site keeps its own records under that
id, and when `/api/people` leaves an id out, the site shows that person
as a **former member**. No one is notified.

## The session cookie

`canopy_session` is a random token, 32 bytes from the OS's random source
(43 characters, base64url), naming one row in `sessions`. Its attributes
are:

- `Domain=canopysf.com`, so every Canopy subdomain gets it. That's the
  whole trick behind "sign in once". (Locally there's no `Domain`, and
  the browser keeps it to that host.)
- `HttpOnly`, so no page script can read it.
- `Secure` in production, so it only travels over https.
- `SameSite=Lax`, so other websites' requests don't carry it, except a
  plain top-level link someone clicks.
- `Max-Age` of a year, renewed: any response more than a day after the
  cookie was last sent carries a fresh one with a new year on it. Sites
  renew it too (see "For Canopy sites"), so someone who only ever visits
  tickets stays signed in.

On the server, a signed-in session lasts a year from when it was last
seen. One that never signed in (a sign-in started and abandoned) lasts
a day.

**Where you're signed in.** Each session remembers what it is: a browser
(named from its `User-Agent` when it signs in, like "Safari on iPhone")
or an app (named by the app, see "Apps"). The profile lists them, most
recently seen first, and any of them can be signed out from there, or
all of them at once with **Sign out everywhere**. Someone who left a
laptop signed in somewhere, or lost a phone, doesn't need the admin for
that. `GET /api/profile/sessions` is the list (`{id, kind, name,
signedInAt, lastSeenAt, current}`), `DELETE /api/profile/sessions/:id`
signs one out, and `POST /api/signout/everywhere` signs out all of them.
The `id` is derived from the session's hash, never the hash itself. The
name is only a label: anything can send any `User-Agent`, so nothing
else depends on it.

**Why only its hash is stored.** The database keeps the token's SHA-256,
never the token. A copy of `account.db` gets made all the time: the
daily snapshots, Coolify's volume backups, a copy pulled down to look at
something. With the plain token in it, any of those copies would be a
pocketful of working sign-ins. With the hash, it's useless for that,
because there's no getting from the hash back to the cookie. The same
goes for the other secrets: setup link codes, site keys and emailed
codes are all stored as hashes.

**Every Canopy site's server sees the cookie.** It's sent to all of
`canopysf.com`, and the sites pass it on to `/api/session`. That's fine
because every Canopy site is ours, but it means a Canopy site has to be
trusted with sessions. A subdomain you wouldn't trust with that
shouldn't live under `canopysf.com`.

## Apps

The iOS and Android apps (Canopy Events first) sign in here, with the
same passkeys, emailed codes and quick sign-up as the web, and come away
with a **token**: a `canopy_session` value, exactly like a browser's
cookie, which the app keeps in the Keychain (iOS) or the Keystore
(Android) and sends as `Authorization: Bearer <token>`, both to Canopy
sites (which pass it to `/api/session` as they would a cookie) and to
this service. `docs/native-api.md` walks app developers through every
step, and `openapi.yaml` (served at `/api/native/v1/openapi.yaml`) is the
contract.

- **Everything is under `/api/native/v1`, and every step is the web's
  own code.** The route handlers for signing in, signing up, the profile,
  passkeys, changing and proving the email, and where you're signed in
  are mounted a second time there. So the rules are the web's by
  construction rather than by copy: the takeover of an unverified
  account, the reauth before an email change, the last passkey that
  can't be removed. So are the limits: the same counters, so an email's
  5 codes an hour are 5 whether they were asked for in a browser, an
  app, or both.
- **A sign-in with no cookie.** A browser keeps a sign-in that's under
  way on its session row (the challenge, the emailed code, the proven
  email), found by its cookie. An app starts with `POST auth/begin`,
  which makes a fresh session row that isn't signed in and answers its
  token as `ceremony`. The app sends that as its bearer token at each
  step. The step that signs in (a passkey, or the passkey that finishes
  a sign-up) signs that row in under a **new** token, as a browser's is,
  and answers it as `token`; the ceremony value is worthless from then
  on. A ceremony nobody finishes runs out in a day, like a browser's
  abandoned sign-in.
- **The token is a session like any other.** It's one row in `sessions`,
  stored as its hash, good for a year from when it was last used. Any use
  keeps it alive: the app's own calls here, or a site's `/api/session`
  with it. There's no renewing to do, since there's no cookie whose
  `Max-Age` runs out, so a bearer answer from `/api/session` never has a
  `renewCookie`. Whatever ends a session ends it: **Sign out** in the app
  (`POST signout`), the profile's list of where you're signed in, **Sign
  out everywhere**, the admin's reset and delete, and the takeover rule.
- **One per app install.** An app that's signed in signs out before it
  signs in again: a sign-in step sent with a signed-in token is refused
  (`409 signed_in`), so a token is never turned into someone else's.
- **What the app is called.** `auth/begin` takes `platform` (`ios` or
  `android`), and optionally `app` and `device`, which make the name in
  the person's list ("Canopy Events on iPhone").
- **Photos.** `GET /photo/<id>` (every `photoUrl`) takes the bearer token
  as well as the cookie, so the apps can show photos too. A bearer header
  decides alone: a malformed or unknown one is nobody, whatever cookie
  came with it. An app's upload has to be a JPEG, and its metadata is
  taken out before it's saved (see "How it works").
- **Passkeys from the apps.** The phone signs each passkey use with
  where it happened. The iOS app's is `https://canopysf.com` (the
  passkey domain), and an Android app's is `android:apk-key-hash:` and
  the hash of the certificate the app was signed with. The app routes
  accept those as well as Canopy pages; the web's routes still only
  accept Canopy pages. Android apps are trusted by listing their hashes
  in `ANDROID_APK_KEY_HASHES`, and none is until one is. Both platforms
  also need a file on `canopysf.com` saying the app may use its passkeys
  (see "The association files").
- **Not in the apps:** the admin, the setup password, recovery and setup
  links. Those stay on the web. An app can't sign anyone in until there's
  an admin (`403 setup_required`).

## The association files

A phone only lets an app use a website's passkeys when the website says
the app is its own. Passkeys here belong to `canopysf.com`, so that's
where the two files go, not `account.canopysf.com`. `canopysf.com` is the
static site deployed from its own repo, so this repo only keeps
ready-to-copy versions in `docs/well-known/`:

- **`apple-app-site-association`** names the iOS app as one that may
  use the domain's passkeys (`webcredentials`), by its team and bundle
  id: `UC3Y84QJ83.com.canopysf.CanopyEvents`. The app has the matching
  entitlement, `webcredentials:canopysf.com`.
- **`assetlinks.json`** does the same for Android
  (`delegate_permission/common.get_login_creds`). The package name
  (`com.canopysf.events`) and the all-zero fingerprint in it are
  **placeholders** until the Android app exists: put in its real package
  name and the SHA-256 fingerprint of the certificate it's signed with
  (with Play App Signing, the app signing key's from the Play Console,
  not the upload key's), and put the same fingerprint in
  `ANDROID_APK_KEY_HASHES` here. A debug build signs with a different
  certificate, so it needs its own entry in both, or it can't sign in.

Where they go, and what both platforms insist on:

- At exactly `https://canopysf.com/.well-known/apple-app-site-association`
  (no `.json` on that one) and
  `https://canopysf.com/.well-known/assetlinks.json`.
- Served as **`Content-Type: application/json`**, with a 200. Google
  says so outright and fails anything else; Apple's own pages have said
  it at times, and it costs nothing. A static host sends a file with no
  extension as `application/octet-stream`, so it has to be told. On
  Cloudflare Pages that's a `_headers` file at the top of the site:

  ```
  /.well-known/apple-app-site-association
    Content-Type: application/json
  /.well-known/assetlinks.json
    Content-Type: application/json
  ```

- **No redirects.** Both are fetched from `https://canopysf.com/...`
  and neither platform follows a 301 or 302. So the bare domain can't
  redirect to `www`, or anywhere else, for these paths. Over https, with
  a real certificate.
- Nothing in the way: no Cloudflare challenge page, no login, and if
  there's a `robots.txt`, it allows `/.well-known/`.

**Apple's CDN.** Phones don't fetch the Apple file from `canopysf.com`
(since iOS 14). Apple's CDN fetches it, within a day of an app install
asking for it, and phones check for changes about once a week. So a
change can take days to reach phones, and a broken file stays broken
that long. While developing, the app's entitlement can say
`webcredentials:canopysf.com?mode=developer`, which goes straight to the
site, on a phone with Developer Mode on, for a development-signed build
only. What the CDN has: `curl
https://app-site-association.cdn-apple.com/a/v1/canopysf.com`.

**Checking them.** `curl -sI` each URL above: a `200`, `content-type:
application/json`, no `location:`. For Android, Google's own reading of
it: `https://digitalassetlinks.googleapis.com/v1/statements:list?source.web.site=https://canopysf.com&relation=delegate_permission/common.get_login_creds`.

## The Origin check

Every request that changes something (anything but GET, HEAD or OPTIONS)
has to carry an `Origin` header for a page on `canopysf.com` or one of
its subdomains, over https. Outside production, `http://localhost` and
`http://127.0.0.1` count too. A missing `Origin`, or `Origin: null`, is
refused, because browsers send one on every POST, PATCH, PUT and DELETE.
The refusal is a 403 with `"reason": "bad_origin"`.

`SameSite=Lax` already keeps other websites' requests from carrying the
cookie. The Origin check is the second lock on the same door. It refuses
those requests outright, including the ones that don't need a cookie at
all (starting a sign-in, entering the setup password), and it doesn't
depend on every browser getting SameSite right. What it can't do is tell
one Canopy subdomain from another: all of them are trusted, the same as
with the cookie.

The check is about browsers. Something that isn't a browser can send
any `Origin` it likes, but it doesn't have anyone's cookie either.

**The apps skip it, and why that's safe.** A native app sends no
`Origin`. A forged request is a page on another site getting a visitor's
browser to send something with the credentials the browser attaches by
itself, which here is the cookie. The app routes (`/api/native/v1`) never
read the cookie: they authenticate only by `Authorization: Bearer`, and
a request with a bearer header is about that header alone, never falling
back to the cookie, even when one came along. A browser never attaches
that header by itself, and a page on another site can't set it without
asking the server first (a CORS preflight), which this service never
says yes to for these routes. So:

- A request to `/api/native/v1` that carries `Authorization: Bearer`
  skips the Origin check, whatever its `Origin` says.
- So does `POST /api/native/v1/auth/begin`, the one step before there's
  a token, when its body is JSON: a page elsewhere can't send JSON there
  without the same preflight either. All it does is make an empty,
  signed-out session row.
- Nothing else does. A cookie with no bearer header still needs a
  Canopy `Origin` everywhere, app routes included (where it's then
  ignored anyway), and a bearer header on a web route changes nothing.

The bearer token is only as safe as the place the app keeps it, the same
way the cookie is only as safe as the browser. That's why it goes in the
Keychain or Keystore, never in plain preferences or logs.

**One known, accepted gap: `GET /signout`.** Sites need a plain link to
put behind their "Sign out", and a link is a GET with no `Origin`. So
`/signout` looks at `Sec-Fetch-Site` instead and ignores the request when
the browser says it came from another website (`cross-site`). A
signed-in visitor is sent to their profile instead. Browsers that don't
send `Sec-Fetch-Site` at all (Safari before 16.4, and other old ones)
can be signed out by any website that links or redirects there. The
worst that does is sign someone out, so it's accepted. `POST
/api/signout` is the Origin-checked way, and it's what the profile
page's button uses.

`?return=` (where to go after signing in or out) gets the same test: an
https URL on `canopysf.com` or a subdomain, with no `user:password@`
part, otherwise it's ignored. So this service can't be used to bounce
people to some other site.

## Guess limits

Everything that can be guessed or abused is counted, per who, per
network address, and with one ceiling across everyone. The ceiling is
the backstop for when the first two are dodged with fresh emails and
addresses. It trips for everyone, which is the point. The counters live
in memory, so a restart forgives everyone, which is fine at this scale.
The address is Cloudflare's `CF-Connecting-IP` when present.
`X-Forwarded-For` keeps whatever the visitor sent first, so it can't be
trusted for this.

| What | Per who | Per address | Everyone |
|---|---|---|---|
| Sending a code | 5 per email per hour | 20 per hour | 100 per hour |
| Wrong codes | 10 per email per 15 min | 40 per 15 min | 300 per hour |
| Wrong setup password | 8 per browser per 15 min | 40 per 15 min | 100 per hour |
| Unknown setup links | | 40 per 15 min | |
| Quick sign-up tries | 10 per browser per 15 min | 20 per hour | 200 per hour |
| Quick accounts made | | 10 per hour | 50 per hour |
| Changing your email (new addresses) | 5 per person per hour | (the code limits) | (the code limits) |
| Lookups by phone or Instagram | 30 per asker per hour, 100 per day | 60 per hour | 300 per hour |

On top of that, each code dies after 5 wrong tries. The apps count in
the same counters as the web (they run the same code, see "Apps"), so
none of these doubles by trying from both. "Per browser" is per sign-in
ceremony for an app; like a browser clearing its cookie, an app can
begin a fresh one, so the per-address limits and the ceilings are what
hold there.

**Why those numbers for quick sign-ups.** No email goes out, so neither
the inbox nor iCloud's daily limit holds them back. Each try answers
"does this email have an account?", so every try counts, including the
ones that hit an account. 20 tries an hour per address is plenty for a
household or a party on one wifi, and too slow to check a list of emails.
The 200-an-hour ceiling is the backstop for an attacker with many
addresses. It tops out near 5,000 checked emails a day, and an email
can't be guessed the way a phone number can, so they'd need the list
first. Accounts actually made are capped harder: 10 per address and 50
across everyone an hour. A link shared to a big group chat makes a few
dozen in an evening, not 50 in an hour, and junk accounts made faster
than that are what the cap is for. Unverified accounts work only on the
sites that allow them, so a junk one can do little. When the ceiling
trips, quick sign-ups stop for everyone for that hour, and the page
points them to signing up with an email and a code, which isn't affected.

**Why those numbers for changing your email.** Every new address tried
is counted, before anything is looked up, against the person (5 an hour)
and against the code limits (that address, the network address, and the
ceiling), since each one sends an email. Someone changing their email
does it once, or twice after a typo. The answer is the same whether the
address has an account or not (see "With an email and a code"), so the
limit isn't what keeps that secret. It's there so a signed-in account
can't be used to send many emails.

**Why those numbers for lookups.** See "Finding people by phone or
Instagram".

**What that means for one account.** With 5 codes an hour and 5 tries on
each, someone going after one email gets **at most 25 guesses an hour**,
each one-in-a-million. That's about 1 in 40,000 per hour, or about 0.06%
a day. Kept up nonstop for a whole year it adds up to roughly a 1-in-5
chance, and the account's owner would get 120 code emails a day the
entire time. The codes are a reasonable lock, but it's the inbox that
actually protects an account. If that ever stops being enough, the
place to tighten it is the per-email sending limit.

**The other side of a shared ceiling.** Someone who wants to be a
nuisance can use up an email's 5 codes an hour, which keeps that person
from signing in **by email** for an hour (their passkey still works). By
spreading across addresses they can also use up the 100-an-hour ceiling,
which stops new sign-ups and email recovery for everyone for that hour.
That's the trade for the ceiling's protection. It also keeps the
service well under iCloud's daily limit on mail.

The per-address limits rely on `CF-Connecting-IP`, and Cloudflare sets
that header. A request that reaches the server without going through
Cloudflare can set it to anything, and dodge those limits. The
per-email limits and the ceilings still hold.

## For Canopy sites

A site asks this service, server to server, over HTTPS (or over
Coolify's internal network). Each site has its own key, made in the
admin's **Sites** tab. The key is shown once, when it's made. **New key**
replaces it (the old one stops working right away), and **Cut off**
stops that site and no other. A site that's been cut off gets back in by
being given a new key. Each site also has the switch **Allows quick
(unverified) accounts**, off unless the admin turns it on (see "Quick
sign-up").

### `GET /api/session`: who's visiting

The site passes along the visitor's `canopy_session` cookie value, which
it has because the cookie belongs to all of `canopysf.com`, plus its own
host:

```http
GET /api/session HTTP/1.1
Host: account.canopysf.com
Authorization: Bearer cnp_8vD...the site's key
X-Canopy-Session: q3Xb...the visitor's canopy_session value (43 characters)
X-Canopy-Site-Host: tickets.canopysf.com
```

Signed in:

```json
{
  "person": {
    "id": "6f1c2b9e-4d0a-4a53-9a51-2f7e0c1d8b44",
    "email": "ana@example.com",
    "emailVerified": true,
    "firstName": "Ana",
    "lastName": "Lima",
    "shortName": "Ana L",
    "photoUrl": "https://account.canopysf.com/photo/6f1c2b9e-4d0a-4a53-9a51-2f7e0c1d8b44?v=1759870000000",
    "venmo": "ana-l",
    "phone": "+14155551234",
    "instagram": "ana.lima",
    "cashapp": "AnaL",
    "findable": true
  },
  "renewCookie": "canopy_session=q3Xb...; Path=/; Domain=canopysf.com; HttpOnly; SameSite=Lax; Max-Age=31536000; Secure"
}
```

Not signed in (no cookie, an unknown one, or signed out): `{"person":
null}`. A missing, wrong or cut-off key: `401 {"error": "unknown or
revoked site key"}`.

**Unverified people** (a quick sign-up, or an email the admin changed,
not yet proven by a code). On a site that **allows** them, `person` is
there as above with `"emailVerified": false`. On a site that doesn't,
they aren't signed in there:

```json
{ "person": null, "unverified": true }
```

The site sends them to `verifyUrl` (`/profile?verify=1&return=…`) rather
than to sign in again. Their session is real, so it's kept alive and its
cookie renewed as usual (`renewCookie` can come with this answer too).
The moment they prove the email, every site sees them on its next ask.

`renewCookie` is only there when the cookie is due for its daily
renewal, and only when the request says `X-Canopy-Site-Host`. The site
sends it back to the visitor as a `Set-Cookie`, unchanged.
`X-Canopy-Site-Host` is how it gets the right `Domain`. A request
without it (an app's bearer token, below) never gets one: there's no
cookie to renew.

`X-Canopy-Session` is the same 43-character value whether it came from
the visitor's cookie or from an app's `Authorization: Bearer` header.
Apps get one by signing in through `/api/native/v1` (see "Apps"). Sites
only have to accept the header, which `client/canopy-account.js` does.
`photoUrl` is `null` for someone with no photo, and `venmo`, `phone`,
`instagram` and `cashapp` are each `null` when there isn't one. They're
all set on the profile page. `phone` is E.164 (`+` and the country code;
US and Canadian numbers are typed without the +1). `instagram`, `venmo`
and `cashapp` come without their `@` or `$`; Instagram names are
lowercased, since Instagram ignores case. `findable` is their "Let people
who know your phone number or Instagram find you". This is the one
answer with contact details in it, and they're the visitor's own: a site
shows them to that visitor and nobody else. Answers are `Cache-Control:
no-store`.

### `GET /api/people?ids=…`: everyone else

Names and photos for the people a page mentions, by id, comma-separated,
up to 200 at a time (more is a 400). Anything that isn't shaped like an
id is skipped.

```http
GET /api/people?ids=6f1c2b9e-4d0a-4a53-9a51-2f7e0c1d8b44,0b7e5a1f-9c2d-4e8b-8f3a-1d2c3b4a5e6f HTTP/1.1
Authorization: Bearer cnp_8vD...
```

```json
{
  "people": [
    {
      "id": "6f1c2b9e-4d0a-4a53-9a51-2f7e0c1d8b44",
      "firstName": "Ana",
      "lastName": "Lima",
      "shortName": "Ana L",
      "photoUrl": "https://account.canopysf.com/photo/6f1c2b9e-4d0a-4a53-9a51-2f7e0c1d8b44?v=1759870000000"
    }
  ]
}
```

Other people come without their email, phone, Instagram, Venmo or Cash
App, and without whether their email is proven. **An id that's missing
from the answer is a deleted account**: the site shows them as a former
member and keeps whatever it recorded for them.

### `GET /api/people/lookup?phone=…` or `?instagram=…`: finding someone

For a site the admin has switched on (**Can find people by phone number
or Instagram**), asked as a visitor: the site passes the visitor's
session in `X-Canopy-Session` exactly as for `/api/session`, and their
address in `X-Canopy-Visitor-Ip` (for the per-address limit; without it
the site's own address counts).

```http
GET /api/people/lookup?phone=(415)%20555-1234 HTTP/1.1
Authorization: Bearer cnp_8vD...
X-Canopy-Session: q3Xb...the visitor's canopy_session value
X-Canopy-Visitor-Ip: 203.0.113.7
```

```json
{
  "person": {
    "id": "6f1c2b9e-4d0a-4a53-9a51-2f7e0c1d8b44",
    "firstName": "Ana",
    "lastName": "Lima",
    "shortName": "Ana L",
    "photoUrl": null
  }
}
```

or `{"person": null}` when nobody is found. Refusals: `403
lookup_not_allowed` (the site isn't switched on), `401 signed_out` (no
signed-in visitor), `403 email_unverified` (the visitor hasn't proven
their email), `400 one_of` (not exactly one of `phone` and `instagram`),
`400 bad_phone` / `400 bad_instagram` (it can't be one), `429
rate_limited`. See "Finding people by phone or Instagram" for what it
matches and why.

### Using `client/canopy-account.js`

Copy the file into the site (it has no dependencies; Node 18+ for
`fetch`) and set two environment variables on the site:

- `CANOPY_ACCOUNT_URL`: `https://account.canopysf.com`
- `CANOPY_ACCOUNT_KEY`: the key from the admin's Sites tab

```js
const canopy = require('./lib/canopy-account')({
  url: process.env.CANOPY_ACCOUNT_URL,
  key: process.env.CANOPY_ACCOUNT_KEY
});

app.set('trust proxy', true);
app.use(canopy.attach);                         // req.person: the visitor, or null
app.get('/mine', canopy.requireSignIn, ...);    // signed in, or off to sign in and back
const people = await canopy.people(ids);        // Map of id -> { firstName, shortName, photoUrl, ... }
const found = await canopy.lookup(req, { phone: '(415) 555-1234' });  // or { instagram: '@ana.lima' }
// For links, each coming back to returnTo (this page by default):
// canopy.signInUrl(req, returnTo), canopy.signOutUrl(req, returnTo),
// canopy.quickSignUpUrl(req, returnTo), canopy.verifyUrl(req, returnTo)
```

- **`app.set('trust proxy', true)` is required.** Coolify (and Cloudflare)
  terminate https in front of the site, so without it Express thinks
  every request is plain http. Then "come back here after signing in"
  says `http://tickets.canopysf.com/...`, this service refuses to return
  to an http address, and people land on their profile instead of where
  they were. It also reads the right host for the renewed cookie.
- `attach` puts `req.person` on every request, and
  `req.canopyUnverified`: `true` for someone signed in whose email this
  site needs proven first (`req.person` is then `null`). `requireSignIn`
  sends a page (a GET asking for HTML) to the sign-in page and back, and
  answers anything else with a 401 and a `signIn` URL. For an unverified
  visitor it sends a page to `verifyUrl` instead, and answers anything
  else with `403 {"error": "confirm your email first", "reason":
  "email_unverified", "verify": "<verifyUrl>"}`. It works with or without
  `attach` before it.
- **Bearer tokens.** Both also take `Authorization: Bearer <token>`, the
  token being a `canopy_session` value (43 characters, base64url), for
  native apps. It's looked up through `/api/session` the same way as the
  cookie. When a request has both, the bearer wins. A `Bearer` header
  that isn't shaped like a token means nobody (it doesn't fall back to
  the cookie); other schemes (`Basic`) are ignored. Apps get their token
  from this service (see "Apps").
- `attach` passes `renewCookie` on to the visitor by itself, for a cookie
  only. Nothing is ever sent back as `Set-Cookie` for a bearer request.
- `lookup(req, { phone } | { instagram })` resolves to the one person
  with exactly that, in the same shape as `people()`, or `null`. It asks
  as the visitor on `req` (cookie or bearer) and passes their address
  along. A refusal rejects with an `Error` carrying `status` and `reason`
  (the reasons above). It isn't cached.
- **Other people are only ever `{ id, firstName, lastName, shortName,
  photoUrl }`.** `people()` and `lookup()` give nothing else, and a site
  should never show one person another's email, phone, Instagram, Venmo
  or Cash App (it doesn't have them to show).
- `quickSignUpUrl` is only worth linking from a site that allows
  unverified accounts. Anywhere else the account it makes counts as
  signed out until it's verified.
- **Each visitor's answer is cached for 60 seconds** (`cacheMs`). So a
  sign-out, a rename, a new photo or a newly confirmed email can take up
  to a minute to show on a site. If this service can't be reached, a
  cached answer up to 15 minutes old stands in. Past that, the site
  answers 503 "Canopy accounts could not be reached". `people()` isn't
  cached: call it once per request.
- **Photos load straight from `account.canopysf.com`.** Put `photoUrl` in
  an `<img>` on any Canopy page and it works. A photo is only served to a
  browser signed in to some Canopy account (everyone else gets a 404),
  and an `<img>` on a Canopy subdomain carries the cookie because the
  browser counts it as the same site. An app loads the same URL with its
  bearer token. The site never has to fetch or
  proxy a photo. The `?v=` changes whenever the photo does, so the
  day-long private cache never shows an old one.
- For "Sign out", link to `canopy.signOutUrl(req)`. That signs the
  browser out of every Canopy site and comes back.

## Finding people by phone or Instagram

Hosts on a Canopy site (events, first) want to invite someone whose
number or Instagram they already have. People fill both in on their
profile, so this service can say whose they are, without ever handing
them out.

**The rule: it's one-way.** Knowing someone's number or handle finds
their account. Their account never gives up their contact details:
nothing here gives one person's email, phone, Instagram, Venmo or Cash
App to another person or to a site, except `/api/session` (which
describes the visitor themself) and the admin's pages. `/api/people` and
the lookup answer with the public shape, `{id, firstName, lastName,
shortName, photoUrl}`, and nothing else, not even the number that was
asked about, and not whether that person's email is proven (no site
needs it to show a name). In `server.js` that shape is
`publicPersonView`, and `test/privacy.test.js` walks every answer another
person or a site can get and fails if any of someone else's contact
details turns up.

How the lookup works (`GET /api/people/lookup`, above):

- **Exact matches only.** What's typed is cleaned exactly the way the
  profile cleans it (`cleanPhone`: E.164, +1 when there's no country
  code; `cleanInstagram`: lowercase, no @, a pasted link trimmed to the
  name) and compared with what's stored. Never a prefix, never anything
  fuzzy, so there's nothing to browse. Part of a number isn't a valid
  number, so it's refused as one.
- **One answer or none.** If two accounts have typed in the same number
  or handle, the answer is `null`. Neither is proven to own it, so either
  answer could be the wrong person, and inviting the wrong person is worse
  than not finding the right one. The cost: someone can hide another
  person from the lookup by claiming their handle. A miss says nothing
  about why.
- **Only for verified askers, on switched-on sites.** The site has to be
  marked **Can find people by phone number or Instagram** in the Sites
  tab (off by default), and the asker has to be signed in there with a
  proven email. The limits are per asker, so an asker has to be someone,
  and an unverified account is too cheap to make for that to mean much.
- **Unverified accounts can be found.** A phone number or handle is typed
  in by its owner and proven by nothing, for every account alike. A proven
  email says nothing about the phone, so it would be a false distinction.
  Being found only lets a host invite them, and unverified accounts can
  be invited on events.
- **Nobody who turned it off.** The profile's "Let people who know your
  phone number or Instagram find you" is **on** by default. It's on
  because the lookup gives away nothing but the name and photo that
  anyone at the same event already sees, and only to someone who already
  has the number. Most people expect a friend with their number to be
  able to invite them, and off by default would make the feature
  useless for the people who never open their profile. Anyone who'd
  rather not turns it off. To flip the default, change
  `FINDABLE_BY_DEFAULT` in `lib/db.js`; it applies to accounts made from
  then on (version 6 gave everyone already here the same default).

**Limits.** Phone numbers can be listed by brute force. An area code is
only ten million of them, so whoever can ask fast enough could map
numbers to names. Every lookup counts, found or not:

- **30 an hour and 100 a day per asker.** A host inviting people one by
  one does a handful. Someone typing in a whole party's numbers might hit
  30 in an hour; the rest can wait an hour, or come from the friends list.
- **60 an hour per address** (the visitor's, passed by the site), so a
  few accounts on one connection don't add up to much more.
- **300 an hour across everyone.** That's at most 7,200 numbers a day,
  however many verified accounts someone has, or over three years for one
  area code. Like the other ceilings, it trips for everyone: someone who
  uses it up stops lookups for that hour.

## Running locally

```bash
npm install
ADMIN_PASSWORD=whatever npm start
```

Visit `http://localhost:3000` and enter `ADMIN_PASSWORD` as the setup
password. Then type your email: on first run it needs no code. Fill in
the profile and make a passkey (browsers allow passkeys on
`http://localhost`). That account is the admin. To see the code email,
sign up from another browser. With no `SMTP_HOST`, codes are printed to
the console instead of emailed:

```
[canopy-account] code for ana@example.com: 123456
```

Locally the cookie has no `Domain` and isn't `Secure`, and
`http://localhost` passes the Origin and `?return=` checks. None of that
holds with `NODE_ENV=production`, which the Dockerfile sets.

`npm test` runs the tests (Node 22).

## Deploying on Coolify

The repo has a `Dockerfile`. It builds `better-sqlite3` in a throwaway
stage and checks the build actually works, so a broken install fails the
build rather than the deploy. It runs as `NODE_ENV=production`, port
3000, `DATA_DIR=/app/data`.

1. New resource from this repository, branch **`main`**, build pack
   **Dockerfile**.
2. **Domains**: `https://account.canopysf.com`. It has to be that name,
   or at least something under `canopysf.com`. The cookie's `Domain`, the
   passkeys and the Origin check are all worked out from the host. On a
   Coolify-generated `sslip.io` address the Origin check refuses every
   sign-in, and no other site would see the cookie anyway.
3. **Ports Exposes**: `3000`.
4. **Persistent storage.** In the **Storages** tab, add a volume with
   **Destination Path `/app/data`** (name it anything, e.g.
   `canopy-account-data`). Everything lives there: the database, its
   snapshots, photos and uploaded images. Without it, every redeploy
   starts from an empty disk, and every account is gone. The
   Dockerfile's `VOLUME` line doesn't do this by itself. Coolify has to be
   told.
5. **Environment variables**, from `.env.example`:
   - `ADMIN_PASSWORD`: the setup password. Keep it to yourself. It
     isn't needed again after the admin exists, except for
     `ADMIN_RECOVERY`.
   - `ADMIN_RECOVERY`: leave unset. See "The first admin, and recovery".
   - `SMTP_HOST=smtp.mail.me.com`, `SMTP_PORT=587`, `SMTP_USER`,
     `SMTP_PASS`, `MAIL_FROM`: see "Email: iCloud SMTP".
   - `PUBLIC_URL` and `CANOPY_DOMAIN`: leave unset. They default to
     `https://account.canopysf.com` and `canopysf.com`.
   - `ANDROID_APK_KEY_HASHES`: empty until there's an Android app. Then
     its signing certificate's SHA-256 (see "Apps" and
     `docs/native-api.md`).
   - Leave `PORT` and `DATA_DIR` alone. The Dockerfile sets them.
6. Deploy.
7. **Make the admin.** Open `https://account.canopysf.com`. A new install
   asks only for the setup password; enter `ADMIN_PASSWORD`, then sign
   up (your email needs no code this once) and save a passkey. That
   account is the admin, and you land on the Account Manager.
8. **Add each Canopy site** in the Account Manager's **Sites** tab (e.g.
   `tickets`), and give the key it shows, once, to that site as its
   `CANOPY_ACCOUNT_KEY` (see "For Canopy sites").

### Confirming the volume is attached

Every startup logs how many people it found:

```
[canopy-account] DATA_DIR=/app/data (42 people found on disk at startup)
```

Check it in the deployment log after a redeploy. If it says `0` when
you know there are people, the volume isn't attached (the Storages tab is
empty, the path isn't `/app/data`, or it was added without a redeploy
since). With 0 people the server also logs a line saying that. On a
brand-new install, 0 is right.

Two more lines worth seeing once: no warning about `SMTP_HOST` (in
production that warning means sign-up and email recovery will fail), and
no "ADMIN_PASSWORD not set" (that means a random one was made up for
this run).

## Email: iCloud SMTP

Codes go out through iCloud Mail, from an address on `canopysf.com`
(iCloud+ custom email domain).

1. The domain is set up in iCloud Mail's **Custom Email Domain**
   settings (on iCloud.com, or in iCloud settings on a device), with a
   real address on it for the
   codes to come from, e.g. `account@canopysf.com`. It has to be an
   address you've added, not one that only arrives through the
   catch-all: iCloud only sends as addresses you've actually added.
2. At **appleid.apple.com → Sign-In and Security → App-Specific
   Passwords**, make one named "Canopy account service". The Apple ID
   needs two-factor authentication on.
3. In Coolify:

   ```
   SMTP_HOST=smtp.mail.me.com
   SMTP_PORT=587
   SMTP_USER=<the Apple ID's iCloud email address>
   SMTP_PASS=<the app-specific password>
   MAIL_FROM=Canopy <account@canopysf.com>
   ```

   Port 587 is STARTTLS, which is required here (`requireTLS`).
   `SMTP_USER` is the Apple ID's iCloud Mail address (like
   `you@icloud.com`), which isn't necessarily the `MAIL_FROM` address.
4. Sign up with a fresh email to check it, or watch the log. A failed
   send is logged as `sending a code failed: ...`, and the page says
   "couldn't send the email".

Some things to know before relying on this:

- **An app-specific password is more than a mail password.** It signs in
  as that Apple ID to its mail, contacts and calendars, not just to
  sending. Anyone who reads it out of Coolify gets all of that. Keep it
  only in Coolify's environment variables. If it might have leaked,
  revoke it at appleid.apple.com (that stops only this service's mail)
  and make a new one.
- **iCloud allows about 1,000 messages a day.** The ceiling here (100
  codes an hour) could in theory pass that in a bad day of abuse. Once
  iCloud stops accepting mail, codes fail until it resets. Passkey
  sign-ins aren't affected.
- **Apple describes iCloud Mail as for personal use.** Low-volume
  automated messages like these codes aren't something Apple explicitly
  supports. It works, and at this scale it's a few emails a week. But if
  Apple ever objects or throttles it, the fix is a transactional mail
  provider. That means changing `lib/mailer.js` and the `SMTP_*`
  settings, and nothing else.

Without `SMTP_HOST` in production, nothing is sent and codes are never
printed. Every code request fails with "couldn't send the email".

## Storage & backups

Everything is in `DATA_DIR` (`/app/data` in the container):

- `account.db` is the database (SQLite, WAL mode, so `account.db-wal` and
  `account.db-shm` sit beside it while it's open);
- `photos/<person id>.jpg` holds the profile photos;
- `logo-image` and `backdrop-image`, each with its `.json`, are the
  admin's uploads;
- `backups/sqlite/account-YYYY-MM-DD.db` holds the snapshots.

**Schema version.** A new `account.db` is made with the whole current
schema (`SCHEMA_VERSION` in `lib/db.js`, kept in SQLite's
`user_version`). An older one is brought up to date at startup, one step
at a time, by `UPGRADES` in `lib/db.js`, inside one transaction. One from
newer code is refused rather than opened with columns this code doesn't
know about. Version 5 added quick sign-ups: everyone already in the
database counts as verified (including anyone whose email the admin had
changed, which until then changed nothing), and every site starts with
unverified accounts not allowed. Version 6 added the lookup: everyone
already here gets `FINDABLE_BY_DEFAULT`, and no site may look people up
until the admin switches it on. Version 7 added what each session is
(`client_kind`, `client_name`) and when it signed in: every signed-in
session already here is a browser's, signed in when it started.

**Backups.** Two layers, the same as tickets:

- The service writes a consistent copy of the database, using SQLite's
  own online backup, to `backups/sqlite/account-YYYY-MM-DD.db` when it
  starts and every 24 hours after. It keeps the newest **14**. These are
  the ones to restore from.
- In Coolify, on this application: **Backups → Scheduled Backups → Add**,
  pointing at the `/app/data` volume, daily. That archives the whole
  volume: snapshots, photos and images. **Backup Now** runs one on
  demand. Archives stay on the Coolify server unless you add
  S3-compatible storage. Coolify copies files as they sit on disk, and
  its copy of the live `account.db` can come out inconsistent if it's
  taken mid-write. That's why the snapshots exist.

**Restoring.** Stop the service. Copy the snapshot you want over
`account.db` and delete `account.db-wal` and `account.db-shm` (otherwise
SQLite replays the newer write log on top of the older snapshot). Start
the service and check the people count in the log. Photos and images
aren't in the snapshot: they come from the volume, or from Coolify's
archive of it.

The snapshots hold everything the database does, but no secrets that
work: session tokens, setup link codes, site keys and emailed codes are
all hashes, and passkeys are public keys. A restored snapshot signs
people in as they were then. Anyone who signed in since needs to sign in
again, and a site key made since won't work.

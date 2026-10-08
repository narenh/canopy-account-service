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
  or Instagram can find them** (on unless they turn it off), get their **Canopy calendar** (one link a calendar app
  subscribes to, with what they're hosting or going to on every Canopy
  site; see "Calendar feed"), see their
  passkeys (add one, remove one they've
  lost), see **where they're signed in** (each browser and app, with
  **Sign out** on any of them, and **Sign out everywhere**), sign out,
  and **delete their account** (their passkey, then typing DELETE; see
  "Deleted accounts").
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
  **can find people by phone number or Instagram**, a box for each of
  the visitor's own contact details it may be told (none for a new
  site), and where its **calendar** is, if it has one; **Lookups**, who has been finding people by phone or Instagram
  and how often they missed (see "The lookup log"); and the sign-in
  page's logo and backdrop (each can be removed again).
- The **iOS and Android apps** sign in through `/api/native/v1`, with
  the same passkeys, codes and quick sign-up, and get a token to send as
  `Authorization: Bearer` (see "Apps").
- Every Canopy site asks it, server to server, who the visitor is
  (`GET /api/session`), what other people are called
  (`GET /api/people`), and, if it's allowed to, who has a phone number or
  Instagram someone typed (`POST /api/people/lookup`). `client/canopy-account.js` is the one file a site
  copies in to do that.
- It asks the sites with a calendar, server to server the other way
  round, what's in each person's calendar (`GET
  <site>/api/calendar/<personId>`, signed), and serves it all as one
  feed at **`/cal/<secret>.ics`** (see "Calendar feed").

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
hold any site's own data either: tickets' seats and orders stay in
tickets, keyed by the person ids from here. The calendar feed is made
from what each site says when it's asked, kept in memory for a few
minutes, never written down here.

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
  with hashed keys), `lookup_log` (every lookup by phone or Instagram),
  `calendar_feeds` (each person's calendar link, hashed and sealed) and
  `meta` (who the admin is). Every contact detail in
  it is encrypted, here and nowhere else (see "Contact details at
  rest"). The schema version
  lives in SQLite's `user_version`. A database from a version this code
  doesn't know is refused at startup rather than opened. It also takes
  the daily snapshots (see "Storage & backups").
- `lib/contactCrypto.js` seals and opens contact details (AES-256-GCM)
  and makes the keyed hashes they're looked up by, from
  `CONTACT_ENCRYPTION_KEYS` and `LOOKUP_HMAC_KEY`.
- `lib/calendar.js` is the calendar feed's asking: which sites, the
  signed request, what's accepted back, the five minutes each answer is
  kept and the last good one that stands in for a site that's down.
  `lib/ics.js` writes the merged entries out as iCalendar (RFC 5545), by
  hand.
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
  mail is in this one file, so moving to another provider means changing
  this file and the `SMTP_*` settings.
- `lib/photoStore.js` stores profile photos, one square JPEG per person
  in `DATA_DIR/photos/<id>.jpg`. The browser has already cropped and
  shrunk it (`public/photo-crop.js`), so what's on disk is small and
  carries none of the original's EXIF, location included. An app crops
  its own, so every JPEG's metadata is also taken out here before it's
  saved (`withoutMetadata`). Anything it can't clean (a PNG, a WebP, a
  JPEG it can't read) is refused rather than kept as it came, from the
  web as well as the apps (`400 bad_image` from the web, `400 bad_photo`
  from the apps, as their contract says). The page always sends a JPEG
  from its canvas, so people using it never see that.
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
  around (its dev dependency `yaml` reads the spec). The calendar feed's
  tests read every feed with `ical.js`, a strict iCalendar parser (the
  other dev dependency), plus the line-by-line rules it lets slide
  (`test/icsCheck.js`). `npm test` runs them all.

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
the only passkey.

What the squatter typed in goes too: the phone and Instagram (which the
lookup finds people by, so a squatter's number would otherwise end up on
the owner's account), the Venmo and Cash App (where the owner's friends
would send money), the photo (its file is deleted), and **Let people
find you**, back to the default. The first and last name stay: an
account can't be without one, and the most common way to get here is a
real quick sign-up signing in by code on a second phone, whose name it
is. But the owner shouldn't have to trust it: the
page shows it in the warning ("Welcome back, Bob"), and once the passkey
is made it goes on to the profile, not back to the site, with a banner
saying what was cleared and asking them to check the name and save
(`/profile?claimed=1`, with **Continue** to `?return=`). The answer says
`"tookOver": true`, so the apps can do the same.

The page says all this before they make the passkey. The cost falls
on a real quick sign-up who signs in by code on a second device instead
of using their passkey: their first phone is signed out and needs a code
too, and the details they'd filled in have to be filled in again.
Confirming from the profile doesn't do this, because that's someone
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

Their calendar link stops working at the same moment (a 404, like any
wrong link), so a calendar subscribed to it stops updating; what's
already in that calendar stays until its app gives up on the feed.

**People can delete their own account**, from the bottom of their
profile (or `DELETE /api/native/v1/me` in an app). It does exactly what
the admin's delete does, and then signs that browser out. It takes the
same passkey check as changing an email (Face ID or the like, within 15
minutes), so a borrowed unlocked phone or a stolen cookie can't do it;
the page also has them type `DELETE`, so it can't happen by a slip of the
thumb (the server needs only the passkey check). The email is free again
afterwards: signing up with it makes a new, unrelated account.

**The admin can't delete their own account**, this way or from the
Account Manager (`409 is_admin`): there would be no admin, and the
install would be open to whoever next enters the setup password. Their
profile says so in place of the button.

**What other sites keep.** Deleting an account here deletes what this
service holds about them, and nothing on any other site: each one keeps
what it recorded, under the id, as it sees fit. Events keeps their RSVPs
(so a guest count doesn't change after the fact), their wall posts and
anything else they did there, all under the id and all shown as "Former
member" with no photo. The text they wrote on a wall stays as written;
whether events should also delete it is an open question for events (see
its decision log), not something this service can do. Tickets keeps its
orders the same way. Anyone deleting their account to be forgotten
should be told that: their name and photo are gone everywhere, and what
they wrote on a site is that site's to remove.

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
a day, and how many of those can be made is limited (see "Guess
limits").

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
codes are all stored as hashes. Contact details, which have to be read
back, are encrypted instead (see "Contact details at rest"). Two secrets
are both: a person's calendar link (looked up by its hash, sealed so
their profile can show it again) and each site's calendar secret (sealed
only: it's what requests are signed with, so it has to be read back).

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
  abandoned sign-in, and making them counts against the same limit as
  browsers starting one (see "Guess limits").
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
  came with it. An upload has to be a JPEG, and its metadata is taken
  out before it's saved (see "How it works").
- **Passkeys from the apps.** The phone signs each passkey use with
  where it happened. The iOS app's is `https://canopysf.com` (the
  passkey domain), and an Android app's is `android:apk-key-hash:` and
  the hash of the certificate the app was signed with. The app routes
  accept those as well as Canopy pages; the web's routes still only
  accept Canopy pages. Android apps are trusted by listing their hashes
  in `ANDROID_APK_KEY_HASHES`, and none is until one is. Both platforms
  also need a file on `canopysf.com` saying the app may use its passkeys
  (see "The association files").
- **Always JSON.** Every answer under `/api/native/v1` is JSON with a
  `reason`, errors included: a malformed upload is `400 bad_upload`, a
  path that doesn't decode `400 bad_request`, and anything unexpected
  `500 server_error`, never Express's HTML page. The web's `/api/`
  endpoints answer errors the same way.
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
- So does a Canopy site asking with its key: `POST /api/people/lookup`
  with `Authorization: Bearer cnp_…`. The reasoning is the same: the key
  is a header no browser attaches by itself, the site routes never read
  the cookie (the visitor's session comes in `X-Canopy-Session`, which a
  page elsewhere can't set without a preflight either), and the key is
  then checked like any site's. The other site routes (`/api/session`,
  `/api/people`) are GETs, which this check never looks at.
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
| New sessions not yet signed in | | 100 per hour | 1,000 per hour |
| Lookups by phone or Instagram | 30 per asker per hour, 100 per day | 60 per hour | 300 per hour |
| Calendar feed fetches | 120 per feed per hour | 1,200 per hour | |
| Unknown calendar links | | 60 per hour | |

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

**Why those numbers for new sessions.** A browser with no cookie that
starts a sign-in (the passkey button, an email, a quick sign-up, the
setup password or a setup link, here or from another Canopy page) gets
a new row in `sessions`, and so does every app's `auth/begin`. One
that's never signed in is kept for a day. Nothing else held these back,
so a loop of requests could fill the disk with rows. Now they're
counted: 100 per address and 1,000 across everyone an hour. A browser
makes one and keeps its cookie, so reloading the page and pressing the
passkey button again costs nothing; only a browser that throws its
cookie away each time (or refuses it) is counted again. 100 an hour is
far more first visits than a household or a party on one wifi will
make. A phone carrier that puts a great many phones behind one address
could in principle reach it, and those phones would wait out the hour;
that's the price of a per-address count anywhere here. 1,000 an hour
across everyone is far above Canopy's sign-ups on any day. That caps
abuse at 24,000 rows a day, on the order of 10 MB, and they're pruned
after a day. When the ceiling trips, browsers without a cookie
and apps can't start a sign-in for that hour; anyone signed in, or
already part way through signing in, isn't affected. Page loads never
make one: only these POSTs do.

**Why those numbers for lookups.** See "Finding people by phone or
Instagram".

**Why those numbers for the calendar feed.** See "Calendar feed". There's
no ceiling across everyone: calendar apps fetch on their own, all day,
and a ceiling tripping would stop everyone's calendar updating at once,
for an hour, which is the one thing the feed is for.

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
sign-up"), and a box for each of the visitor's own contact details it may
be told (see "What a site is told about the visitor").

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
`instagram` and `cashapp` are each `null` when there isn't one, and left
out altogether when the site hasn't been granted them (below). They're
all set on the profile page. `phone` is E.164 (`+` and the country code;
US and Canadian numbers are typed without the +1). `instagram`, `venmo`
and `cashapp` come without their `@` or `$`; Instagram names are
lowercased, since Instagram ignores case. `findable` is their "Let people
who know your phone number or Instagram find you". This is the one
answer with contact details in it, and they're the visitor's own: a site
shows them to that visitor and nobody else. Answers are `Cache-Control:
no-store`.

#### What a site is told about the visitor

Each site is granted, in the Sites tab, which of the visitor's own
`email`, `phone`, `instagram`, `venmo` and `cashapp` its `/api/session`
answer carries. **A new site gets none of them.** The id, names, photo,
`emailVerified` and `findable` always come; they're what every site needs
to show who's signed in.

The ones not granted are **left out of `person` altogether**, not sent as
`null`. `null` already means "they haven't filled it in", and a site that
reads a missing field as that would tell someone their phone is blank
when it's only that the site was never told. Absent means "not yours to
know". A site that wasn't granted a field and shows one anyway has a bug,
and it shows up as `undefined`.

Why less is safer: a site can only leak what it's sent. Every Canopy
site's server sees these answers, and so does whatever it logs or caches
them in. A site that only shows a name and a photo (events) should be
granted nothing, and then its database, its logs and its error reports
never hold anyone's phone number. Grant a field to a site that shows it
to the person (tickets shows Venmo next to an order, say) and to no other.

Sites that existed before this (schema version 8) were granted all five,
which is what they were getting, so nothing that works stopped working.
Untick what they don't use.

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

### `POST /api/people/lookup`: finding someone

For a site the admin has switched on (**Can find people by phone number
or Instagram**), asked as a visitor: the site passes the visitor's
session in `X-Canopy-Session` exactly as for `/api/session`, and their
address in `X-Canopy-Visitor-Ip` (for the per-address limit; without it
the site's own address counts). What was typed goes in a JSON body,
exactly one of `phone` or `instagram`, as a string:

```http
POST /api/people/lookup HTTP/1.1
Authorization: Bearer cnp_8vD...
X-Canopy-Session: q3Xb...the visitor's canopy_session value
X-Canopy-Visitor-Ip: 203.0.113.7
Content-Type: application/json

{"phone": "(415) 555-1234"}
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

or `{"person": null}` when nobody is found: nobody with exactly that,
someone who turned it off, more than one account with it, or, for a phone
number, one account whose email isn't proven. Refusals: `403
lookup_not_allowed` (the site isn't switched on), `401 signed_out` (no
signed-in visitor), `403 email_unverified` (the visitor hasn't proven
their email), `400 one_of` (not exactly one of `phone` and `instagram`),
`400 bad_phone` / `400 bad_instagram` (it can't be one), `429
rate_limited`. See "Finding people by phone or Instagram" for what it
matches and why.

**Why a POST.** It changes nothing, so it would naturally be a GET, but
then the number or handle would be in the URL, and URLs get written down
everywhere along the way: this service's and the site's error logs, a
proxy's access log, Cloudflare's. A body isn't. It used to be `GET
/api/people/lookup?phone=…`; nothing outside Canopy used it yet, so that
form is gone rather than kept for compatibility (it's a 404 now). The
site's key in `Authorization` is what lets it skip the Origin check (see
"The Origin check"). Neither service logs request bodies, and an error's
log line has the path without its query string.

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
  along. It's a POST with what was typed in the body, so it never shows
  up in a URL; don't log it on the site's side either. A refusal rejects with an `Error` carrying `status` and `reason`
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
- `verifyCalendarRequest(req)` is for a site with a calendar: see the
  next section.

### `GET <site>/api/calendar/<personId>`: the site's calendar

The one call that goes the other way: **this service asks the site**,
for each person's calendar feed (see "Calendar feed"). A site with a
calendar implements it; one without doesn't need to. Events is the
first.

**Setting a site up.** In the Sites tab, put the site's base URL in its
**Calendar URL** and Save: `https://events.canopysf.com`, or its address
on Coolify's internal network (`http://<its container>:3000`). The feed
asks `<that>/api/calendar/<personId>`. The first time, that shows a
**calendar secret**, once, like a key: set it on the site as
`CANOPY_CALENDAR_SECRET`, and hand it to the client file:

```js
const canopy = require('./lib/canopy-account')({
  url: process.env.CANOPY_ACCOUNT_URL,
  key: process.env.CANOPY_ACCOUNT_KEY,
  calendarSecret: process.env.CANOPY_CALENDAR_SECRET
});

app.get('/api/calendar/:personId', (req, res) => {
  const personId = canopy.verifyCalendarRequest(req);
  if (!personId) return res.status(401).json({ error: 'not the account service', reason: 'unauthorized' });
  res.set('Cache-Control', 'no-store');
  res.json({ entries: entriesFor(personId) });
});
```

**New calendar secret** replaces it, and the old one stops working at
once (until the site has the new one, feeds use that site's last good
answers). Emptying the Calendar URL takes the site out of every feed, and
so does **Cut off**.

**How the site knows it's this service asking.** Every request is signed:

```http
GET /api/calendar/6f1c2b9e-4d0a-4a53-9a51-2f7e0c1d8b44 HTTP/1.1
Authorization: Canopy-Calendar t=1759870000, sig=<64 hex characters>
Accept: application/json
```

`sig` is HMAC-SHA256, keyed with the calendar secret, of three lines
joined by `\n`: `canopy-calendar-v1`, the person id, and `t` (Unix
seconds, as sent). The site works out the same, compares in constant
time, and refuses a `t` more than five minutes from its own clock.
`verifyCalendarRequest(req)` does all of that and answers the person id
from the path (`req.params.personId`, or the URL's last part), or `null`,
including on a site with no `calendarSecret`. This service never follows
a redirect from a site.

Why this, rather than a key sent as it is (the way a site asks here):
this service can't send the site's own key, since it only keeps that
key's hash, so it needs a secret of its own for each site, and has to
keep it readable to use it. With a signature, that secret never travels.
A request that ends up in a log, a proxy, or at a mistyped Calendar URL
gives away one person's calendar on that one site for five minutes, not
everyone's for good. That costs about a dozen lines on each side. The
secret is sealed in the database like a contact detail, so a copy of the
database doesn't have it either.

**What the site answers.** JSON, `200`:

```json
{
  "entries": [
    {
      "uid": "q7Lm2xR9TcWb@events.canopysf.com",
      "title": "Rooftop dinner",
      "start": "2026-10-31T03:00:00.000Z",
      "end": "2026-10-31T06:00:00.000Z",
      "allDay": false,
      "timeZone": "America/Los_Angeles",
      "location": "Ana's place, 1 Market St, San Francisco",
      "url": "https://events.canopysf.com/e/AbCdEfGhIjKl",
      "status": "confirmed",
      "description": "Bring a jacket.",
      "updatedAt": "2026-10-01T12:00:00.000Z"
    }
  ]
}
```

- **`uid`** (required) is what calendar apps know the entry by, so it
  stays the same for the life of the entry, whatever else changes:
  `<the site's own id for it>@<the site's host>`, so no two sites can
  clash. Up to 255 characters, no spaces. Never from anything that can
  change (events uses the event's internal id, not its link, which a
  host can replace).
- **`title`** (required), up to 500 characters.
- **`start`** (required) and **`end`**: ISO 8601 with `Z` or an offset.
  `end` may be `null`, and the feed shows the entry as an hour long. With
  **`allDay: true`** both are dates (`2026-10-31`), `end` the last day
  (or `null` for one day). The feed writes every time in UTC, which
  calendar apps show in their own zone.
- **`timeZone`**: the entry's IANA zone, if the site knows it. Not used
  yet (UTC says the moment); there for when the feed writes local times.
- **`location`**, **`description`**: text, up to 1,000 and 4,000
  characters. Only what the person may see on the site.
- **`url`**: an http(s) link to the entry on the site.
- **`status`** (required): `confirmed`, `tentative` or `cancelled`. A
  cancelled entry is shown as such (struck through in Apple's Calendar,
  and "Cancelled:" in its title everywhere, since Google ignores the
  status), so keep cancelled entries in the answer for a while rather
  than dropping them: a dropped one vanishes without saying why.
- **`updatedAt`** (required): when anything about the entry last
  changed, the person's own part in it included (going → maybe). It
  becomes the event's `LAST-MODIFIED`, `DTSTAMP` and `SEQUENCE`, which
  is how a calendar app knows to update it.

An entry that doesn't fit this is left out (the log says how many), not
the whole answer. At most 1,000 entries and 2 MB are read. A person the
site has nothing for is `{"entries": []}`, never a 404: the answer
shouldn't say whether someone exists. Leave out whatever the person
couldn't see on the site, and **never anyone's contact details or other
guests' names**: the feed ends up on Google's and Apple's servers.

**When the site is down.** It has three seconds to answer. A failure
(anything but a `200` with `entries`, or no answer in time) is logged
with the site's name and nothing else, and the person's last good answer
from that site is used instead, however old (see "Calendar feed").

## Calendar feed

Everyone gets **one calendar link**,
`https://account.canopysf.com/cal/<secret>.ics` (or `webcal://` the
same, which is what phones subscribe with), with everything they're
hosting or going to on every Canopy site that has a calendar, kept up to
date by their calendar app. Events is the first; tickets and whatever
comes next join by answering one request (see "`GET
<site>/api/calendar/<personId>`").

**On the profile**, a **Calendar** section: **Add to Calendar** (the
`webcal://` link, which Apple Calendar, Outlook and most others subscribe
from), **Copy link** (for an app that takes a URL), **Google Calendar**
(Google's own subscribe page with the link filled in; Android has no
webcal handler of its own) and **Reset link**. The apps get the same from
`GET /api/native/v1/me/calendar` and `POST .../me/calendar/reset` (see
`docs/native-api.md`); the web's are `GET /api/profile/calendar` and
`POST /api/profile/calendar/reset`. All of them answer `{"calendar":
{url, webcalUrl, createdAt}}` with `Cache-Control: no-store`.

**The link is the key.** Calendar apps can't sign in or send a header,
so whoever has the URL can read the feed: what you're going to, where,
and when. So:

- The secret is 32 random bytes (43 characters), made the first time
  someone opens their Calendar section, one per person. The database
  keeps its SHA-256, which a fetch is looked up by, and a sealed copy
  (see "Contact details at rest") so the profile can show the same link
  again. A copy of the database alone gives neither. (Storing only the
  hash would have made the link show-once, and "Copy link" a reset every
  time.)
- **Reset link** makes a new one, and the old one is a 404 at once. A
  calendar subscribed to the old link stops updating (it keeps what it
  had) until the new one is added. That's the way out of a link shared
  by mistake.
- It travels where URLs go: the calendar app's servers (Google and Apple
  fetch it from theirs, not from the phone) and the logs of anything in
  between. That's every calendar subscription's trade. This service
  never logs it: a failed fetch's log line has no path.
- An unknown link is a plain `404 Not found`, exactly like a wrong URL.
- **A deleted account's link is gone** with it (`calendar_feeds` goes
  with the person), and the profile's delete section says so.

**What's in it** is up to each site (events: see its README). For each
site with a Calendar URL that isn't cut off, this service asks `GET
<calendar URL>/api/calendar/<personId>`, signed (see the site's side
above), all of them at once, three seconds each. An unverified person's
feed only asks the sites that let unverified accounts in, the same line
as `/api/session`. The answers are merged into one calendar, soonest
first; if two sites send the same `uid`, the first site's wins.

**Kept five minutes, and the last good one when a site is down.** Each
person's answer from each site is kept in memory and used as it is for
five minutes, so a calendar app polling every minute asks each site at
most every five. After that the site is asked again, and if it fails (an
error, a timeout, nonsense) **the last good answer stands in**, however
old: a calendar app takes a missing event as a deleted one, and a site's
deploy shouldn't wipe everyone's calendars. Only a site that has never
answered for that person since this service started is left out. When
every site is in that state (a restart while the only site is down), the
feed answers **`503`** with `Retry-After: 300` instead of an empty
calendar, which the app would take as "delete everything"; on a 503 it
keeps what it has. The answers are in memory rather than on disk on
purpose: they say where people will be, with home addresses, and on disk
they'd be in every snapshot and backup. The cost is a restart during a
site's outage, which the 503 covers while there's one site.

**The answer** is `Content-Type: text/calendar; charset=utf-8`, with an
`ETag` (of the text, which only changes when an entry does, so an app
that sends `If-None-Match` gets a `304`), `Cache-Control: private,
max-age=300`, and inside it `REFRESH-INTERVAL:PT1H` and
`X-PUBLISHED-TTL:PT1H`, asking apps to look every hour (Apple and Outlook
listen; Google fetches every several hours whatever it's told). The text
is written by hand in `lib/ics.js`: CRLF line endings, lines folded at 75
octets, text escaped, times in UTC, `STATUS` for tentative and cancelled
events (and "Cancelled:" in a cancelled one's title), and `SEQUENCE` and
`LAST-MODIFIED` from each entry's `updatedAt`. The tests read every feed
they fetch with a strict parser.

**Limits.** Calendar apps poll, some every few minutes, from every device
someone has, and Google's fetchers share addresses across many people.
So the limits are light: **120 fetches an hour per feed** (a phone, a
laptop and a tablet every five minutes is 36), **1,200 an hour per
address**, and **60 unknown links an hour per address**, after which that
address waits (guessing 32 random bytes is hopeless; this is about
noise). A `429` has `Retry-After: 600`, and calendar apps keep what they
have meanwhile.

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

How the lookup works (`POST /api/people/lookup`, above):

- **Exact matches only.** What's typed is cleaned exactly the way the
  profile cleans it (`cleanPhone`: E.164, +1 when there's no country
  code; `cleanInstagram`: lowercase, no @, a pasted link trimmed to the
  name) and its keyed hash compared with the stored one's (see "Contact
  details at rest": the stored value itself is encrypted). Never a prefix, never anything
  fuzzy, so there's nothing to browse. Part of a number isn't a valid
  number, so it's refused as one.
- **One answer or none.** If two accounts have typed in the same number
  or handle, the answer is `null`. Neither is proven to own it, so either
  answer could be the wrong person, and inviting the wrong person is worse
  than not finding the right one. The cost: someone can hide another
  person from the lookup by claiming their handle. A miss says nothing
  about why. Every account's claim counts here, unverified ones included
  (see the next point for why).
- **Only for verified askers, on switched-on sites.** The site has to be
  marked **Can find people by phone number or Instagram** in the Sites
  tab (off by default), and the asker has to be signed in there with a
  proven email. The limits are per asker, so an asker has to be someone,
  and an unverified account is too cheap to make for that to mean much.
- **By phone, only verified accounts are found. By Instagram, any
  account is.** The first version found unverified accounts both ways;
  a security review then showed that anyone can make a quick sign-up in
  a minute, with no inbox at all, type in a friend's name and their
  number or handle, and be the one match, so a host who looks the friend
  up invites the impostor. So for a while only verified accounts were
  found at all. That was undone for Instagram, on purpose: on a new
  network most people never confirm their email, and a lookup that can't
  find them is no use for inviting them. The impostor case is narrower
  than it sounds. It only works while the real person hasn't typed in
  their own handle (once they do, the claim is contested and nobody is
  found), and someone has to squat the handle of a person a host is about
  to look for. Phones stay verified-only, because numbers can be
  enumerated in a way handles can't, so a squatter could claim them in
  bulk.

  **Its claim still counts against others.** If a verified account and
  an unverified one have typed in the same number, the answer is `null`,
  not the verified one. That keeps "inviting the wrong person is worse
  than not finding the right one": the verified account isn't more likely
  to own the phone (a proven email says nothing about it), and the
  unverified one may well be the real owner, a quick sign-up who never
  confirmed, with an impostor on a throwaway verified email. The cost is
  that an unverified squatter can now hide someone from the lookup,
  which only a verified one could before. Hiding someone is the lesser
  harm.

  **This raises the cost, it doesn't close the hole.** An impostor now
  needs an email inbox they can read, which is a free webmail account
  away. What would actually close it is proving the number itself: a
  code by SMS to the phone (and, for Instagram, something like a code
  sent by DM). Until there is that, a lookup's answer means "the one
  account with a proven email that typed in this number", not "the
  owner of this number", and sites should show it that way (the name and
  photo, for the host to recognise).
- **Nobody who turned it off.** The profile's "Let people who know your
  phone number or Instagram find you" is **on** by default. It's on
  because the lookup gives away nothing but the name and photo that
  anyone at the same event already sees, and only to someone who already
  has the number. Most people expect a friend with their number to be
  able to invite them, and off by default would make the feature
  useless for the people who never open their profile. Anyone who'd
  rather not turns it off. A takeover (see "Proving the email") puts it
  back to the default along with clearing the phone and Instagram. To
  flip the default, change
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

### The lookup log

The limits slow a scraper down; the log is for noticing one. Every
lookup a site makes is written to `lookup_log`, found or not, and
refused or not:

- **who asked** (their person id; none when nobody signed in asked),
- **which site** asked,
- **what kind** (`phone` or `instagram`),
- **what was looked for, as a keyed hash**: the same HMAC as the lookup
  columns (see "Contact details at rest"), of the cleaned value. Never the
  number or handle itself. None when it couldn't be cleaned (`bad_phone`)
  or wasn't read (refused before that),
- **whether it found someone**, and **whether it was refused, and why**
  (the answer's `reason`: `lookup_not_allowed`, `signed_out`,
  `email_unverified`, `one_of`, `rate_limited`, `bad_phone`,
  `bad_instagram`),
- **the visitor's address, as a keyed hash** (the same key). Telling
  addresses apart is all the log needs, so it doesn't keep the address
  itself; it's personal data, and it would sit in every backup,
- and **when**.

**Kept 90 days**, and pruned on the same daily run as the snapshots (just
before each one, so a snapshot doesn't carry what's expired). Long enough
to look back over a slow, patient run through numbers (the limits hold
one asker to 100 a day, so a real attempt takes weeks or months), and to
answer "how did they find me?" when someone asks weeks later. No longer,
because the log is a record of who looked for whom, copied into every
backup. A deleted account's entries stay under its id until they age out.
Refusals that come before the limits are counted (not switched on, signed
out, not verified, not one of the two, rate limited) are written down at
most 30 an hour per asker (or per address, when nobody signed in asked)
and 600 an hour in all, so the log can't be used to fill the disk; every
other entry is already held back by the lookup limits.

**When it looks wrong.** Someone working through numbers misses almost
every time. A host inviting friends misses now and then (a friend who
isn't on Canopy, a typo), but rarely ten times running. So an asker, or
an address, is flagged for:

- **10 misses in a row** (lookups that ran and found nobody);
- in the last day, **at least 20 lookups with 80% or more missed**;
- **running into the lookup limits** at all in the last day.

There's no alerting channel yet, so a flag is a line in the server's log,
once a day per asker or address:

```
[canopy-account] lookup alert: asker 6f1c2b9e-... (site events): 10 misses in a row. See the Account Manager's Lookups tab.
```

and the Account Manager's **Lookups** tab lists everyone who looked
anyone up in the last week, flagged ones first, with how many lookups,
how many found someone, the share that missed, how many were refused,
which sites, and why they're flagged; then any address that's flagged,
by the first characters of its hash. The thresholds are `LOOKUP_ALERT` in
`server.js`. A flag blocks nothing: the limits do that. What to do about
one is the admin's call (ask the person, turn the site's lookup off, or
delete the account).

**What an admin can learn from it, and what they can't.** From the
Lookups tab: who has been looking people up, on which site, how often,
how often they found someone, and whether one address is behind several
askers. Not what anyone looked for: the tab never shows a target, and the
database never holds one in plain text. A target hash can't be turned
back into a number by itself, and a copy of the database (a snapshot)
gives nothing more, because the hashes are keyed. **But it isn't
irreversible to someone with the live server's keys.** Phone numbers are
few enough to try them all, so whoever has `LOOKUP_HMAC_KEY` could hash
every number in an area code and see which ones were looked up, and by
whom; the same goes for addresses. That's the same line as everywhere
else in "Contact details at rest": the log protects copies, not the live
server. Without doing that, all anyone can tell is that two entries were
for the same target (equal hashes), which is what shows someone asking
for the same person over and over.

## Contact details at rest

Everyone's email, phone number, Instagram, Venmo and Cash App is
**encrypted in `account.db`**, and so are the email and sign-up details a
session holds for the few minutes a sign-in takes. Names, photos,
passkeys and everything else aren't: names and photos are shown to
everyone at the same event anyway, and the rest is already hashes or
public keys.

### What this protects, and what it doesn't

**It protects copies of the database.** A copy of `account.db` gets made
all the time: the daily snapshots, Coolify's volume backups (and the S3
bucket they may go to), a file pulled down to look at something, a disk
that's thrown away. Before this, every one of those was a list of
everyone's email, phone number and Instagram, with their names. Now
they're ciphertext, and a copy alone gives up none of them.

**It doesn't protect against anyone on the live server.** The keys are in
the service's environment, so whoever can read that (Coolify's
environment variables, a shell in the container, the running process)
can read everything, exactly as the service itself does. Nor does it
change what the service gives out: the admin's pages, `/api/session` for
a site that's granted a field, and someone's own profile all show the
details decrypted, as before. It's a lock on the copies, not on the
house.

### Email is encrypted too

Email was the hard call. It's looked up by exact value all over: signing
in by code, whether an address already has an account (quick sign-up,
changing your email, the admin's edit), and its uniqueness. So it's
encrypted **and** has a keyed hash beside it (`email_hash`, with the
unique index), which is what all of those use. Encrypting only the
phone, Instagram, Venmo and Cash App would have been simpler, but a leaked
copy would still have been a list of every name and email address here,
which is the most useful part of it to a spammer or a phisher. The cost
is that the email depends on the key like the rest, which the backup
plan below covers. The keyed hash is also what lets an email come back
if the key is lost.

### How

- **Sealed values** are `v1:<keyId>:<nonce>:<ciphertext and tag>` (the
  last two base64url): AES-256-GCM with a fresh random 12-byte nonce for
  every value, so the same phone number twice is two different strings.
  What kind of value it is (`email`, `phone`, ...) is GCM's additional
  data, so a value moved into another column won't open. `keyId` says
  which key sealed it, which is what makes rotation possible.
- **Lookup hashes**, `email_hash`, `phone_hash` and `instagram_hash`:
  HMAC-SHA256 under a separate key, `LOOKUP_HMAC_KEY`, of exactly the
  cleaned value the profile stores (`+14155551234`, `ana.lima`,
  `ana@example.com`). The lookup cleans what's typed the same way and
  hashes it, so it still matches exactly and only exactly, and "more than
  one account claims this" is counted on the hashes without decrypting
  anyone. A hash can't be checked against a guess without the key. With
  the key, it can, and phone numbers are few enough to try them all: that
  is the same line as above, the live server.
- Everything is sealed and opened in `lib/db.js` and nowhere else; the
  rest of the code only ever sees plain values. The same keys seal two
  things that aren't contact details but have to be read back: each
  person's calendar link and each site's calendar secret (see "Calendar
  feed"). They're re-sealed on rotation like the rest. If a key is lost,
  a person's link is replaced the next time they open their Calendar
  section (the old one can't be shown, and stops working), and a site's
  calendar is left out of feeds until the admin makes it a new calendar
  secret.
- **No plain text left in the file.** The database runs with SQLite's
  `secure_delete`, so a value that's changed or deleted is overwritten,
  not left in free space for a copy to carry, and the upgrade that first
  sealed everything rebuilds the file (`VACUUM`) afterwards.

### The keys

Two environment variables, each base64 of 32 random bytes
(`openssl rand -base64 32` makes one):

- `CONTACT_ENCRYPTION_KEYS`: `<id>:<key>`, comma-separated. The **first
  one encrypts**; any of them decrypts. The id is yours to choose
  (letters, digits, `-`, `_`), e.g. the year: `k2026:9Gx...=`.
- `LOOKUP_HMAC_KEY`: the key for the lookup hashes.

**Setting them up on Coolify:**

1. On your own computer, run `openssl rand -base64 32` twice.
2. In Coolify, on this application, **Environment Variables**, add
   `CONTACT_ENCRYPTION_KEYS` = `k2026:<the first one>` and
   `LOOKUP_HMAC_KEY` = `<the second one>`. Tick nothing else (they're
   runtime variables, not build ones).
3. **Before deploying, copy both lines into your password manager** (see
   the backup plan below).
4. Redeploy. The log should have no `CONTACT_ENCRYPTION_KEYS` warning.
   On the first deploy with this code, it also says the contact details
   are now encrypted and that older snapshots aren't.

Unset, the service makes **throwaway keys** for that run and prints them,
the way it does `ADMIN_PASSWORD`. That's fine in development and on a
brand-new install, where it warns loudly (`!!!`) in production. But
details saved under throwaway keys can't be read after a restart, so
**in production the service refuses to start without keys once there's
anyone in the database**, saying why. Setting only one of the two, or a
malformed one, always stops it.

### Rotating a key

1. Make a new key and put it **first**, keeping the old one after it:
   `CONTACT_ENCRYPTION_KEYS=k2027:<new>,k2026:<old>`. Redeploy.
2. At startup the service re-encrypts everything under an older key with
   the new one, in one transaction, and logs `re-encrypted N contact
   detail(s) under the current key, "k2027"`. (It does this at every
   startup where anything isn't under the first key, so there's nothing
   to run by hand.)
3. **Keep the old key in the list as long as you keep any backup made
   before the rotation**: the snapshots (14 days) and Coolify's backups
   are still under it, and restoring one needs it. Once they've all aged
   out, take it out and redeploy. If you take it out too soon, a
   production start that finds anything under it is refused (see below).

**Changing `LOOKUP_HMAC_KEY`** needs no steps: set the new one and
redeploy. The service notices (a check value in `meta`), decrypts every
email, phone and Instagram and works their hashes out again under the
new key, and logs how many.

### The key backup plan

**Losing `CONTACT_ENCRYPTION_KEYS` loses every contact detail.** Nobody,
including the admin, can get them back from the database: that's the
point. So:

- Keep both variables in your password manager, the moment they're made,
  under something like "Canopy account service keys", and again whenever
  one is rotated (with the old one, until it's retired).
- Not on the Coolify server only: a lost server is when you'll need them.
  Not in the repo. Not in the same place as the backups (a backup and its
  key together are no better than plain text).
- Restoring a backup on a new server means setting the same keys there
  (or the list that includes the one the backup was made under).

### If the keys are lost

Startup in production refuses a database with values under a key it
doesn't have: `N contact detail(s) in the database are encrypted under a
key that isn't in CONTACT_ENCRYPTION_KEYS`. If the old key is somewhere,
put it back after the current one. If it's truly gone, set
`CONTACT_KEYS_LOST=1` (with new keys) and redeploy: the service starts,
and every value it can't decrypt reads as empty. Nothing is deleted, so
if the key turns up later, putting it back makes them readable again (and
the next start re-encrypts them under the current key). Remove
`CONTACT_KEYS_LOST` once the old values have been dealt with.

Exactly what survives, with this design:

**Only `CONTACT_ENCRYPTION_KEYS` lost** (`LOOKUP_HMAC_KEY` kept):

- **Kept:** every account, name, photo, passkey and session, the admin,
  the sites and their keys, every site's own records. **Sign-in by
  passkey works** as before (a passkey names the account, not an email).
- **Sign-in by email code still works**: the typed address is hashed and
  finds the account by `email_hash`, the code goes to that address, and
  proving it **puts the email back**, encrypted under the new key. So
  each person's email comes back the first time they sign in by code.
  Until then their profile and the admin show it as empty, and
  confirming an unverified email from the profile asks them to sign in
  by code instead.
- **The lookup still finds people** by the phone number or Instagram
  they had, because the hashes are intact, even though their profile
  shows those as empty. Typing them in again (or clearing them) replaces
  the hash as usual.
- **Lost for good:** every phone number, Instagram, Venmo and Cash App,
  as text. People have to type them in again.

**Only `LOOKUP_HMAC_KEY` lost:** nothing is lost. Set a new one; the
service rebuilds every hash from the decrypted values at startup.

**Both lost:** as the first case, except the hashes are rebuilt under the
new key from values that can't be decrypted, so they're cleared. Then
emails can't be recovered by code: a person who signs in by code with
their address gets a **new, empty account** for it (their old one is
still reachable by passkey, with an empty email; the admin can set it).
The lookup finds no one until people type their numbers in again. This is
why both keys go in the password manager together.

**Snapshots and backups from before the upgrade** that introduced this
(schema version 9) still hold everything in plain text. They age out of
`backups/sqlite` in 14 days; delete them sooner once the first new
snapshot exists, and expire Coolify's older backups the same way. The
service says so in its log the first time it starts on version 9.

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

With no `CONTACT_ENCRYPTION_KEYS` and `LOOKUP_HMAC_KEY`, throwaway keys
are made and printed at each start (see "Contact details at rest"); copy
them into your environment to keep a local database readable across
restarts.

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
   - `CONTACT_ENCRYPTION_KEYS` and `LOOKUP_HMAC_KEY`: required. Make each
     with `openssl rand -base64 32`, set `CONTACT_ENCRYPTION_KEYS` to
     `k2026:<one>` and `LOOKUP_HMAC_KEY` to `<the other>`, and **put both
     in your password manager before deploying**. See "Contact details at
     rest" for why, rotation, and what losing them costs.
   - `CONTACT_KEYS_LOST`: leave unset. See "If the keys are lost".
   - Leave `PORT` and `DATA_DIR` alone. The Dockerfile sets them.
6. Deploy.
7. **Make the admin.** Open `https://account.canopysf.com`. A new install
   asks only for the setup password; enter `ADMIN_PASSWORD`, then sign
   up (your email needs no code this once) and save a passkey. That
   account is the admin, and you land on the Account Manager.
8. **Add each Canopy site** in the Account Manager's **Sites** tab (e.g.
   `tickets`), and give the key it shows, once, to that site as its
   `CANOPY_ACCOUNT_KEY` (see "For Canopy sites"). Tick only the contact
   details that site shows people about themselves; events needs none
   (see "What a site is told about the visitor").
9. **Calendars.** For each site with a calendar (events), fill in its
   **Calendar URL** in the Sites tab and Save, and give the calendar
   secret it shows, once, to that site as `CANOPY_CALENDAR_SECRET` (see
   "`GET <site>/api/calendar/<personId>`"). Check it from your own
   profile: **Copy link** and open it in a browser; your events should be
   in it.

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

Three more lines worth seeing once: no warning about `SMTP_HOST` (in
production that warning means sign-up and email recovery will fail), no
"ADMIN_PASSWORD not set" (that means a random one was made up for this
run), and no "CONTACT_ENCRYPTION_KEYS and LOOKUP_HMAC_KEY are not set"
(that means contact details saved in this run are lost at the next
restart; with anyone in the database it doesn't start at all).

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
session already here is a browser's, signed in when it started. Version 8
added which contact details each site is told (`apps.contact_fields`):
every site already here keeps all five, and a new one starts with none.
Version 9 encrypted the contact details (see "Contact details at rest"):
every row is sealed in the upgrade's one transaction, the plain-text
indexes go, keyed-hash columns and their indexes come in, and the file
is rebuilt with `VACUUM` so none of the plain text is left in it. It
needs the keys set before it runs. Version 10 added the lookup log
(`lookup_log`, see "The lookup log"), empty to start with. Version 11
added the calendar feed: each site's `calendar_url`, `calendar_secret`
(sealed) and `calendar_secret_at`, all empty (no site has a calendar until
the admin says where it is), and `calendar_feeds`, empty (a link is made
when someone first opens their Calendar section).

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
archive of it. The contact details in a snapshot are encrypted under
whatever key was current when it was taken, so `CONTACT_ENCRYPTION_KEYS`
has to include that key (see "Rotating a key").

The snapshots hold everything the database does, but no secrets that
work: session tokens, setup link codes, site keys and emailed codes are
all hashes, and passkeys are public keys. And no contact details anyone
can read without the keys: they're encrypted (see "Contact details at
rest"). A restored snapshot signs
people in as they were then. Anyone who signed in since needs to sign in
again, and a site key made since won't work.

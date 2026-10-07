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
- At **`/profile`** they change their name, photo, phone, Instagram,
  Venmo and Cash App, see their passkeys (add one, remove one they've
  lost) and sign out. **Changing their email** takes three steps: their
  passkey (Face ID or the like, so a borrowed unlocked phone or a stolen
  cookie isn't enough; good for 15 minutes and one change), a code sent
  to the new address and typed back, and then a notice to the old
  address with the new one masked (`a•••@domain`), the only warning its
  owner gets if it wasn't them. A new address that already has an
  account just "can't be used". The admin lands on the Account Manager
  after signing in, with **My Profile** to their own and **Back to
  manager** from it.
- At **`/admin`**, the **Account Manager**, the admin sees everyone (the
  admin first, then by name) and can **Edit profile** (every field above
  except the photo, plus the email: a changed email counts as unconfirmed
  until its owner next gets a code there), reset passkeys, send a setup
  link or delete; the **Sites** allowed to ask about people; and the
  sign-in page's logo and backdrop (each can be removed again).
- Every Canopy site asks it, server to server, who the visitor is
  (`GET /api/session`) and what other people are called
  (`GET /api/people`). `client/canopy-account.js` is the one file a site
  copies in to do that.

Signing in on one Canopy site signs you in on all of them, because the
session cookie belongs to `canopysf.com` rather than to any one
subdomain. Signing out signs you out of all of them, for the same reason.

**What this isn't.** It isn't an OAuth / OpenID Connect provider. There
are no redirect dances, no tokens handed to other domains, no consent
screens. It only works for sites under `canopysf.com`, because it relies
on the browser sharing one cookie between them. There are no passwords
for anyone (the one setup password is for the admin and the server, see
"The first admin"), and no phone numbers. It doesn't send notifications:
the only email it ever sends is the sign-in code. It doesn't hold any
site's own data either. Tickets' seats, orders and calendar feeds stay
in tickets, keyed by the same person ids as here. And for now there's
no way to change an account's email, not even from the admin.

Switching tickets over to this service is a separate job. Until then
tickets keeps doing its own sign-in, and nothing here changes it.

## How it works

- `server.js` is the Express app, every route in one file: sign-in and
  sign-up, the first admin and recovery, signing out, the profile,
  photos, the admin's JSON, the site API, and the pages. It also has the
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
- `lib/domain.js` is the one answer to "is this a Canopy address?": who
  may make changes here (the Origin check), where `?return=` may send
  someone, the cookie's `Domain`, and which domain passkeys belong to.
- `lib/limits.js` holds the in-memory try counters behind the guess
  limits, and `clientIp()`, the visitor's address (Cloudflare's
  `CF-Connecting-IP` when it's there).
- `lib/mailer.js` sends the code email over SMTP (iCloud Mail, see
  "Email: iCloud SMTP"). Everything about mail is in this one file, so
  moving to another provider means changing this file and the `SMTP_*`
  settings.
- `lib/photoStore.js` stores profile photos, one square JPEG per person
  in `DATA_DIR/photos/<id>.jpg`. The browser has already cropped and
  shrunk it (`public/photo-crop.js`), so what's on disk is small and
  carries none of the original's EXIF, location included.
- `lib/uploadedImage.js` stores the admin's uploaded logo and sign-in
  backdrop as files in `DATA_DIR`.
- `client/canopy-account.js` is the file Canopy sites copy in (see "For
  Canopy sites").
- `scripts/import-from-tickets.js` is the one-time copy of everyone out of
  tickets (see "Importing from tickets").
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
  to end with no browser. `npm test` runs them all.

`GET /healthz` answers `{"ok":true}`, and `GET /favicon.ico` answers an
empty 204, so pages don't log a 404 for the icon they don't have.

## Signing in

Passkeys are the way in. Everything else here exists to get someone a
passkey.

**Passkeys belong to `canopysf.com`** (override with `PASSKEY_RP_ID`), not
to `account.canopysf.com`. So one passkey signs in from any Canopy
subdomain, and the passkeys tickets already made (also for
`canopysf.com`) keep working here after the import. Phones list them as
"Canopy". On any other host (localhost, in development) they're made for
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
  browser that doesn't sync, and anyone who was imported from tickets
  without a passkey. It's self-serve on purpose: whoever can read the
  account's email can get in, and the admin doesn't have to be awake.

That last point is the real security boundary. **An account is exactly
as safe as its email inbox**, plus the odds of guessing a 6-digit code
inside the limits below. Those odds are worked out under "Guess limits".

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
  (nothing imported) the sign-in page asks only for the **setup
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

On top of that, each code dies after 5 wrong tries.

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
being given a new key.

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
    "firstName": "Ana",
    "lastName": "Lima",
    "shortName": "Ana L",
    "photoUrl": "https://account.canopysf.com/photo/6f1c2b9e-4d0a-4a53-9a51-2f7e0c1d8b44?v=1759870000000",
    "venmo": "ana-l",
    "phone": "+14155551234",
    "instagram": "ana.lima",
    "cashapp": "AnaL"
  },
  "renewCookie": "canopy_session=q3Xb...; Path=/; Domain=canopysf.com; HttpOnly; SameSite=Lax; Max-Age=31536000; Secure"
}
```

Not signed in (no cookie, an unknown one, or signed out): `{"person":
null}`. A missing, wrong or cut-off key: `401 {"error": "unknown or
revoked site key"}`.

`renewCookie` is only there when the cookie is due for its daily
renewal. The site sends it back to the visitor as a `Set-Cookie`,
unchanged. `X-Canopy-Site-Host` is how it gets the right `Domain`.
`photoUrl` is `null` for someone with no photo, and `venmo`, `phone`,
`instagram` and `cashapp` are each `null` when there isn't one. They're
all set on the profile page. `phone` is E.164 (`+` and the country code;
US and Canadian numbers are typed without the +1). `instagram`, `venmo`
and `cashapp` come without their `@` or `$`; Instagram names are
lowercased, since Instagram ignores case. Answers are `Cache-Control: no-store`.

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

Other people come without their email or Venmo. **An id that's missing
from the answer is a deleted account**: the site shows them as a former
member and keeps whatever it recorded for them.

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
// canopy.signInUrl(req, returnTo), canopy.signOutUrl(req, returnTo) for links
```

- **`app.set('trust proxy', true)` is required.** Coolify (and Cloudflare)
  terminate https in front of the site, so without it Express thinks
  every request is plain http. Then "come back here after signing in"
  says `http://tickets.canopysf.com/...`, this service refuses to return
  to an http address, and people land on their profile instead of where
  they were. It also reads the right host for the renewed cookie.
- `attach` puts `req.person` on every request. `requireSignIn` sends a
  page (a GET asking for HTML) to the sign-in page and back, and answers
  anything else with a 401 and a `signIn` URL. It works with or without
  `attach` before it.
- `attach` passes `renewCookie` on to the visitor by itself.
- **Each visitor's answer is cached for 60 seconds** (`cacheMs`). So a
  sign-out, a rename or a new photo can take up to a minute to show on a
  site. If this service can't be reached, a cached answer up to 15
  minutes old stands in. Past that, the site answers 503 "Canopy
  accounts could not be reached". `people()` isn't cached: call it once
  per request.
- **Photos load straight from `account.canopysf.com`.** Put `photoUrl` in
  an `<img>` on any Canopy page and it works. A photo is only served to a
  browser signed in to some Canopy account (everyone else gets a 404),
  and an `<img>` on a Canopy subdomain carries the cookie because the
  browser counts it as the same site. The site never has to fetch or
  proxy a photo. The `?v=` changes whenever the photo does, so the
  day-long private cache never shows an old one.
- For "Sign out", link to `canopy.signOutUrl(req)`. That signs the
  browser out of every Canopy site and comes back.

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
     isn't needed again after the admin exists (or after an import),
     except for `ADMIN_RECOVERY`.
   - `ADMIN_RECOVERY`: leave unset. See "The first admin, and recovery".
   - `SMTP_HOST=smtp.mail.me.com`, `SMTP_PORT=587`, `SMTP_USER`,
     `SMTP_PASS`, `MAIL_FROM`: see "Email: iCloud SMTP".
   - `PUBLIC_URL` and `CANOPY_DOMAIN`: leave unset. They default to
     `https://account.canopysf.com` and `canopysf.com`.
   - Leave `PORT` and `DATA_DIR` alone. The Dockerfile sets them.
6. Deploy.

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

## Importing from tickets

A one-time copy of tickets' people into this service:

- their ids, which stay the same so every site's records line up;
- emails, names, Venmo and photos;
- their passkeys, every column unchanged, so the phones that sign in to
  tickets sign in here;
- who the admin is;
- tickets' uploaded logo, if it has one.

The backdrop doesn't come across. Tickets' link-preview image is a movie
still, and it doesn't belong behind the account sign-in page. The
sign-in page has no backdrop until one is uploaded in the admin's
Settings. With no logo uploaded either, the pages show the Canopy logo
that ships with the service.

**It only imports into an empty database, with no people in it yet.** So
don't sign up or set up an admin on the live account service before
importing. If you already have, stop it, delete `account.db`,
`account.db-wal` and `account.db-shm` from the volume, and start over.

### Without a terminal: on startup

Coolify's terminal doesn't always work, so the service can do the import
itself as it starts (`lib/startupImport.js`):

1. In tickets' **Storages** tab, note the name of its volume (the one at
   `/app/data`).
2. In the account service's **Storages** tab, add a volume mount with
   that same name and a destination of `/tickets-data`. Docker shares a
   named volume between every container that mounts it, so this is
   tickets' live data folder, seen from here. The import only reads it.
3. Add the setting `IMPORT_FROM_TICKETS=/tickets-data` and redeploy.
4. Read the deploy's logs. Before anything else opens the database, the
   service runs a dry run, and only if that ends `intact.`, the real run.
   Every line of both is in the log, ending in `import: done.` or in what
   went wrong. The service starts either way; a failed import leaves the
   database empty, to fix and redeploy.
5. **Remove `IMPORT_FROM_TICKETS` and the `/tickets-data` mount**, and
   redeploy. Left on, it does nothing (the database has people now, and
   the log says so), but tickets' data has no business being mounted
   here.

Reading tickets' live `canopy.db` while tickets runs is fine: SQLite lets
other processes read while one writes, and the import reads people,
passkeys and the admin in one read transaction, so it sees a single
consistent moment. Someone who signs up on tickets after that moment
won't be in it.

### With a terminal

The exact Docker names depend on your Coolify install, so
`docker volume ls` and `docker images` are how to find them:

1. **Stop the account service** in Coolify, so nothing has the database
   open while the import writes it.
2. **Copy tickets' data onto the account volume**, into a folder of its
   own, e.g. `/app/data/tickets-import/`:
   - the database: either `canopy.db` with tickets stopped, or, with
     tickets left running, one of its consistent daily snapshots,
     `backups/sqlite/canopy-YYYY-MM-DD.db` (today's is made when tickets
     starts and then daily);
   - `photos/`;
   - `logo-image` and `logo-image.json`, if they're there.

   On the Coolify server both volumes are directories under
   `/var/lib/docker/volumes/<name>/_data/`, so it's a `cp -a` from one to
   the other.
3. **A dry run first**, with the account service's image and its volume:

   ```bash
   docker run --rm -v <account-volume>:/app/data <account-image> \
     node scripts/import-from-tickets.js --from /app/data/tickets-import --dry-run
   ```

   Using a snapshot instead of `canopy.db`, add
   `--db /app/data/tickets-import/backups/sqlite/canopy-YYYY-MM-DD.db`.

   A dry run imports into a scratch folder, checks it, and throws it
   away. Nothing on the volume is touched. It prints how many people,
   passkeys and photos came across, who the admin is, who has no
   passkey yet (they'll sign in with an emailed code, which makes them
   one), and any photo tickets had a date for but no file. Then every
   person and passkey is read back from both sides and compared field by
   field, photos by their bytes. It ends with `every person and passkey
   checked: intact.`, or with a list of what differs and exit code 1.
4. **The real run**: the same command without `--dry-run`. It does the
   same checks against what it actually wrote.
5. **Start the account service** and look for the startup line with the
   right number of people. Sign in with a passkey that works on tickets:
   it should work here, and the admin should be able to open `/admin`.
6. **Delete `/app/data/tickets-import/`** afterwards. It's a full copy of
   tickets' database, sitting on a volume it doesn't belong to.

Emails come across trimmed and lowercased. Nobody imported counts as
having had their email verified here until the first time they type a
code.

## Storage & backups

Everything is in `DATA_DIR` (`/app/data` in the container):

- `account.db` is the database (SQLite, WAL mode, so `account.db-wal` and
  `account.db-shm` sit beside it while it's open);
- `photos/<person id>.jpg` holds the profile photos;
- `logo-image` and `backdrop-image`, each with its `.json`, are the
  admin's uploads;
- `backups/sqlite/account-YYYY-MM-DD.db` holds the snapshots.

**Schema version.** A new `account.db` is made with the whole current
schema (version 1, in SQLite's `user_version`). One at any other version
is refused at startup rather than opened with columns this code doesn't
know about. Future upgrades go in `UPGRADES` in `lib/db.js`.

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

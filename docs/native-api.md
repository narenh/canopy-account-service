# Canopy accounts for the apps

How the iOS and Android apps sign people in, sign them up, and do
everything else the account pages do. `openapi.yaml` (served at
`https://account.canopysf.com/api/native/v1/openapi.yaml`) is the exact
contract; this is the walk through it. The README's "Apps" section says
why it works the way it does.

Every path below is under **`https://account.canopysf.com/api/native/v1`**.

## The short version

1. `POST /auth/begin` answers a **ceremony** value.
2. Send it as `Authorization: Bearer <ceremony>` through one of the
   sign-in flows below.
3. The step that signs in answers a **token**. Keep it in the Keychain
   (iOS) or behind the Keystore (Android), and forget the ceremony.
4. Send `Authorization: Bearer <token>` to Canopy sites (events) and to
   the `/me` endpoints here. It lasts a year from when it was last used,
   and every use counts.
5. A `401` with `"reason": "signed_out"` from anywhere means the token is
   over (signed out, reset by the admin, account deleted, or a year
   unused). Delete it and show sign-in.

## Requests and answers

- JSON in and out (`Content-Type: application/json`), except the photo
  upload. A step with nothing to send sends `{}`.
- **No cookies and no `Origin`.** Don't let the HTTP client keep cookies
  for `account.canopysf.com`; nothing here sets any, and these endpoints
  never read one.
- Errors are `{"error": "<a sentence>", "reason": "<code>"}` with the
  right status. Match on `reason`. The sentence is for logs, and may
  change. The reasons are listed under "Errors" at the end. Every answer
  under `/api/native/v1` is JSON, errors included, never an HTML page.
- Times are milliseconds since 1970 (UTC), as numbers.
- Answers are `Cache-Control: no-store`.

## Before any of it works: passkeys and the app

Passkeys belong to **`canopysf.com`** (the relying party id in every
`options.rp.id` / `options.rpId`), the same passkeys the web uses. So a
passkey made on the web signs in from the app and the other way around,
and iCloud Keychain or Google Password Manager syncs them.

The phone only lets the app use them because `canopysf.com` says so:

- **iOS**: the app's Associated Domains entitlement has
  `webcredentials:canopysf.com`, and
  `https://canopysf.com/.well-known/apple-app-site-association` lists
  `UC3Y84QJ83.com.canopysf.CanopyEvents`. Apple's CDN caches that file
  and can take a day or more to pick up a change. While developing,
  `webcredentials:canopysf.com?mode=developer` skips the CDN on a phone
  with Developer Mode on.
- **Android**: `https://canopysf.com/.well-known/assetlinks.json` lists
  the package and its signing certificate's SHA-256 fingerprint
  (`delegate_permission/common.get_login_creds`), and the account
  service's `ANDROID_APK_KEY_HASHES` has the same fingerprint. Debug and
  release builds are signed with different certificates: each one used
  has to be in both places. With Play App Signing it's the app signing
  key's fingerprint (Play Console), not the upload key's.

The README's "The association files" has the files and how to serve and
check them.

**Where a passkey says it was used.** The phone signs that into every
passkey response (`clientDataJSON.origin`), and the server checks it.
The iOS app's is `https://canopysf.com`. An Android app's is
`android:apk-key-hash:` and the base64url SHA-256 of its signing
certificate. Anything else is `400 not_verified`.

### Making and using a passkey

The server answers WebAuthn options as JSON (binary fields base64url,
no padding), and wants the response back the same way.

**Android** (Credential Manager) takes and gives that JSON directly:

- Making one: `CreatePublicKeyCredentialRequest(requestJson =
  options.toString())`, then send `JSONObject(result.registrationResponseJson)`
  as `response`.
- Using one: `GetCredentialRequest(listOf(GetPublicKeyCredentialOption(requestJson
  = options.toString())))`, then send
  `JSONObject((result.credential as PublicKeyCredential).authenticationResponseJson)`
  as `response`.

**iOS** (AuthenticationServices) works in bytes, so the app converts:

- Making one: `ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier:
  options.rp.id).createCredentialRegistrationRequest(challenge:
  b64url(options.challenge), name: options.user.name, userID:
  b64url(options.user.id))`. On iOS 17.4 and later, set
  `excludedCredentials` from `options.excludeCredentials`, so the phone
  doesn't make a second passkey for an account it already has one for.
  From the `ASAuthorizationPlatformPublicKeyCredentialRegistration`, send:

  ```json
  {
    "response": {
      "id": "<credentialID, base64url>",
      "rawId": "<credentialID, base64url>",
      "type": "public-key",
      "response": {
        "clientDataJSON": "<rawClientDataJSON, base64url>",
        "attestationObject": "<rawAttestationObject, base64url>",
        "transports": ["internal", "hybrid"]
      },
      "clientExtensionResults": {},
      "authenticatorAttachment": "platform"
    }
  }
  ```

- Using one: `createCredentialAssertionRequest(challenge:
  b64url(options.challenge))`, with `allowedCredentials` from
  `options.allowCredentials` when there are any (the reauth step has
  them). From the `ASAuthorizationPlatformPublicKeyCredentialAssertion`,
  send:

  ```json
  {
    "response": {
      "id": "<credentialID, base64url>",
      "rawId": "<credentialID, base64url>",
      "type": "public-key",
      "response": {
        "clientDataJSON": "<rawClientDataJSON, base64url>",
        "authenticatorData": "<rawAuthenticatorData, base64url>",
        "signature": "<signature, base64url>",
        "userHandle": "<userID, base64url>"
      },
      "clientExtensionResults": {},
      "authenticatorAttachment": "platform"
    }
  }
  ```

`b64url(...)` means base64url-decoded to `Data`. A response has to come
back within **5 minutes** of its options, and each options answer is good
for one try: after any failure, ask for options again. Someone tapping
Cancel isn't an error to show (iOS `ASAuthorizationError.canceled`,
Android `GetCredentialCancellationException`).

## Keeping the token

The token signs the person in to every Canopy site. Treat it like a
password.

- **iOS**: a Keychain generic password item, with
  `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`. "ThisDeviceOnly"
  keeps it out of iCloud Keychain and out of backups restored onto
  another phone, which should sign in for itself. Keychain items outlive
  deleting the app, so on the first launch after an install (no flag in
  `UserDefaults` yet), delete any token left from before.
- **Android**: encrypt it with a key in the Android Keystore and keep
  the ciphertext in the app's private storage, excluded from backups
  (`dataExtractionRules` / `fullBackupContent`).
- Never log it, never put it in a URL, never send it anywhere but
  `account.canopysf.com` and Canopy sites (`*.canopysf.com`).
- **One token per install.** Signed in already? Sign out
  (`POST /signout`) before signing in as someone else. A sign-in step
  sent with a signed-in token is refused (`409 signed_in`).
- The ceremony value only matters during a sign-in. Keep it in memory.

## Starting: `POST /auth/begin`

No `Authorization`. The body has to be JSON.

```http
POST /api/native/v1/auth/begin
Content-Type: application/json

{"platform": "ios", "app": "Canopy Events", "device": "iPhone"}
```

```json
201 {"ceremony": "Jx3n...43 characters"}
```

`platform` is `ios` or `android` (`400 bad_platform` otherwise). `app`
and `device` are optional, up to 40 characters each, and become the name
in the person's list of where they're signed in ("Canopy Events on
iPhone"). Send the device's **model** (`UIDevice.current.model`,
`Build.MODEL`), not the name its owner gave it.

Every `/auth/*` step after this sends `Authorization: Bearer <ceremony>`.
A missing, unknown or run-out ceremony is `400 expired`: begin again. A
ceremony nobody finishes runs out a day after it was last used. Begin
again for each new attempt; the same ceremony can be reused while it
lasts (to resend a code, say). Each one is counted (see "Limits"), so
don't begin one until the person starts signing in; `429 rate_limited`
means wait.

## Signing in with a passkey

No email: the phone offers whichever Canopy passkey it has.

```http
POST /api/native/v1/auth/passkey/options
Authorization: Bearer <ceremony>

{}
```

```json
200 {"options": {"challenge": "...", "rpId": "canopysf.com", "userVerification": "preferred", "timeout": 60000}}
```

Use a passkey with those (above), then:

```http
POST /api/native/v1/auth/passkey/verify
Authorization: Bearer <ceremony>

{"response": { ...the assertion... }}
```

```json
200 {
  "token": "q3Xb...43 characters",
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
    "findable": true,
    "isAdmin": false
  }
}
```

Keep `token`. The ceremony is worthless now (the session was signed in
under a new token, so a value seen before sign-in never becomes a
signed-in one).

`400 unknown_passkey` means the passkey was removed or reset, or its
account deleted: offer to sign in by email instead.

## Signing in or up with an email code

For someone with no passkey on this phone: a new phone, a lost one, or
someone new.

**1. The email.**

```http
POST /api/native/v1/auth/email/start
Authorization: Bearer <ceremony>

{"email": "ana@example.com"}
```

```json
200 {"verified": false, "email": "ana@example.com"}
```

Every email gets a code, whether it has an account or not; nothing is
said about which until the code is typed. Calling it again sends a new
code, and the old one stops working ("Send a new code"). `400
bad_email`, `429 rate_limited`, `502 mail_failed`.

**2. The code.**

```http
POST /api/native/v1/auth/email/verify
Authorization: Bearer <ceremony>

{"code": "123456"}
```

A code is good for 10 minutes and 5 wrong tries (`403 wrong_code`; after
that, or after 10 minutes, `400 expired`: send a new one). The right one
proves the email on this ceremony for 15 minutes, and says what's next:

```json
200 {"verified": true, "state": "new", "email": "ana@example.com"}
```

```json
200 {"verified": true, "state": "existing", "email": "ana@example.com", "firstName": "Ana", "hasPasskey": true, "unverified": false}
```

**3a. `new`: a new account.** Ask for first and last name (both
required) and optionally their Venmo username.

```http
POST /api/native/v1/auth/register/new
Authorization: Bearer <ceremony>

{"firstName": "Ana", "lastName": "Lima", "venmoHandle": "ana-l"}
```

```json
200 {"options": { ...creation options... }}
```

Make a passkey with them, then `POST /auth/register/verify` (below). The
account is only made once the passkey is, so there's never an account
nobody can get into. Then upload their photo (`POST /me/photo`) with the
new token. `400 names_required`, `400 bad_venmo`, `400 verify_first`
(the proven email ran out: start over), `409 conflict` (the email got an
account in the meantime).

**3b. `existing`: a new passkey for their account, on this phone.**

```http
POST /api/native/v1/auth/register/existing
Authorization: Bearer <ceremony>

{}
```

```json
200 {"options": { ...creation options, with excludeCredentials... }}
```

Then `POST /auth/register/verify`. That signs them in, and proves the
email if it wasn't already.

**When `unverified` is true, say so first.** That account's email was
never proven (a quick sign-up), so whoever made it may not own the
inbox. Finishing here takes it over: **every passkey it had is removed,
every other browser and app is signed out**, leaving this passkey as
the only one, and **its phone, Instagram, Venmo, Cash App and photo are
cleared** (and "findable" goes back to on). That's right for the inbox's
owner, and it's what stops someone squatting on their email. But it also
signs out a real quick sign-up's other phone and empties their profile,
so tell them before they go on, the way the web does. The `firstName`
here is whatever the account's maker typed, and it stays.

**4. The passkey, either way.**

```http
POST /api/native/v1/auth/register/verify
Authorization: Bearer <ceremony>

{"response": { ...the new passkey... }}
```

```json
201 {"token": "q3Xb...", "person": { ... }}
```

After a takeover (above) the answer also has `"tookOver": true`. The name
is still the one its maker typed, so go to the profile next, where they
can change it, as the web does.

`409 passkey_exists` (that passkey is already saved), `400 expired`
(more than 5 minutes, or already tried: ask for options again).

## The quick sign-up

For someone who's never used Canopy, from a part of the app that allows
it (events does; most Canopy sites don't let these accounts in until
their email is proven). First name, last name, email and a passkey: no
code, no photo.

```http
POST /api/native/v1/auth/quick/start
Authorization: Bearer <ceremony>

{"firstName": "Quinn", "lastName": "Quick", "email": "quinn@example.com"}
```

```json
200 {"options": { ...creation options... }}
```

Make a passkey and `POST /auth/register/verify` as above. The account is
**unverified**: `person.emailVerified` is `false` (see "The unverified
banner").

An email that already has an account is told so, rather than making a
second one:

```json
409 {"error": "that email has an account -- sign in instead", "reason": "email_has_account", "email": "quinn@example.com"}
```

Offer **Sign in with passkey** and **Email me a code** (the code flow,
with the email filled in). Quick sign-ups are counted, every try
including these (see "Limits"). `400 names_required`, `400 bad_email`.

## Who's signed in: `GET /me`

```http
GET /api/native/v1/me
Authorization: Bearer <token>
```

```json
200 {"person": { ...as above... }}
```

`photoUrl` loads with the same header (`Authorization: Bearer <token>`);
without it, it's a 404. It's `null` when there's no photo, and its `?v=`
changes whenever the photo does, so it can be cached by URL. Canopy
sites hand out the same URLs for other people's photos, and they load
the same way.

## The unverified banner

When `person.emailVerified` is `false`, show a banner that can't be
closed: confirm your email, and until then some Canopy sites treat you as
signed out. Events lets them in; other sites answer their requests with
`403 email_unverified`. Its button:

```http
POST /api/native/v1/me/verify/start
Authorization: Bearer <token>

{}
```

```json
200 {"ok": true, "verified": false, "email": "quinn@example.com"}
```

(`"verified": true` means there was nothing to confirm: hide the
banner.) Then the code:

```http
POST /api/native/v1/me/verify/check
Authorization: Bearer <token>

{"code": "123456"}
```

```json
200 {"person": { ..., "emailVerified": true }}
```

Same codes and limits as signing in: `403 wrong_code`, `400 expired`,
`429 rate_limited`. Sites see the change on their next ask (they cache
for up to a minute).

## The profile

```http
PATCH /api/native/v1/me
Authorization: Bearer <token>

{"firstName": "Ana", "lastName": "Lima", "phone": "(415) 555-1234", "instagram": "@ana.lima", "venmoHandle": "ana-l", "cashapp": "$AnaL", "findable": true}
```

```json
200 {"person": { ... }}
```

Names are required every time. Every other field is changed only when
it's sent, and `""` clears it. What's typed is cleaned the way the web
cleans it: phone to E.164 (US and Canadian numbers without the +1),
Instagram lowercased with no @ (a pasted link is trimmed to the name),
Venmo without the @, Cash App without the $. `findable` is "Let people
who know your phone number or Instagram find you" (they only ever see
the name and photo). `400 names_required`, `bad_phone`,
`bad_instagram`, `bad_venmo`, `bad_cashapp`.

**The photo:**

```http
POST /api/native/v1/me/photo
Authorization: Bearer <token>
Content-Type: multipart/form-data; boundary=...

--...
Content-Disposition: form-data; name="photo"; filename="photo.jpg"
Content-Type: image/jpeg

<the JPEG>
```

```json
200 {"person": { ..., "photoUrl": "https://account.canopysf.com/photo/...?v=..." }}
```

Crop it square and shrink it on the phone first (the web sends 512 by
512, JPEG quality around 0.88), at most 3 MB. It has to be a JPEG, with
the part's `Content-Type: image/jpeg`. The server takes the metadata out
(EXIF and the rest: where it was taken, the camera, the orientation)
before saving it, so send the pixels upright. `400 no_photo`, `400
bad_photo` (not a JPEG it can read), `400 too_large`, `400 bad_upload`
(not multipart, or the body was cut short).

## Passkeys

```http
GET /api/native/v1/me/passkeys
Authorization: Bearer <token>
```

```json
200 {"passkeys": [{"id": "Kq3...", "createdAt": 1759870000000, "lastUsedAt": 1759956400000, "synced": true, "transports": ["internal", "hybrid"]}]}
```

**Add one** (a phone that doesn't sync, a second device):
`POST /me/passkeys/options` (`{}`) answers creation options; make the
passkey; `POST /me/passkeys/verify` with `{"response": ...}` answers
`201 {"ok": true}`.

**Remove one:** `DELETE /me/passkeys/{id}` (the id URL-encoded). Never
the last one: `409 last_passkey`.

## Changing the email

Three steps, as on the web: their passkey (so someone holding an
unlocked phone can't), a code to the new address, and a notice to the
old one.

1. `POST /me/reauth/options` (`{}`) answers request options for their
   own passkeys, with user verification **required** (Face ID or the
   like). Use one, and `POST /me/reauth/verify` with
   `{"response": ...}` answers `{"ok": true}`. That's good for 15
   minutes and one change.
2. `POST /me/email/start` with `{"email": "ana.new@example.com"}` sends
   a code there and answers `{"ok": true, "email": "ana.new@example.com"}`.
   `403 reauth_required` (step 1 first, or again), `400 same_email`,
   `429 rate_limited` (5 new addresses an hour). An address that already
   has an account answers the same way: its owner gets a notice instead
   of a code, so this is no way to find out who has an account.
3. `POST /me/email/verify` with `{"code": "123456"}` answers
   `{"person": ...}` with the new email, verified. The old address gets
   a notice. `409 email_unavailable` if the address has an account (which
   only its owner, who got no code, could be told).

## Where they're signed in, and signing out

```http
GET /api/native/v1/me/sessions
Authorization: Bearer <token>
```

```json
200 {"sessions": [
  {"id": "3f9a0c1e2b7d4a6f8e5c1d2b", "kind": "ios", "name": "Canopy Events on iPhone", "signedInAt": 1759870000000, "lastSeenAt": 1759956400000, "current": true},
  {"id": "a1b2c3d4e5f60718293a4b5c", "kind": "web", "name": "Safari on Mac", "signedInAt": 1759000000000, "lastSeenAt": 1759900000000, "current": false}
]}
```

Every browser and app signed in as them, most recently seen first.
`name` is `null` when it never said; show something by `kind` then.
`current` is this app.

- **Sign one out:** `DELETE /me/sessions/{id}` answers `{"ok": true,
  "current": false}`. If `current` comes back `true`, that was this app:
  forget the token.
- **Sign out (this app):** `POST /signout` (`{}`) ends this token's
  session, on every Canopy site at once, and always answers `200 {"ok":
  true}`. Delete the token whatever the answer, even with no network.
  Sites may go on showing them for the minute they cache answers.
- **Sign out everywhere:** `POST /signout/everywhere` ends every browser
  and app, this one included.

The person can also do any of this from the web profile, and the admin
can reset their passkeys or delete them. Either way the token stops
working, and the next request gets `401 signed_out`.

## Using the token with Canopy sites

Send `Authorization: Bearer <token>` to every Canopy site's API (events'
`/api/v1`, and whatever comes next). Sites pass it to this service the
same way they pass a browser's cookie, and nothing comes back as a
cookie. An unverified person gets `403 email_unverified` from a site that
doesn't allow them (show the banner), and a `401` means the token is
over.

## Errors

| Status | `reason` | Means | Do |
|---|---|---|---|
| 400 | `bad_platform` | `auth/begin` without `ios` or `android` | Fix the request |
| 400 | `expired` | No ceremony or it ran out; options more than 5 minutes old or already tried; a code ran out | Start that step again (`auth/begin` if it's the ceremony) |
| 400 | `bad_email` | Not an email | Ask again |
| 400 | `verify_first` | The proven email ran out (15 minutes) | Start over with the email |
| 400 | `names_required` | First or last name missing | Ask again |
| 400 | `bad_phone`, `bad_instagram`, `bad_venmo`, `bad_cashapp` | That field can't be one | Say which |
| 400 | `same_email` | Changing to the email they have | |
| 400 | `unknown_passkey` | That passkey isn't linked to an account any more | Offer the email code |
| 400 | `not_verified` | The passkey response didn't check out | Ask for options and try again |
| 400 | `no_photo`, `bad_photo`, `too_large`, `bad_upload` | The upload | Send a JPEG under 3 MB in `photo` |
| 400 | `bad_json` | The body isn't JSON | Fix the request |
| 400 | `bad_request` | The request can't be read (a path with a `%` that doesn't decode) | Fix the request |
| 400 | `no_passkeys` | Passkeys aren't available on this host | A misconfigured server |
| 401 | `signed_out` | The token is over | Delete it, show sign-in |
| 403 | `wrong_code` | Not the code | Let them try again |
| 403 | `reauth_required` | Changing the email needs the passkey step first | Back to step 1 |
| 403 | `setup_required` | The service has no admin yet | Nothing to do from the app |
| 403 | `bad_origin` | No bearer header (or `auth/begin` without JSON) | Fix the request |
| 404 | `not_found` | No such passkey or session of theirs | Refresh the list |
| 409 | `signed_in` | A sign-in step with a signed-in token | Sign out first, or use a ceremony |
| 409 | `email_has_account` | The quick sign-up's email has an account | Offer passkey sign-in or a code |
| 409 | `conflict` | The email got an account in the meantime | Sign in instead |
| 409 | `passkey_exists` | That passkey is already saved | |
| 409 | `last_passkey` | It's their only passkey | Add another first |
| 409 | `email_unavailable` | At the code step: the new email has an account | Ask for another |
| 429 | `rate_limited` | Too many tries | Wait a few minutes |
| 500 | `server_error` | Something went wrong here | Try again; report it if it keeps happening |
| 502 | `mail_failed` | The email couldn't be sent | Try again later |

## Limits

The app and the web count in the same counters, so these are shared:

| What | Per who | Per address | Everyone |
|---|---|---|---|
| Sending a code (sign-in, confirming, changing the email) | 5 per email per hour | 20 per hour | 100 per hour |
| Wrong codes | 10 per email per 15 min | 40 per 15 min | 300 per hour |
| Quick sign-up tries | 10 per ceremony per 15 min | 20 per hour | 200 per hour |
| Quick accounts made | | 10 per hour | 50 per hour |
| `auth/begin` (and browsers starting a sign-in with no cookie) | | 100 per hour | 1,000 per hour |

On top of that, each code dies after 5 wrong tries. "Address" is the
phone's network address, so a party on one wifi shares it.

## Trying it out

The server's own tests (`test/native.test.js`) run every flow above with
a software passkey that signs as the iOS or Android app, and are the
quickest way to see the exact requests. Real passkeys need the real
domain: a phone won't use a `canopysf.com` passkey for a server on
`localhost`. Point a development build at `https://account.canopysf.com`
(or a deployment under `canopysf.com` with the association files in
place).

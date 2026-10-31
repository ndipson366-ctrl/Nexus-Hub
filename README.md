# Nexus Hub

Link hub with a signup landing page, viewer login, and an admin login that is gated by a
"two free logins, then the owner must approve" rule. Links live on the server.

## Run it on your own computer (needs Node 22.5 or newer)

    npm install
    npm start

Open http://localhost:3000. The first person who signs up as **Admin** becomes the **owner**.

## How the rules work

* **Signup page** is the landing page. "Admin login" and "Viewer login" buttons are at the bottom.
* **Viewer** accounts must be **accepted by an admin** before they can log in (bell icon or the Members screen). Once accepted they can see and launch links, nothing else.
* **Members screen (admins):** lists everyone with their role. Admins can accept or decline new viewers, **Make admin** (promote an accepted viewer), and **Remove** a member (signs them out at once; the username can be used again). Only the owner can remove other admins, and the owner account can't be removed.
* A promoted viewer becomes a normal admin, so the two-free-logins-then-approval rule applies to them from then on.
* **Admin** accounts: the first one is the owner. Later admin signups wait until the owner accepts them (bell icon).
* **Admin login rule (per account):** logins 1 and 2 are automatic. From login 3 on, the person is held on a
  "Waiting for approval" screen and the owner gets a live notification (toast + bell badge, optional desktop alert,
  optional phone push) with **Accept** / **Decline**. Accept signs the waiting browser in; Decline or no answer
  within `APPROVAL_TTL_MINUTES` rejects it.
* The login counter is stored in the database and bumped by one atomic SQL statement, so clearing browser data or
  firing many logins at once cannot get more than two free logins.
* The owner's own 3rd+ login must be approved from another browser/device where the owner is already logged in.
  If you are locked out: `npm run admin -- approve-login <id>` (the waiting screen shows the id),
  or `npm run admin -- reset-logins <username>` to hand out two fresh free logins.

## Notifications (delivery choice)

On a normal server the owner's page gets live pushes. On Netlify (no always-on process) the admin page checks every 10 seconds instead; everything else behaves the same.

Server-Sent Events: the owner's open page keeps a one-way stream open and the server pushes events to it.
It is the simplest reliable option here (no extra service, auto-reconnects). If the owner is not logged in anywhere,
the request simply waits; it is shown the next time they open the app. Set `NOTIFY_URL` (ntfy.sh) for push to a phone.

## Security notes

* Passwords are hashed with bcrypt (cost 12). Sessions are random tokens in an HttpOnly cookie, stored hashed.
* Run it behind HTTPS if it is on the internet, and set `TRUST_PROXY=1` there.
* Set `OWNER_SETUP_CODE` before exposing it publicly so no one else can claim the owner account first.
* Login attempts are rate-limited per address + username. Rate limits reset when the server restarts.
* Local mode stores data in `data/nexushub.db` (back it up; deleting it resets everything). When `TURSO_DATABASE_URL` is set, data lives in Turso instead.

## Server tool

    npm run admin -- list
    npm run admin -- approve-login 7
    npm run admin -- approve-account someadmin
    npm run admin -- reset-password someuser "new password"
    npm run admin -- reset-logins someadmin

## Files

    server.js      HTTP server, routes, auth + approval logic
    db.js          SQLite schema (users, sessions, login_attempts, links)
    admin-cli.js   recovery commands
    public/index.html   the whole front end

## Putting it online for free

See **DEPLOY.md** (GitHub + Turso + Netlify, all free tiers).

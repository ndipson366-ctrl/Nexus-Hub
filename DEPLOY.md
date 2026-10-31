# Deploy Nexus Hub for free (GitHub + Turso + Netlify)

| Piece | Job | Free tier notes |
|---|---|---|
| GitHub | holds your code so Netlify can pull it | free account |
| Turso | stores accounts, login counts, links | free plan, no card listed on their pricing page |
| Netlify | serves the page and runs the API as a function | free plan has a hard monthly limit (300 credits): when it runs out the site pauses, it does not bill you |

Everything below can be done from home. Only *opening* the finished site needs to work on the school network.

## 1. Turso (the database)
1. Sign up at https://turso.tech (GitHub login is fine).
2. Create a database (any name, nearest region).
3. Copy its **URL** (starts with `libsql://`).
4. Create/copy an **auth token** for that database. Treat it like a password. Never put it on GitHub.

## 2. GitHub (the code)
Create a free GitHub account, make an empty repository (no README), then in the `nexus-hub` folder:
```
git init
git add .
git commit -m "Nexus Hub"
git remote add origin https://github.com/YOUR-NAME/nexus-hub.git
git branch -M main
git push -u origin main
```
`.gitignore` keeps `node_modules`, `data` and `.env` out. Check they did not get uploaded.

## 3. Netlify (the website + API)
1. Sign up at https://netlify.com (GitHub login is easiest).
2. Add a new project > **Import an existing project** > GitHub > pick `nexus-hub`.
3. Netlify reads `netlify.toml` by itself (publish folder `public`, functions in `netlify/functions`). Leave the build command empty.
4. Before deploying, add **environment variables** (project settings; menu names can differ a little):
   - `TURSO_DATABASE_URL` = the libsql:// URL
   - `TURSO_AUTH_TOKEN` = the token
   - `OWNER_SETUP_CODE` = a long secret only you know  **(set this before anyone visits)**
   - leave their scopes on "all", so the function can read them
5. Deploy. You get `https://something.netlify.app`. If you add or change variables later, redeploy.
6. Optional: change the site name (domain settings) to something that looks ordinary.

## 4. First run
1. Open your address, choose **Admin**, enter your setup code, create the account. You are the owner.
2. Log in with Admin login, then add links with Bulk Add (or Upload JSON from your old copy).
3. **Test the address on the school network before sharing it.**

## How it differs from a normal server
- There is no always-on process. Each request wakes a small function; all data stays in Turso.
- **Live alerts become polling:** an admin's open page checks for new requests every 10 seconds while the tab is visible.
  So the owner sees an approval request within about 10 seconds instead of instantly. Waiting users see approval within about 3 seconds.
- Phone alerts still work: set `NOTIFY_URL` to an ntfy.sh topic (https://ntfy.sh).
- Free usage: Netlify counts requests and compute time. A few people using the site is far below the limit.
  Leaving an admin tab open all day is the biggest use, which is why polling pauses when the tab is hidden.
- A single request is limited to about 6 MB on Netlify. Uploaded logos are shrunk to small images, so this only matters for huge bulk uploads.

## If something goes wrong
- Site loads but login says "Server error": open the Netlify project > Functions > `api` > logs, and check that both `TURSO_*` variables are set (then redeploy).
- Locked out / forgot owner password: put the same `TURSO_*` values in a local `.env` and run `npm run admin -- list` (see README).
- Updating the app later: `git push`; Netlify redeploys automatically.

## Running it on your own computer instead
`npm install` then `npm start` (Node 22.5+). With no `TURSO_*` variables it stores data in `data/nexushub.db`, and admins get instant push alerts.

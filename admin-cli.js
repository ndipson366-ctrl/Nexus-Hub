'use strict';
// Server-side recovery tool. Run it wherever the app's environment variables are set
// (on your own computer with a .env file, or in Render's Shell if you have one):
//   npm run admin -- list
//   npm run admin -- approve-login <id>      decline-login <id>
//   npm run admin -- approve-account <username>
//   npm run admin -- reset-password <username> <new password>
//   npm run admin -- reset-logins <username>   (gives an admin 2 fresh free logins)
// If TURSO_DATABASE_URL and TURSO_AUTH_TOKEN are set (in .env or the environment), this edits the live hosted database.
require('./env');
const bcrypt = require('bcryptjs');
const { db } = require('./db');

const [cmd, a, b] = process.argv.slice(2);
const now = Date.now();
const need = (v, what) => { if (!v) { console.error('Missing ' + what + '. See the usage at the top of admin-cli.js'); process.exit(1); } };

async function main() {
  await db.init();
  switch (cmd) {
    case 'list': {
      console.log('\nUsers:');
      for (const u of await db.all('SELECT id, username, role, is_owner, status, login_count FROM users ORDER BY id')) {
        console.log(`  #${u.id} ${u.username}  role=${u.role}${u.is_owner ? ' (owner)' : ''}  status=${u.status}  logins=${u.login_count}`);
      }
      console.log('\nLogin requests waiting for approval:');
      const rows = await db.all(`SELECT a.id, u.username, a.ip, a.created_at FROM login_attempts a JOIN users u ON u.id = a.user_id
                                 WHERE a.status = 'pending' AND a.expires_at > ? ORDER BY a.id`, [now]);
      if (!rows.length) console.log('  (none)');
      for (const r of rows) console.log(`  #${r.id} ${r.username} from ${r.ip} at ${new Date(r.created_at).toLocaleString()}`);
      break;
    }
    case 'approve-login':
    case 'decline-login': {
      need(a, 'login request id');
      const r = await db.run("UPDATE login_attempts SET status = ?, decided_at = ? WHERE id = ? AND status = 'pending' AND expires_at > ?",
        [cmd === 'approve-login' ? 'approved' : 'declined', now, Number(a), now]);
      console.log(r.changes ? 'Done.' : 'No pending request with that id (already handled or expired).');
      break;
    }
    case 'approve-account': {
      need(a, 'username');
      const r = await db.run("UPDATE users SET status = 'active' WHERE username = ? AND status = 'pending'", [a]);
      console.log(r.changes ? 'Account approved.' : 'No pending account with that name.');
      break;
    }
    case 'reset-password': {
      need(a, 'username'); need(b, 'new password');
      if (b.length < 8 || Buffer.byteLength(b) > 72) { console.error('Password must be at least 8 characters (max 72 bytes).'); process.exit(1); }
      const u = await db.get('SELECT id FROM users WHERE username = ?', [a]);
      if (!u) { console.log('No such user.'); break; }
      await db.batch([
        { sql: 'UPDATE users SET password_hash = ? WHERE id = ?', args: [bcrypt.hashSync(b, 12), u.id] },
        { sql: 'DELETE FROM sessions WHERE user_id = ?', args: [u.id] }
      ]);
      console.log('Password changed and existing sessions signed out.');
      break;
    }
    case 'reset-logins': {
      need(a, 'username');
      const r = await db.run("UPDATE users SET login_count = 0 WHERE username = ? AND role = 'admin'", [a]);
      console.log(r.changes ? 'Free login counter reset.' : 'No admin with that name.');
      break;
    }
    default:
      console.log('Commands: list | approve-login <id> | decline-login <id> | approve-account <username> | reset-password <username> <new password> | reset-logins <username>');
  }
}
main().then(() => process.exit(0), e => { console.error(e.message || e); process.exit(1); });

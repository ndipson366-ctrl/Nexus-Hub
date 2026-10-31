'use strict';
const BASE_DIR = typeof __dirname !== 'undefined' ? __dirname : process.cwd();   // __dirname does not exist once bundled as an ES module
// Storage layer. One small async interface, two drivers:
//   * Turso / libSQL (hosted SQLite)  when TURSO_DATABASE_URL is set  -> used in production
//   * a local SQLite file via Node's built-in node:sqlite              -> used for local development
//
//   await db.get(sql, args)    -> first row as a plain object, or undefined
//   await db.all(sql, args)    -> array of plain objects
//   await db.run(sql, args)    -> { changes, lastInsertRowid }
//   await db.batch([{sql,args}, ...])  -> runs all statements atomically (all or nothing)
//   await db.init()            -> creates the tables if they do not exist yet
const fs = require('node:fs');
const path = require('node:path');

const SCHEMA = [
  `CREATE TABLE IF NOT EXISTS users (
     id            INTEGER PRIMARY KEY AUTOINCREMENT,
     username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
     password_hash TEXT NOT NULL,
     role          TEXT NOT NULL CHECK (role IN ('admin','viewer')),
     is_owner      INTEGER NOT NULL DEFAULT 0,
     status        TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','pending','declined')),
     login_count   INTEGER NOT NULL DEFAULT 0,
     created_at    INTEGER NOT NULL
   )`,
  // at most one owner (the first admin), enforced by the database itself
  `CREATE UNIQUE INDEX IF NOT EXISTS one_owner ON users(is_owner) WHERE is_owner = 1`,
  `CREATE TABLE IF NOT EXISTS sessions (
     token_hash TEXT PRIMARY KEY,
     user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
     expires_at INTEGER NOT NULL
   )`,
  `CREATE TABLE IF NOT EXISTS login_attempts (
     id          INTEGER PRIMARY KEY AUTOINCREMENT,
     user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
     claim_hash  TEXT NOT NULL,
     status      TEXT NOT NULL DEFAULT 'pending'
                 CHECK (status IN ('pending','approved','declined','expired','cancelled','claimed')),
     ip          TEXT,
     user_agent  TEXT,
     created_at  INTEGER NOT NULL,
     expires_at  INTEGER NOT NULL,
     decided_at  INTEGER
   )`,
  `CREATE TABLE IF NOT EXISTS links (
     id         INTEGER PRIMARY KEY AUTOINCREMENT,
     title      TEXT NOT NULL,
     url        TEXT NOT NULL UNIQUE,
     category   TEXT NOT NULL DEFAULT '',
     status     TEXT NOT NULL DEFAULT 'Testing' CHECK (status IN ('Working','Testing','Down')),
     logo       TEXT NOT NULL DEFAULT '',
     created_at INTEGER NOT NULL
   )`
];

function makeTursoDriver(url, authToken) {
  const { createClient } = require('@libsql/client/web');      // pure-JS HTTP client: no native binary, works on serverless hosts
  const client = createClient({ url, authToken });
  const plain = rs => rs.rows.map(row => {
    const o = {};
    rs.columns.forEach((c, i) => { o[c] = row[c] !== undefined ? row[c] : row[i]; });
    return o;
  });
  return {
    name: 'turso',
    async get(sql, args = []) { return plain(await client.execute({ sql, args }))[0]; },
    async all(sql, args = []) { return plain(await client.execute({ sql, args })); },
    async run(sql, args = []) {
      const r = await client.execute({ sql, args });
      return { changes: Number(r.rowsAffected || 0), lastInsertRowid: Number(r.lastInsertRowid || 0) };
    },
    async batch(stmts) {
      const out = await client.batch(stmts.map(s => ({ sql: s.sql, args: s.args || [] })), 'write');
      return out.map(r => ({ changes: Number(r.rowsAffected || 0) }));
    },
    async init() { await client.batch(SCHEMA.map(sql => ({ sql, args: [] })), 'write'); }
  };
}

function makeFileDriver(file) {
  const sqliteModule = 'node:sqlite';                       // needs Node 22.5+; loaded only for local development (kept out of bundlers)
  const { DatabaseSync } = require(sqliteModule);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const raw = new DatabaseSync(file);
  raw.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;');
  const rows = (sql, args) => raw.prepare(sql).all(...args).map(r => ({ ...r }));
  return {
    name: 'file',
    async get(sql, args = []) { return rows(sql, args)[0]; },
    async all(sql, args = []) { return rows(sql, args); },
    async run(sql, args = []) {
      const r = raw.prepare(sql).run(...args);
      return { changes: Number(r.changes), lastInsertRowid: Number(r.lastInsertRowid) };
    },
    async batch(stmts) {
      raw.exec('BEGIN IMMEDIATE');
      try {
        const out = stmts.map(s => ({ changes: Number(raw.prepare(s.sql).run(...(s.args || [])).changes) }));
        raw.exec('COMMIT');
        return out;
      } catch (e) {
        try { raw.exec('ROLLBACK'); } catch (_) { /* already rolled back */ }
        throw e;
      }
    },
    async init() { SCHEMA.forEach(sql => raw.exec(sql)); }
  };
}

const TURSO_URL = process.env.TURSO_DATABASE_URL || '';
const db = TURSO_URL
  ? makeTursoDriver(TURSO_URL, process.env.TURSO_AUTH_TOKEN || undefined)
  : makeFileDriver(process.env.DB_PATH || path.join(BASE_DIR, 'data', 'nexushub.db'));

module.exports = { db };

'use strict';
const BASE_DIR = typeof __dirname !== 'undefined' ? __dirname : process.cwd();   // __dirname does not exist once bundled as an ES module
// Tiny .env loader (KEY=value lines). Real environment variables win over the file.
const fs = require('node:fs');
const path = require('node:path');

try {
  const text = fs.readFileSync(path.join(BASE_DIR, '.env'), 'utf8');
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const i = line.indexOf('=');
    if (i < 1) continue;
    const key = line.slice(0, i).trim();
    const val = line.slice(i + 1).trim().replace(/^(['"])(.*)\1$/, '$2');
    if (!(key in process.env)) process.env[key] = val;
  }
} catch (e) { /* no .env file, that's fine */ }

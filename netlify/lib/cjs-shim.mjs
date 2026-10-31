// Bundlers turn this function into one ES-module file, but the app code (server.js, db.js) is CommonJS and calls require().
// This module runs first and makes `require` available, so those calls keep working after bundling.
import { createRequire } from 'node:module';

if (typeof globalThis.require === 'undefined') globalThis.require = createRequire(import.meta.url);

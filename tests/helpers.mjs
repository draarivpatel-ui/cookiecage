import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import * as esm from '../src/index.mjs';

const require = createRequire(import.meta.url);
const cjs = require('../cjs/index.cjs');

export { esm, cjs };
export const MODULES = [
  ['ESM', esm],
  ['CJS', cjs]
];

export const SECRET = 'R7v2Q9x4M1z8K3p6T0b5N2c8V4x1Z7a9Q3';
export const SECRET_ALT = 'M8z1K6x3Q0v7R4p9T2b5N1c7V3x6Z0a4Q8';

export function testSecret(label = '') {
  return SECRET + label;
}

export function throwsCode(fn, code, message) {
  let error;
  try {
    fn();
  } catch (caught) {
    error = caught;
  }
  assert.ok(error, message || 'expected function to throw');
  assert.equal(error.name, 'CookieCageError', message);
  assert.equal(error.code, code, message || 'unexpected error code');
  return error;
}

export function withProtoKey() {
  return JSON.parse('{"__proto__":{"polluted":true}}');
}

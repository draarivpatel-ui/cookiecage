import test from 'node:test';
import assert from 'node:assert/strict';
import { esm as api, SECRET } from './helpers.mjs';

const {
  CookieCageError,
  parseCookieHeader,
  serializeCookie,
  signCookieValue,
  verifyCookieValue
} = api;

function lcg(seed) {
  let state = seed >>> 0;
  return function next() {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    return state;
  };
}

function cookieErrorOrNull(fn) {
  try {
    return { value: fn(), error: null };
  } catch (error) {
    return { value: null, error };
  }
}

test('fixed-seed mutated Cookie headers only produce CookieCageError or safe objects', () => {
  const next = lcg(0xC00C1E);
  const alphabet = 'abcXYZ019;= %"\t\r\n\\\u00e9';
  for (let iteration = 0; iteration < 200; iteration += 1) {
    const length = 1 + (next() % 40);
    let header = '';
    for (let index = 0; index < length; index += 1) {
      header += alphabet[next() % alphabet.length];
    }
    const outcome = cookieErrorOrNull(() => parseCookieHeader(header));
    if (outcome.error) {
      assert.ok(outcome.error instanceof CookieCageError, 'unexpected error type at iteration ' + iteration);
      assert.match(outcome.error.code, /^ERR_COOKIECAGE_/);
    } else {
      assert.equal(Object.getPrototypeOf(outcome.value), null, 'prototype at iteration ' + iteration);
    }
    assert.equal({}.polluted, undefined);
  }
});

test('fixed-seed duplicate-heavy headers never pollute prototypes', () => {
  const next = lcg(0xD0B1CAFE);
  for (let iteration = 0; iteration < 100; iteration += 1) {
    const count = 1 + (next() % 12);
    const parts = [];
    for (let index = 0; index < count; index += 1) {
      const name = ['sid', 'sid', 'theme', 'constructor', '__proto__'][next() % 5];
      parts.push(name + '=v' + index);
    }
    const outcome = cookieErrorOrNull(() => parseCookieHeader(parts.join('; '), { duplicatePolicy: 'last' }));
    if (outcome.error) {
      assert.ok(outcome.error instanceof CookieCageError, 'unexpected error type at iteration ' + iteration);
    } else {
      assert.equal(Object.getPrototypeOf(outcome.value), null);
    }
    assert.equal({}.polluted, undefined);
  }
});

test('fixed-seed signed-value mutations never produce platform type errors', () => {
  const signed = signCookieValue('sid', 'abc', SECRET, { now: 1000, maxAge: 60 });
  const next = lcg(0x516EED);
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.';
  for (let iteration = 0; iteration < 150; iteration += 1) {
    const position = next() % signed.length;
    let replacement = alphabet[next() % alphabet.length];
    if (replacement === signed[position]) replacement = replacement === 'A' ? 'B' : 'A';
    const mutated = signed.slice(0, position) + replacement + signed.slice(position + 1);
    const outcome = cookieErrorOrNull(() => verifyCookieValue('sid', mutated, SECRET, { now: 1000 }));
    if (outcome.error) {
      assert.ok(outcome.error instanceof CookieCageError, 'unexpected error type at iteration ' + iteration);
      assert.match(outcome.error.code, /^ERR_COOKIECAGE_/);
    } else {
      assert.fail('mutation unexpectedly verified at iteration ' + iteration);
    }
  }
});

test('fixed-seed percent-encoding round trips preserve Unicode application values', () => {
  const next = lcg(0xABCDEF);
  const alphabet = 'ab ;,%\\\u00e9\u2603';
  for (let iteration = 0; iteration < 80; iteration += 1) {
    const length = 1 + (next() % 24);
    let logical = '';
    for (let index = 0; index < length; index += 1) {
      logical += alphabet[next() % alphabet.length];
    }
    const serialized = serializeCookie('x', logical, { encodeValue: true, maxSerializedBytes: 5000 });
    const encoded = serialized.slice('x='.length, serialized.indexOf(';'));
    const parsed = parseCookieHeader('x=' + encoded, { decodeValues: true });
    assert.equal(parsed.x, logical, 'round trip at iteration ' + iteration);
  }
});

test('fixed-seed malformed percent sequences fail cleanly', () => {
  const next = lcg(0xFEED);
  const hex = '0123456789abcdefxyz%';
  for (let iteration = 0; iteration < 120; iteration += 1) {
    let value = 'a%';
    value += hex[next() % hex.length];
    if (next() % 2 === 0) value += hex[next() % hex.length];
    const outcome = cookieErrorOrNull(() => parseCookieHeader('x=' + value));
    if (outcome.error) {
      assert.ok(outcome.error instanceof CookieCageError, 'unexpected error type at iteration ' + iteration);
    } else {
      assert.equal(typeof outcome.value.x, 'string');
    }
  }
});

test('fixed-seed oversized inputs stay within configured rejection behavior', () => {
  const next = lcg(0xB01000);
  for (let iteration = 0; iteration < 30; iteration += 1) {
    const size = 16000 + (next() % 20000);
    const header = 'x=' + 'a'.repeat(size);
    const outcome = cookieErrorOrNull(() => parseCookieHeader(header));
    assert.ok(outcome.error instanceof CookieCageError, 'unexpected error type at iteration ' + iteration);
    assert.equal(outcome.error.code, api.CODE.LIMIT_EXCEEDED);
  }
});

test('inherited Object.prototype serialize options are ignored', () => {
  Object.defineProperty(Object.prototype, 'domain', {
    value: 'attacker.example',
    configurable: true,
    enumerable: false
  });
  try {
    const output = serializeCookie('sid', 'abc', {});
    assert.equal(output.includes('Domain='), false);
  } finally {
    delete Object.prototype.domain;
  }
});

test('inherited Object.prototype parse options are ignored', () => {
  Object.defineProperty(Object.prototype, 'duplicatePolicy', {
    value: 'last',
    configurable: true,
    enumerable: false
  });
  try {
    assert.throws(() => parseCookieHeader('sid=one; sid=two', {}), { code: api.CODE.DUPLICATE });
  } finally {
    delete Object.prototype.duplicatePolicy;
  }
});

test('inherited Object.prototype guard sections are ignored', () => {
  Object.defineProperty(Object.prototype, 'parse', {
    value: { duplicatePolicy: 'last' },
    configurable: true,
    enumerable: false
  });
  try {
    const guard = api.createCookieJarGuard({});
    assert.throws(() => guard.parse('sid=one; sid=two'), { code: api.CODE.DUPLICATE });
  } finally {
    delete Object.prototype.parse;
  }
});

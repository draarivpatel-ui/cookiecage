import test from 'node:test';
import assert from 'node:assert/strict';
import fc from 'fast-check';
import {
  CODE,
  CookieCageError,
  parseCookieHeader,
  serializeCookie
} from '../src/index.mjs';

function outcome(fn) {
  try {
    return { value: fn(), error: null };
  } catch (error) {
    return { value: null, error };
  }
}

const hostileUnit = fc.constantFrom(
  '', 'a', 'sid', 'theme', '=', ';', ',', ' ', '%', '%zz', '%41', '\\', '"', '\r', '\n', '\0', '\t', '__proto__', 'constructor', 'prototype', 'é', '文件'
);
const hostileText = fc.string({ unit: hostileUnit, minLength: 1, maxLength: 18 });

test('fast-check hostile Cookie headers either fail closed or produce null-prototype objects', () => {
  fc.assert(fc.property(hostileText, (header) => {
    const result = outcome(() => parseCookieHeader(header));
    if (result.error) {
      assert.ok(result.error instanceof CookieCageError, 'unexpected error type');
      assert.match(result.error.code, /^ERR_COOKIECAGE_/);
    } else {
      assert.equal(Object.getPrototypeOf(result.value), null);
      for (const value of Object.values(result.value)) {
        assert.equal(typeof value, 'string');
      }
    }
    assert.equal({}.polluted, undefined);
  }), { seed: 0xc001e5, numRuns: 240 });
});

test('fast-check duplicate and prototype-heavy Cookie headers never pollute Object.prototype', () => {
  const name = fc.constantFrom('sid', 'theme', '__proto__', 'constructor', 'prototype');
  fc.assert(fc.property(fc.array(name, { minLength: 1, maxLength: 14 }), (names) => {
    const header = names.map((part, index) => part + '=v' + index).join('; ');
    const result = outcome(() => parseCookieHeader(header, { duplicatePolicy: 'last' }));
    if (result.error) {
      assert.ok(result.error instanceof CookieCageError, 'unexpected error type');
      assert.match(result.error.code, /^ERR_COOKIECAGE_/);
    } else {
      assert.equal(Object.getPrototypeOf(result.value), null);
    }
    assert.equal({}.polluted, undefined);
    assert.equal(Object.prototype.polluted, undefined);
  }), { seed: 0xd0b1ca, numRuns: 180 });
});

test('fast-check CR LF and NUL insertion in cookie values always fails closed', () => {
  const safeUnit = fc.constantFrom('a', 'b', 'x', '1', '!', '#', '$', '%', '&', "'", '+', '-', '.', '^', '_', '`', '|', '~');
  const safeValue = fc.string({ unit: safeUnit, minLength: 0, maxLength: 24 });
  fc.assert(fc.property(safeValue, safeValue, fc.constantFrom('\r', '\n', '\0'), (left, right, marker) => {
    assert.throws(
      () => serializeCookie('sid', left + marker + right),
      (error) => {
        const expected = marker === '\0' ? CODE.CONTROL_CHARACTER : CODE.CRLF;
        return error instanceof CookieCageError && error.code === expected;
      }
    );
  }), { seed: 0xc21f00, numRuns: 160 });
});

test('fast-check percent-encoded round trips preserve printable Unicode application values', () => {
  const printableUnicode = fc.string({ unit: 'grapheme', minLength: 0, maxLength: 24 });
  fc.assert(fc.property(printableUnicode, (logical) => {
    const serialized = serializeCookie('x', logical, { encodeValue: true });
    assert.equal(/[\r\n\0]/.test(serialized), false);
    const end = serialized.indexOf(';');
    const encoded = serialized.slice('x='.length, end);
    const parsed = parseCookieHeader('x=' + encoded, { decodeValues: true });
    assert.equal(parsed.x, logical);
  }), { seed: 0xabcde1, numRuns: 160 });
});

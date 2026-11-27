import test from 'node:test';
import assert from 'node:assert/strict';
import { esm as api, throwsCode, withProtoKey, SECRET, SECRET_ALT } from './helpers.mjs';

const {
  CODE,
  serializeCookie,
  signCookieValue,
  verifyCookieValue
} = api;

function mutateChar(text, index) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  const current = text[index];
  const replacement = alphabet[(alphabet.indexOf(current) + 1) % alphabet.length] || 'A';
  return text.slice(0, index) + replacement + text.slice(index + 1);
}

function keyring(keys) {
  return { keys };
}

test('signing empty payload uses deterministic v1 format', () => {
  assert.equal(
    signCookieValue('empty', '', SECRET, { now: 1000 }),
    'v1.k1.0..qHohauOzDWHA1AXppYQ_-QSBpPpBLHl-8vZhA__FZ4g'
  );
});

test('signing without expiration uses deterministic v1 format', () => {
  assert.equal(
    signCookieValue('sid', 'abc', SECRET, { now: 1000 }),
    'v1.k1.0.YWJj.QygAEVqmekwbtiN6WicgqBx9-Fx8wteKEH-3zdyIp8k'
  );
});

test('signing with maxAge embeds an expiration in the MAC input', () => {
  assert.equal(
    signCookieValue('sid', 'abc', SECRET, { now: 1000, maxAge: 60 }),
    'v1.k1.61000.YWJj.B_f2E9doemWTRGfUy7g7zAbF0d9_TyUxH-cqfXkVXug'
  );
});

test('signing UTF-8 text round-trips exactly', () => {
  const signed = signCookieValue('prefs', 'dark mode café', SECRET, { now: 1000 });
  const verified = verifyCookieValue('prefs', signed, SECRET, { now: 1001 });
  assert.equal(verified.value, 'dark mode café');
});

test('verification result shape is exact and frozen', () => {
  const signed = signCookieValue('sid', 'abc', SECRET, { now: 1000, maxAge: 60 });
  const verified = verifyCookieValue('sid', signed, SECRET, { now: 2000 });
  assert.equal(verified.value, 'abc');
  assert.equal(verified.keyId, 'k1');
  assert.equal(verified.rotated, false);
  assert.equal(verified.expiresAt, 61000);
  assert.equal(Object.getPrototypeOf(verified), null);
  assert.equal(Object.isFrozen(verified), true);
});

test('verification without expiration reports null expiresAt', () => {
  const signed = signCookieValue('sid', 'abc', SECRET, { now: 1000 });
  assert.equal(verifyCookieValue('sid', signed, SECRET, { now: 2000 }).expiresAt, null);
});

test('empty value round-trips exactly', () => {
  const signed = signCookieValue('sid', '', SECRET, { now: 1000 });
  assert.equal(verifyCookieValue('sid', signed, SECRET, { now: 1000 }).value, '');
});

test('signed output uses only cookie-safe ASCII characters', () => {
  const signed = signCookieValue('sid', 'unicode \u2603 value', SECRET, { now: 1000 });
  assert.match(signed, /^[\x21\x23-\x2B\x2D-\x3A\x3C-\x5B\x5D-\x7E]+$/);
  assert.equal(signed.includes('\r'), false);
  assert.equal(signed.includes('\n'), false);
});

test('signed output can be serialized as a hardened cookie value', () => {
  const signed = signCookieValue('sid', 'abc', SECRET, { now: 1000 });
  assert.match(serializeCookie('sid', signed), new RegExp('^sid=' + signed.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + ';'));
});

test('expiration remains valid one millisecond before the boundary', () => {
  const signed = signCookieValue('sid', 'abc', SECRET, { now: 1000, maxAge: 60 });
  assert.equal(verifyCookieValue('sid', signed, SECRET, { now: 60999 }).value, 'abc');
});

test('expiration is invalid at the exact expiration boundary', () => {
  const signed = signCookieValue('sid', 'abc', SECRET, { now: 1000, maxAge: 60 });
  throwsCode(() => verifyCookieValue('sid', signed, SECRET, { now: 61000 }), CODE.EXPIRED);
});

test('expiration is invalid after the expiration boundary', () => {
  const signed = signCookieValue('sid', 'abc', SECRET, { now: 1000, maxAge: 60 });
  throwsCode(() => verifyCookieValue('sid', signed, SECRET, { now: 61001 }), CODE.EXPIRED);
});

test('Date clock override is accepted for signing and verification', () => {
  const signed = signCookieValue('sid', 'abc', SECRET, { now: new Date(1000), maxAge: 10 });
  assert.equal(verifyCookieValue('sid', signed, SECRET, { now: new Date(2000) }).value, 'abc');
});

test('cross-cookie substitution into another cookie name is rejected', () => {
  const signed = signCookieValue('preference', 'abc', SECRET, { now: 1000 });
  throwsCode(() => verifyCookieValue('session', signed, SECRET, { now: 1000 }), CODE.SIGNATURE);
});

test('cross-cookie substitution is rejected even when values are identical', () => {
  const signed = signCookieValue('a', 'same-value', SECRET, { now: 1000 });
  throwsCode(() => verifyCookieValue('b', signed, SECRET, { now: 1000 }), CODE.SIGNATURE);
});

test('changing the embedded key id is rejected even for the same secret', () => {
  const ring = keyring([
    { id: 'k1', secret: SECRET },
    { id: 'k2', secret: SECRET }
  ]);
  const signed = signCookieValue('sid', 'abc', ring, { now: 1000 });
  const forged = signed.replace('.k1.', '.k2.');
  throwsCode(() => verifyCookieValue('sid', forged, ring, { now: 1000 }), CODE.SIGNATURE);
});

test('verification with a wrong secret is rejected', () => {
  const signed = signCookieValue('sid', 'abc', SECRET, { now: 1000 });
  throwsCode(() => verifyCookieValue('sid', signed, SECRET_ALT, { now: 1000 }), CODE.SIGNATURE);
});

test('payload tampering is rejected', () => {
  const signed = signCookieValue('sid', 'abc', SECRET, { now: 1000 });
  const parts = signed.split('.');
  const mutated = mutateChar(parts[3], 0);
  parts[3] = mutated;
  throwsCode(() => verifyCookieValue('sid', parts.join('.'), SECRET, { now: 1000 }), CODE.SIGNATURE);
});

test('MAC tampering is rejected', () => {
  const signed = signCookieValue('sid', 'abc', SECRET, { now: 1000 });
  const parts = signed.split('.');
  parts[4] = mutateChar(parts[4], 0);
  throwsCode(() => verifyCookieValue('sid', parts.join('.'), SECRET, { now: 1000 }), CODE.SIGNATURE);
});

test('expiration field tampering is rejected', () => {
  const signed = signCookieValue('sid', 'abc', SECRET, { now: 1000, maxAge: 60 });
  const forged = signed.replace('.61000.', '.61001.');
  throwsCode(() => verifyCookieValue('sid', forged, SECRET, { now: 1000 }), CODE.SIGNATURE);
});

test('key id field tampering is rejected', () => {
  const signed = signCookieValue('sid', 'abc', SECRET, { now: 1000 });
  const forged = signed.replace('.k1.', '.k9.');
  throwsCode(() => verifyCookieValue('sid', forged, SECRET, { now: 1000 }), CODE.SIGNATURE);
});

test('truncated signed value is rejected', () => {
  const signed = signCookieValue('sid', 'abc', SECRET, { now: 1000 });
  throwsCode(() => verifyCookieValue('sid', signed.slice(0, -1), SECRET, { now: 1000 }), CODE.SIGNATURE);
});

test('wrong-length HMAC tag is rejected without a type error', () => {
  const signed = signCookieValue('sid', 'abc', SECRET, { now: 1000 });
  const parts = signed.split('.');
  parts[4] = parts[4].slice(0, -1);
  const error = throwsCode(() => verifyCookieValue('sid', parts.join('.'), SECRET, { now: 1000 }), CODE.SIGNATURE);
  assert.match(error.reason, /wrong-length|malformed/);
});

test('wrong version is rejected', () => {
  const signed = signCookieValue('sid', 'abc', SECRET, { now: 1000 }).replace(/^v1\./, 'v2.');
  throwsCode(() => verifyCookieValue('sid', signed, SECRET, { now: 1000 }), CODE.SIGNATURE);
});

test('too few signed value parts are rejected', () => {
  throwsCode(() => verifyCookieValue('sid', 'v1.k1.0.YWJj', SECRET), CODE.SIGNATURE);
});

test('too many signed value parts are rejected', () => {
  const signed = signCookieValue('sid', 'abc', SECRET, { now: 1000 }) + '.extra';
  throwsCode(() => verifyCookieValue('sid', signed, SECRET), CODE.SIGNATURE);
});

test('invalid embedded key id is rejected', () => {
  const signed = signCookieValue('sid', 'abc', SECRET, { now: 1000 });
  const parts = signed.split('.');
  parts[1] = '_bad';
  throwsCode(() => verifyCookieValue('sid', parts.join('.'), SECRET), CODE.SIGNATURE);
});

for (const expiry of ['abc', '-1', '1x', '00', '061000', '12345678901234567', '9007199254740992']) {
  test('invalid embedded expiration rejected: ' + expiry, () => {
    const signed = signCookieValue('sid', 'abc', SECRET, { now: 1000 });
    const parts = signed.split('.');
    parts[2] = expiry;
    throwsCode(() => verifyCookieValue('sid', parts.join('.'), SECRET), CODE.SIGNATURE);
  });
}

test('base64url plus character in payload is rejected', () => {
  const signed = signCookieValue('sid', 'abc', SECRET, { now: 1000 });
  const parts = signed.split('.');
  parts[3] = '+' + parts[3].slice(1);
  throwsCode(() => verifyCookieValue('sid', parts.join('.'), SECRET), CODE.SIGNATURE);
});

test('base64 padding in MAC is rejected', () => {
  const signed = signCookieValue('sid', 'abc', SECRET, { now: 1000 }) + '=';
  throwsCode(() => verifyCookieValue('sid', signed, SECRET), CODE.SIGNATURE);
});

for (const input of [undefined, null, 1, {}, []]) {
  test('non-string signedValue rejected: ' + String(input), () => {
    throwsCode(() => verifyCookieValue('sid', input, SECRET), CODE.INVALID_INPUT);
  });
}

test('CRLF in signed value rejected', () => {
  throwsCode(() => verifyCookieValue('sid', 'v1.k1.0.\r\nabc', SECRET), CODE.CRLF);
});

test('non-ASCII signed value rejected', () => {
  throwsCode(() => verifyCookieValue('sid', 'v1.k1.0.caf\u00e9.x', SECRET), CODE.NON_ASCII);
});

test('oversized signed value rejected before parsing', () => {
  throwsCode(() => verifyCookieValue('sid', 'x'.repeat(5000), SECRET), CODE.LIMIT_EXCEEDED);
});

test('custom maxSignedBytes is enforced during verification', () => {
  const signed = signCookieValue('sid', 'abc', SECRET, { now: 1000 });
  throwsCode(() => verifyCookieValue('sid', signed, SECRET, { maxSignedBytes: signed.length - 1 }), CODE.LIMIT_EXCEEDED);
});

test('keyring rotation verifies a non-primary key and reports rotated true', () => {
  const primary = { id: 'key2026', secret: SECRET };
  const old = { id: 'key2025', secret: SECRET_ALT };
  const active = keyring([primary, old]);
  const oldSigned = signCookieValue('sid', 'abc', keyring([old]), { now: 1000 });
  const verified = verifyCookieValue('sid', oldSigned, active, { now: 1000 });
  assert.equal(verified.value, 'abc');
  assert.equal(verified.keyId, 'key2025');
  assert.equal(verified.rotated, true);
});

test('keyring primary verification reports rotated false', () => {
  const ring = keyring([
    { id: 'key2026', secret: SECRET },
    { id: 'key2025', secret: SECRET_ALT }
  ]);
  const signed = signCookieValue('sid', 'abc', ring, { now: 1000 });
  const verified = verifyCookieValue('sid', signed, ring, { now: 1000 });
  assert.equal(verified.keyId, 'key2026');
  assert.equal(verified.rotated, false);
});

test('signing always uses the primary keyring key', () => {
  const ring = keyring([
    { id: 'key2026', secret: SECRET },
    { id: 'key2025', secret: SECRET_ALT }
  ]);
  const signed = signCookieValue('sid', 'abc', ring, { now: 1000 });
  assert.equal(signed.split('.')[1], 'key2026');
});

test('removed rotation key can no longer verify', () => {
  const old = { id: 'key2025', secret: SECRET_ALT };
  const oldSigned = signCookieValue('sid', 'abc', keyring([old]), { now: 1000 });
  const active = keyring([{ id: 'key2026', secret: SECRET }]);
  throwsCode(() => verifyCookieValue('sid', oldSigned, active, { now: 1000 }), CODE.SIGNATURE);
});

test('binary Uint8Array secret signs and verifies', () => {
  const secret = new Uint8Array(Array.from({ length: 32 }, (_, index) => index + 1));
  const signed = signCookieValue('sid', 'abc', secret, { now: 1000 });
  assert.equal(verifyCookieValue('sid', signed, secret, { now: 1000 }).value, 'abc');
});

test('Buffer secret signs and verifies', () => {
  const secret = Buffer.from(Array.from({ length: 32 }, (_, index) => index + 101));
  const signed = signCookieValue('sid', 'abc', secret, { now: 1000 });
  assert.equal(verifyCookieValue('sid', signed, secret, { now: 1000 }).value, 'abc');
});

test('31 byte secret is rejected by default', () => {
  throwsCode(() => signCookieValue('sid', 'abc', SECRET.slice(0, 31)), CODE.WEAK_KEY);
});

test('32 byte high-diversity secret is accepted', () => {
  const secret = SECRET.slice(0, 32);
  const signed = signCookieValue('sid', 'abc', secret, { now: 1000 });
  assert.equal(verifyCookieValue('sid', signed, secret, { now: 1000 }).value, 'abc');
});

test('low-diversity 32 byte secret is rejected', () => {
  throwsCode(() => signCookieValue('sid', 'abc', 'A9x4'.repeat(8)), CODE.WEAK_KEY);
});

test('placeholder-looking long secret is rejected', () => {
  throwsCode(() => signCookieValue('sid', 'abc', 'secret-0123456789abcdef0123456789xyz'), CODE.WEAK_KEY);
});

test('whitespace-padded secret is rejected', () => {
  throwsCode(() => signCookieValue('sid', 'abc', ' ' + SECRET), CODE.WEAK_KEY);
});

test('weak-key rejection does not leak the secret in serialized error output', () => {
  const weak = 'secret-0123456789abcdef0123456789xyz';
  const error = throwsCode(() => signCookieValue('sid', 'abc', weak), CODE.WEAK_KEY);
  assert.equal(JSON.stringify(error).includes(weak), false);
});

test('allowWeakKeysForTests explicitly accepts a short test key', () => {
  const signed = signCookieValue('sid', 'abc', 'x', { now: 1000, allowWeakKeysForTests: true });
  assert.equal(verifyCookieValue('sid', signed, 'x', { now: 1000, allowWeakKeysForTests: true }).value, 'abc');
});

test('explicit minSecretBytes is still enforced with test opt-out', () => {
  throwsCode(() => signCookieValue('sid', 'abc', 'x', {
    allowWeakKeysForTests: true,
    minSecretBytes: 2
  }), CODE.WEAK_KEY);
});

test('custom minSecretBytes above 32 is enforced', () => {
  throwsCode(() => signCookieValue('sid', 'abc', SECRET, { minSecretBytes: 40 }), CODE.WEAK_KEY);
});

test('custom minSecretBytes above 32 accepts a qualifying secret', () => {
  const secret = (SECRET + SECRET_ALT).slice(0, 40);
  const signed = signCookieValue('sid', 'abc', secret, { now: 1000, minSecretBytes: 40 });
  assert.equal(verifyCookieValue('sid', signed, secret, { now: 1000, minSecretBytes: 40 }).value, 'abc');
});

const invalidKeyrings = [
  [undefined, 'undefined key input'],
  [null, 'null key input'],
  [{}, 'missing keys array'],
  [{ keys: [] }, 'empty keys array'],
  [{ keys: 'x' }, 'non-array keys'],
  [{ keys: [null] }, 'null key entry'],
  [{ keys: ['x'] }, 'string key entry'],
  [{ keys: [{ secret: SECRET }] }, 'missing key id'],
  [{ keys: [{ id: 'k1' }] }, 'missing secret'],
  [{ keys: [{ id: '', secret: SECRET }] }, 'empty key id'],
  [{ keys: [{ id: '_bad', secret: SECRET }] }, 'key id starts underscore'],
  [{ keys: [{ id: 'bad.id', secret: SECRET }] }, 'key id contains dot'],
  [{ keys: [{ id: 'a'.repeat(65), secret: SECRET }] }, 'key id too long'],
  [{ keys: [{ id: 'constructor', secret: SECRET }] }, 'reserved constructor id'],
  [{ keys: [{ id: 'k1', secret: '' }] }, 'empty string secret', CODE.WEAK_KEY],
  [{ keys: [{ id: 'k1', secret: new Uint8Array(0) }] }, 'empty binary secret', CODE.WEAK_KEY],
  [{ keys: [{ id: 'k1', secret: 1 }] }, 'numeric secret'],
  [{ keys: [{ id: 'k1', secret: SECRET, extra: true }] }, 'extra key entry property'],
  [{ keys: [{ id: 'k1', secret: SECRET }], extra: true }, 'extra keyring property'],
  [keyring([{ id: 'dup', secret: SECRET }, { id: 'dup', secret: SECRET_ALT }]), 'duplicate key id'],
  [keyring(Array.from({ length: 33 }, (_, index) => ({ id: 'k' + index, secret: SECRET }))), 'too many active keys']
];
for (const row of invalidKeyrings) {
  const [input, label, code = CODE.KEYRING] = row;
  test('invalid keyring rejected: ' + label, () => {
    throwsCode(() => signCookieValue('sid', 'abc', input), code);
  });
}

test('prototype key in keyring rejected', () => {
  const input = keyring([{ id: 'k1', secret: SECRET }]);
  Object.defineProperty(input, '__proto__', { value: {}, enumerable: true });
  throwsCode(() => signCookieValue('sid', 'abc', input), CODE.PROTOTYPE_KEY);
});

test('prototype key in keyring entry rejected', () => {
  const entry = JSON.parse('{"id":"k1","secret":"' + SECRET + '","__proto__":{}}');
  throwsCode(() => signCookieValue('sid', 'abc', keyring([entry])), CODE.PROTOTYPE_KEY);
});

for (const value of [0, -1, 1.5, NaN, Infinity, -Infinity, true, '60', null, 34560001]) {
  test('invalid signing maxAge rejected: ' + String(value), () => {
    throwsCode(() => signCookieValue('sid', 'abc', SECRET, { maxAge: value }), CODE.MAX_AGE);
  });
}

for (const value of [1, 34560000]) {
  test('valid signing maxAge accepted: ' + String(value), () => {
    const signed = signCookieValue('sid', 'abc', SECRET, { now: 1000, maxAge: value });
    assert.equal(typeof signed, 'string');
  });
}

for (const value of [-1, 1.5, NaN, Infinity, -Infinity, true, '1000', null, new Date('invalid'), new Date(-1)]) {
  test('invalid signing now rejected: ' + String(value), () => {
    throwsCode(() => signCookieValue('sid', 'abc', SECRET, { now: value }), CODE.OPTIONS);
  });
}

for (const key of ['minSecretBytes', 'maxValueBytes', 'maxSignedBytes']) {
  for (const value of [0, -1, 1.5, NaN, Infinity, '32']) {
    test('signing numeric limit enforced for ' + key + ': ' + String(value), () => {
      throwsCode(() => signCookieValue('sid', 'abc', SECRET, { [key]: value }), CODE.OPTIONS);
    });
  }
}

test('allowWeakKeysForTests type enforced', () => {
  throwsCode(() => signCookieValue('sid', 'abc', SECRET, { allowWeakKeysForTests: 'true' }), CODE.OPTIONS);
});

test('unknown sign option rejected', () => {
  throwsCode(() => signCookieValue('sid', 'abc', SECRET, { algorithm: 'sha256' }), CODE.OPTIONS);
});

test('maxAge is not accepted as a verify option', () => {
  const signed = signCookieValue('sid', 'abc', SECRET, { now: 1000 });
  throwsCode(() => verifyCookieValue('sid', signed, SECRET, { maxAge: 60 }), CODE.OPTIONS);
});

test('unknown verify option rejected', () => {
  const signed = signCookieValue('sid', 'abc', SECRET, { now: 1000 });
  throwsCode(() => verifyCookieValue('sid', signed, SECRET, { clockSkew: 1 }), CODE.OPTIONS);
});

test('prototype key in sign options rejected', () => {
  throwsCode(() => signCookieValue('sid', 'abc', SECRET, withProtoKey()), CODE.PROTOTYPE_KEY);
});

test('prototype key in verify options rejected', () => {
  const signed = signCookieValue('sid', 'abc', SECRET, { now: 1000 });
  throwsCode(() => verifyCookieValue('sid', signed, SECRET, withProtoKey()), CODE.PROTOTYPE_KEY);
});

test('signing value byte limit counts UTF-8 bytes rather than string length', () => {
  throwsCode(() => signCookieValue('sid', '\ud83d\ude00'.repeat(1025), SECRET, { maxSignedBytes: 6000 }), CODE.LIMIT_EXCEEDED);
});

test('custom maxValueBytes enforced during signing', () => {
  throwsCode(() => signCookieValue('sid', 'abcde', SECRET, { maxValueBytes: 4 }), CODE.LIMIT_EXCEEDED);
});

test('signed output byte limit is enforced during signing', () => {
  throwsCode(() => signCookieValue('sid', 'x'.repeat(3050), SECRET), CODE.LIMIT_EXCEEDED);
});

test('signed output byte limit can be raised explicitly', () => {
  const signed = signCookieValue('sid', 'x'.repeat(3050), SECRET, { maxSignedBytes: 5000 });
  assert.equal(typeof signed, 'string');
});

test('verification maxValueBytes is enforced after payload decoding', () => {
  const value = 'x'.repeat(4097);
  const signed = signCookieValue('sid', value, SECRET, {
    maxValueBytes: 5000,
    maxSignedBytes: 6000
  });
  throwsCode(() => verifyCookieValue('sid', signed, SECRET, { maxSignedBytes: 6000 }), CODE.LIMIT_EXCEEDED);
});

test('non-string signing value rejected', () => {
  throwsCode(() => signCookieValue('sid', 1, SECRET), CODE.INVALID_INPUT);
});

test('invalid cookie name rejected before signing', () => {
  throwsCode(() => signCookieValue('bad name', 'abc', SECRET), CODE.NAME);
});

test('prototype cookie name rejected before signing', () => {
  throwsCode(() => signCookieValue('__proto__', 'abc', SECRET), CODE.PROTOTYPE_KEY);
});

test('invalid cookie name rejected before verification', () => {
  const signed = signCookieValue('sid', 'abc', SECRET, { now: 1000 });
  throwsCode(() => verifyCookieValue('bad name', signed, SECRET), CODE.NAME);
});

test('key ids may contain hyphen and underscore after the first character', () => {
  const ring = keyring([{ id: 'k-1_2', secret: SECRET }]);
  const signed = signCookieValue('sid', 'abc', ring, { now: 1000 });
  assert.equal(signed.split('.')[1], 'k-1_2');
  assert.equal(verifyCookieValue('sid', signed, ring, { now: 1000 }).value, 'abc');
});

test('unknown key id cannot verify even when keyring has other active keys', () => {
  const signed = signCookieValue('sid', 'abc', keyring([{ id: 'unknown', secret: SECRET_ALT }]), { now: 1000 });
  const ring = keyring([{ id: 'current', secret: SECRET }]);
  throwsCode(() => verifyCookieValue('sid', signed, ring, { now: 1000 }), CODE.SIGNATURE);
});

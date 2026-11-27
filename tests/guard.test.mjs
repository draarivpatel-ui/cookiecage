import test from 'node:test';
import assert from 'node:assert/strict';
import { esm as api, throwsCode, withProtoKey, SECRET, SECRET_ALT } from './helpers.mjs';

const {
  CODE,
  createCookieJarGuard
} = api;

test('guard exposes the five required methods and is frozen', () => {
  const guard = createCookieJarGuard({ keyOrKeyring: SECRET });
  for (const name of ['serialize', 'delete', 'parse', 'sign', 'verify']) {
    assert.equal(typeof guard[name], 'function', name);
  }
  assert.equal(Object.isFrozen(guard), true);
});

test('guard serialize applies configured defaults', () => {
  const guard = createCookieJarGuard({
    serialize: { sameSite: 'Strict', path: '/app', httpOnly: true }
  });
  assert.equal(
    guard.serialize('sid', 'abc'),
    'sid=abc; Path=/app; HttpOnly; Secure; SameSite=Strict'
  );
});

test('guard serialize per-call options override defaults', () => {
  const guard = createCookieJarGuard({ serialize: { sameSite: 'Strict', path: '/app' } });
  assert.match(guard.serialize('sid', 'abc', { sameSite: 'Lax', path: '/' }), /Path=\/; HttpOnly; Secure; SameSite=Lax$/);
});

test('guard serialize rejects unknown call options', () => {
  const guard = createCookieJarGuard();
  throwsCode(() => guard.serialize('sid', 'abc', { unknown: true }), CODE.OPTIONS);
});

test('guard delete applies configured deletion defaults', () => {
  const guard = createCookieJarGuard({
    delete: { path: '/app', sameSite: 'Strict' }
  });
  assert.equal(
    guard.delete('sid'),
    'sid=; Path=/app; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; Secure; SameSite=Strict'
  );
});

test('guard delete preserves per-call prefix enforcement', () => {
  const guard = createCookieJarGuard();
  throwsCode(() => guard.delete('__Host-sid', { path: '/app' }), CODE.PREFIX);
});

test('guard parse applies configured duplicate policy', () => {
  const guard = createCookieJarGuard({ parse: { duplicatePolicy: 'first' } });
  assert.equal(guard.parse('sid=one; sid=two').sid, 'one');
});

test('guard parse per-call options override defaults', () => {
  const guard = createCookieJarGuard({ parse: { duplicatePolicy: 'first' } });
  assert.equal(guard.parse('sid=one; sid=two', { duplicatePolicy: 'last' }).sid, 'two');
});

test('guard parse default remains reject without configuration', () => {
  const guard = createCookieJarGuard();
  throwsCode(() => guard.parse('sid=one; sid=two'), CODE.DUPLICATE);
});

test('guard sign and verify use the configured top-level key', () => {
  const guard = createCookieJarGuard({ keyOrKeyring: SECRET });
  const signed = guard.sign('sid', 'abc', { now: 1000, maxAge: 30 });
  const verified = guard.verify('sid', signed, { now: 1001 });
  assert.equal(verified.value, 'abc');
  assert.equal(verified.keyId, 'k1');
});

test('guard sign uses keyring primary key', () => {
  const guard = createCookieJarGuard({
    keyOrKeyring: { keys: [{ id: 'primary', secret: SECRET }, { id: 'old', secret: SECRET_ALT }] }
  });
  const signed = guard.sign('sid', 'abc', { now: 1000 });
  assert.equal(signed.split('.')[1], 'primary');
});

test('guard verify reports rotation from configured keyring', () => {
  const old = { id: 'old', secret: SECRET_ALT };
  const oldSigned = createCookieJarGuard({ keyOrKeyring: { keys: [old] } }).sign('sid', 'abc', { now: 1000 });
  const guard = createCookieJarGuard({
    keyOrKeyring: { keys: [{ id: 'primary', secret: SECRET }, old] }
  });
  const verified = guard.verify('sid', oldSigned, { now: 1000 });
  assert.equal(verified.rotated, true);
});

test('guard sign accepts per-call key override', () => {
  const guard = createCookieJarGuard({ keyOrKeyring: SECRET });
  const signed = guard.sign('sid', 'abc', { now: 1000, keyOrKeyring: SECRET_ALT });
  throwsCode(() => guard.verify('sid', signed, { now: 1000 }), CODE.SIGNATURE);
  assert.equal(
    guard.verify('sid', signed, { now: 1000, keyOrKeyring: SECRET_ALT }).value,
    'abc'
  );
});

test('guard sign accepts a key configured in sign defaults', () => {
  const guard = createCookieJarGuard({ sign: { keyOrKeyring: SECRET, now: 1000 } });
  const signed = guard.sign('sid', 'abc');
  assert.equal(guard.verify('sid', signed, { keyOrKeyring: SECRET, now: 1000 }).value, 'abc');
});

test('guard verify accepts a key configured in verify defaults', () => {
  const signer = createCookieJarGuard({ keyOrKeyring: SECRET });
  const signed = signer.sign('sid', 'abc', { now: 1000 });
  const guard = createCookieJarGuard({ verify: { keyOrKeyring: SECRET, now: 1000 } });
  assert.equal(guard.verify('sid', signed).value, 'abc');
});

test('guard without a key rejects signing fail-closed', () => {
  const guard = createCookieJarGuard();
  throwsCode(() => guard.sign('sid', 'abc'), CODE.KEYRING);
});

test('guard without a key rejects verification fail-closed', () => {
  const guard = createCookieJarGuard();
  throwsCode(() => guard.verify('sid', 'v1.k1.0.YWJj.QygAEVqmekwbtiN6WicgqBx9-Fx8wteKEH-3zdyIp8k'), CODE.KEYRING);
});

test('guard applies sign maxAge defaults', () => {
  const guard = createCookieJarGuard({
    keyOrKeyring: SECRET,
    sign: { now: 1000, maxAge: 10 },
    verify: { now: 11000 }
  });
  const signed = guard.sign('sid', 'abc');
  assert.equal(verifyExpires(signed), 11000);
  throwsCode(() => guard.verify('sid', signed), CODE.EXPIRED);

  function verifyExpires(value) {
    return Number(value.split('.')[2]);
  }
});

test('guard per-call sign now overrides configured now', () => {
  const guard = createCookieJarGuard({ keyOrKeyring: SECRET, sign: { now: 1000 } });
  const signed = guard.sign('sid', 'abc', { now: 2000, maxAge: 1 });
  assert.equal(Number(signed.split('.')[2]), 3000);
});

test('guard construction validates the configured key', () => {
  throwsCode(() => createCookieJarGuard({ keyOrKeyring: 'x' }), CODE.WEAK_KEY);
});

test('guard construction accepts test opt-out for a weak configured key', () => {
  const guard = createCookieJarGuard({
    keyOrKeyring: 'x',
    sign: { allowWeakKeysForTests: true }
  });
  assert.equal(typeof guard.sign, 'function');
});

test('guard verification does not inherit a sign-only weak key opt-out', () => {
  const guard = createCookieJarGuard({
    keyOrKeyring: 'x',
    sign: { allowWeakKeysForTests: true, now: 1000 }
  });
  const signed = guard.sign('sid', 'abc');
  throwsCode(() => guard.verify('sid', signed, { now: 1000 }), CODE.WEAK_KEY);
  assert.equal(guard.verify('sid', signed, { now: 1000, allowWeakKeysForTests: true }).value, 'abc');
});

test('guard per-call strict sign options revalidate the configured key', () => {
  const guard = createCookieJarGuard({
    keyOrKeyring: 'x',
    sign: { allowWeakKeysForTests: true, now: 1000 }
  });
  assert.equal(typeof guard.sign('sid', 'abc'), 'string');
  throwsCode(() => guard.sign('sid', 'abc', { allowWeakKeysForTests: false }), CODE.WEAK_KEY);
});

test('guard rejects unknown top-level option', () => {
  throwsCode(() => createCookieJarGuard({ cookies: {} }), CODE.OPTIONS);
});

test('guard rejects prototype key in top-level options', () => {
  throwsCode(() => createCookieJarGuard(withProtoKey()), CODE.PROTOTYPE_KEY);
});

test('guard rejects unknown nested serialize option', () => {
  throwsCode(() => createCookieJarGuard({ serialize: { unknown: true } }), CODE.OPTIONS);
});

test('guard rejects unknown nested parse option', () => {
  throwsCode(() => createCookieJarGuard({ parse: { unknown: true } }), CODE.OPTIONS);
});

test('guard rejects unknown nested sign option', () => {
  throwsCode(() => createCookieJarGuard({ sign: { unknown: true } }), CODE.OPTIONS);
});

test('guard rejects non-object nested serialize defaults', () => {
  throwsCode(() => createCookieJarGuard({ serialize: [] }), CODE.OPTIONS);
});

test('guard methods cannot be mutated because the guard is frozen', () => {
  const guard = createCookieJarGuard({ keyOrKeyring: SECRET });
  assert.throws(() => {
    'use strict';
    guard.serialize = function replacement() {};
  }, TypeError);
});

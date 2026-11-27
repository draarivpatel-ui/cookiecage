import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { esm, cjs, SECRET, SECRET_ALT } from './helpers.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const exportNames = [
  'CODE', 'CookieCageError', 'serializeCookie', 'deleteCookie',
  'parseCookieHeader', 'signCookieValue', 'verifyCookieValue', 'createCookieJarGuard'
];

test('ESM and CJS expose the same top-level API names', () => {
  for (const name of exportNames) {
    assert.ok(esm[name], 'missing ESM export ' + name);
    assert.ok(cjs[name], 'missing CJS export ' + name);
    assert.equal(typeof esm[name], typeof cjs[name], name);
  }
});

test('ESM default export matches named exports', () => {
  for (const name of exportNames) assert.equal(esm.default[name], esm[name], name);
});

test('CJS default export is the module object', () => {
  assert.equal(cjs.default, cjs);
  for (const name of exportNames) assert.equal(cjs.default[name], cjs[name], name);
});

test('ESM and CJS error codes are identical', () => {
  assert.deepEqual({ ...cjs.CODE }, { ...esm.CODE });
});

test('ESM and CJS serialize complex cookies identically', () => {
  const options = {
    domain: 'Example.COM',
    path: '/app',
    maxAge: 60,
    expires: new Date(Date.UTC(2030, 0, 1)),
    sameSite: 'None',
    partitioned: true
  };
  assert.equal(esm.serializeCookie('sid', 'abc', options), cjs.serializeCookie('sid', 'abc', options));
});

test('ESM and CJS deletion cookies are identical', () => {
  assert.equal(esm.deleteCookie('__Host-sid'), cjs.deleteCookie('__Host-sid'));
});

test('ESM and CJS reject invalid input with the same error shape', () => {
  const errors = [];
  for (const module of [esm, cjs]) {
    try {
      module.serializeCookie('sid', 'a;b');
    } catch (error) {
      errors.push(error);
    }
  }
  assert.equal(errors.length, 2);
  assert.equal(errors[0].name, errors[1].name);
  assert.equal(errors[0].code, errors[1].code);
  assert.equal(errors[0].reason, errors[1].reason);
  assert.deepEqual(errors[0].toJSON(), errors[1].toJSON());
});

test('ESM and CJS parse hostile duplicate input identically', () => {
  for (const module of [esm, cjs]) {
    assert.throws(() => module.parseCookieHeader('sid=one; sid=two'), { code: module.CODE.DUPLICATE });
  }
});

test('ESM and CJS parse valid headers identically', () => {
  const left = esm.parseCookieHeader('a=1; b="two"; c=a%20b');
  const right = cjs.parseCookieHeader('a=1; b="two"; c=a%20b');
  assert.deepEqual({ ...left }, { ...right });
  assert.equal(Object.getPrototypeOf(left), null);
  assert.equal(Object.getPrototypeOf(right), null);
});

test('ESM and CJS produce byte-identical deterministic signatures', () => {
  const left = esm.signCookieValue('sid', 'abc', SECRET, { now: 1000, maxAge: 30 });
  const right = cjs.signCookieValue('sid', 'abc', SECRET, { now: 1000, maxAge: 30 });
  assert.equal(left, right);
});

test('ESM signature verifies through CJS', () => {
  const signed = esm.signCookieValue('sid', 'abc', SECRET, { now: 1000 });
  assert.equal(cjs.verifyCookieValue('sid', signed, SECRET, { now: 1000 }).value, 'abc');
});

test('CJS signature verifies through ESM', () => {
  const signed = cjs.signCookieValue('sid', 'abc', SECRET, { now: 1000 });
  assert.equal(esm.verifyCookieValue('sid', signed, SECRET, { now: 1000 }).value, 'abc');
});

test('ESM and CJS keyring rotation metadata are identical', () => {
  const old = { id: 'old', secret: SECRET_ALT };
  const ring = { keys: [{ id: 'primary', secret: SECRET }, old] };
  const oldSigned = esm.signCookieValue('sid', 'abc', { keys: [old] }, { now: 1000 });
  const left = esm.verifyCookieValue('sid', oldSigned, ring, { now: 1000 });
  const right = cjs.verifyCookieValue('sid', oldSigned, ring, { now: 1000 });
  assert.deepEqual({ ...left }, { ...right });
});

test('ESM guard output matches CJS guard output', () => {
  const options = {
    keyOrKeyring: SECRET,
    serialize: { sameSite: 'Strict' },
    parse: { duplicatePolicy: 'first' },
    sign: { now: 1000 },
    verify: { now: 1000 }
  };
  const left = esm.createCookieJarGuard(options);
  const right = cjs.createCookieJarGuard(options);
  assert.equal(left.serialize('sid', 'abc'), right.serialize('sid', 'abc'));
  assert.equal(left.delete('sid'), right.delete('sid'));
  assert.deepEqual({ ...left.parse('a=1; a=2') }, { ...right.parse('a=1; a=2') });
  assert.equal(left.sign('sid', 'abc'), right.sign('sid', 'abc'));
});

test('package self-reference resolves through ESM exports', async () => {
  const module = await import('cookiecage');
  assert.equal(typeof module.serializeCookie, 'function');
  assert.equal(module.serializeCookie('sid', 'abc'), esm.serializeCookie('sid', 'abc'));
});

test('package self-reference resolves through CJS exports', () => {
  const module = cjs;
  assert.equal(typeof module.serializeCookie, 'function');
  assert.equal(module.serializeCookie('sid', 'abc'), esm.serializeCookie('sid', 'abc'));
});

test('generated CJS file has the deterministic build header', () => {
  const output = fs.readFileSync(path.join(root, 'cjs', 'index.cjs'), 'utf8');
  assert.match(output, /Generated by scripts\/build-cjs\.mjs/);
  assert.match(output, /module\.exports\.default = module\.exports/);
});

test('source of truth does not contain CommonJS require for node:crypto', () => {
  const source = fs.readFileSync(path.join(root, 'src', 'index.mjs'), 'utf8');
  assert.match(source, /import \{ createHmac, timingSafeEqual \} from 'node:crypto';/);
  assert.equal(source.includes("require('node:crypto')"), false);
});

test('generated CJS does not contain ESM export declarations', () => {
  const output = fs.readFileSync(path.join(root, 'cjs', 'index.cjs'), 'utf8');
  assert.equal(/^export\s/m.test(output), false);
  assert.match(output, /const \{ createHmac, timingSafeEqual \} = require\('node:crypto'\);/);
});

test('TypeScript declarations expose every public function', () => {
  const types = fs.readFileSync(path.join(root, 'types', 'index.d.ts'), 'utf8');
  for (const name of exportNames.filter((name) => name !== 'CODE')) {
    assert.ok(types.includes(name), name);
  }
});

test('TypeScript declarations expose strict option surfaces', () => {
  const types = fs.readFileSync(path.join(root, 'types', 'index.d.ts'), 'utf8');
  for (const name of [
    'SerializeCookieOptions', 'DeleteCookieOptions', 'ParseCookieHeaderOptions',
    'CookieSigningKey', 'CookieKeyring', 'SignCookieValueOptions',
    'VerifyCookieValueOptions', 'VerifiedCookieValue', 'GuardSignOptions',
    'GuardVerifyOptions', 'CookieJarGuardOptions', 'CookieJarGuard'
  ]) {
    assert.ok(types.includes(name), name);
  }
});

test('TypeScript declarations include security-critical option documentation', () => {
  const types = fs.readFileSync(path.join(root, 'types', 'index.d.ts'), 'utf8');
  for (const text of [
    'duplicatePolicy', 'allowWeakKeysForTests', 'keyOrKeyring', 'maxSignedBytes',
    'additionalPublicSuffixes', 'strictPercentEncoding'
  ]) {
    assert.ok(types.includes(text), text);
  }
});

test('package manifest is zero dependency and points at the public repository', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  assert.equal(pkg.name, 'cookiecage');
  assert.equal(pkg.version, '1.0.0');
  assert.deepEqual(pkg.dependencies, {});
  assert.deepEqual(pkg.devDependencies, {});
  assert.equal(pkg.repository.url, 'git+https://github.com/draarivpatel-ui/cookiecage.git');
  assert.equal(pkg.homepage, 'https://github.com/draarivpatel-ui/cookiecage#readme');
  assert.equal(pkg.bugs.url, 'https://github.com/draarivpatel-ui/cookiecage/issues');
});

test('package manifest module entry points are exact', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  assert.equal(pkg.type, 'module');
  assert.equal(pkg.main, './cjs/index.cjs');
  assert.equal(pkg.module, './src/index.mjs');
  assert.equal(pkg.types, './types/index.d.ts');
  assert.deepEqual(pkg.exports['.'], {
    types: './types/index.d.ts',
    import: './src/index.mjs',
    require: './cjs/index.cjs'
  });
});

test('package test script uses the explicit cross-platform glob', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  assert.equal(pkg.scripts.test, 'node --test tests/*.test.mjs');
});

test('package files list contains the runtime and contributor surface', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  for (const entry of ['src', 'cjs', 'types', 'README.md', 'SECURITY.md', 'CONTRIBUTING.md', 'GOOD_FIRST_ISSUES.md', 'LICENSE']) {
    assert.ok(pkg.files.includes(entry), entry);
  }
});

test('gitattributes enforces LF for generated CommonJS files', () => {
  const attributes = fs.readFileSync(path.join(root, '.gitattributes'), 'utf8');
  assert.match(attributes, /\*\.cjs text eol=lf/);
});

test('CI covers Node 18 20 22 and 24 on Linux and Windows', () => {
  const ci = fs.readFileSync(path.join(root, '.github', 'workflows', 'ci.yml'), 'utf8');
  assert.match(ci, /os: \[ubuntu-latest, windows-latest\]/);
  assert.match(ci, /node: \[18, 20, 22, 24\]/);
  assert.match(ci, /node --test tests\/\*\.test\.mjs/);
});

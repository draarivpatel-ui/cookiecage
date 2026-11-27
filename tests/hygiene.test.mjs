import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function walk(directory, output = []) {
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    if (entry.name === '.git' || entry.name === 'node_modules' || entry.name === 'coverage') continue;
    const full = path.join(directory, entry.name);
    if (entry.isDirectory()) walk(full, output);
    else if (entry.isFile()) output.push(full);
  }
  return output;
}

function trackedTextFiles() {
  return walk(root).filter((file) => {
    const base = path.basename(file);
    if (base.endsWith('.tgz') || base.endsWith('.log')) return false;
    return true;
  });
}

function readFile(file) {
  return fs.readFileSync(file, 'utf8');
}

test('repository has the required contributor surface files', () => {
  for (const file of [
    'README.md', 'SECURITY.md', 'CONTRIBUTING.md', 'GOOD_FIRST_ISSUES.md',
    'LICENSE', '.gitattributes', '.github/workflows/ci.yml',
    '.github/ISSUE_TEMPLATE/bug_report.md',
    '.github/ISSUE_TEMPLATE/feature_request.md',
    '.github/PULL_REQUEST_TEMPLATE.md'
  ]) {
    assert.equal(fs.existsSync(path.join(root, file)), true, file);
  }
});

test('license is the MIT license text', () => {
  const license = readFile(path.join(root, 'LICENSE'));
  assert.match(license, /MIT License/);
  assert.match(license, /Permission is hereby granted/);
  assert.match(license, /cookiecage contributors/);
});

test('good first issues file contains exactly 10 scoped ideas', () => {
  const text = readFile(path.join(root, 'GOOD_FIRST_ISSUES.md'));
  const count = (text.match(/^## \d+\./gm) || []).length;
  assert.equal(count, 10);
});

test('README reports a numeric verified test count', () => {
  const readme = readFile(path.join(root, 'README.md'));
  assert.match(readme, /\*\*Tests:\*\* [1-9][0-9]+ passing with `npm test`/);
});

test('README test count is at least the required red-team floor', () => {
  const readme = readFile(path.join(root, 'README.md'));
  const match = /\*\*Tests:\*\* ([0-9]+) passing/.exec(readme);
  assert.ok(match, 'missing test count');
  assert.ok(Number(match[1]) >= 240, 'test count below floor');
});

test('README documents honest scope and limitations', () => {
  const readme = readFile(path.join(root, 'README.md'));
  assert.match(readme, /## Scope and limitations/);
  assert.match(readme, /not a browser cookie jar/);
  assert.match(readme, /Signing is authentication, not encryption/);
  assert.match(readme, /not a complete Public Suffix List/);
});

test('README documents cookie-tossing duplicate defense', () => {
  const readme = readFile(path.join(root, 'README.md'));
  assert.match(readme, /Cookie-tossing duplicate policy/);
  assert.match(readme, /duplicatePolicy: 'first'/);
  assert.match(readme, /duplicatePolicy: 'last'/);
});

test('README documents that signed payloads are not encrypted', () => {
  const readme = readFile(path.join(root, 'README.md'));
  assert.match(readme, /base64url encoded, not encrypted/);
});

test('SECURITY documents private reporting and scope', () => {
  const security = readFile(path.join(root, 'SECURITY.md'));
  assert.match(security, /Report a vulnerability/i);
  assert.match(security, /## Scope/);
  assert.match(security, /out of scope/);
  assert.match(security, /Never include a real session cookie/);
});

test('no tracked file contains em dash or en dash characters', () => {
  const emDash = String.fromCharCode(8212);
  const enDash = String.fromCharCode(8211);
  const offenders = [];
  for (const file of trackedTextFiles()) {
    const text = readFile(file);
    if (text.includes(emDash) || text.includes(enDash)) offenders.push(path.relative(root, file));
  }
  assert.deepEqual(offenders, []);
});

test('no tracked file contains a local absolute user path', () => {
  const offenders = [];
  const unixHome = '/' + 'Users' + '/';
  const windowsHome = 'C:' + '\\' + 'Users' + '\\';
  for (const file of trackedTextFiles()) {
    const text = readFile(file);
    if (text.includes(unixHome) || text.includes(windowsHome)) offenders.push(path.relative(root, file));
  }
  assert.deepEqual(offenders, []);
});

test('no tracked file contains personal contact or address markers', () => {
  const offenders = [];
  const markers = [
    'someone@' + 'gmail.com',
    'handle-redacted' + '286',
    'Exampleton' + ' Manor'
  ];
  for (const file of trackedTextFiles()) {
    const text = readFile(file);
    if (markers.some((marker) => text.includes(marker))) offenders.push(path.relative(root, file));
  }
  assert.deepEqual(offenders, []);
});

test('no tracked file contains a co-author trailer', () => {
  const trailer = 'Co-' + 'Authored-' + 'By:';
  const offenders = [];
  for (const file of trackedTextFiles()) {
    if (readFile(file).includes(trailer)) offenders.push(path.relative(root, file));
  }
  assert.deepEqual(offenders, []);
});

test('tracked text files use LF line endings', () => {
  const offenders = [];
  for (const file of trackedTextFiles()) {
    if (readFile(file).includes('\r')) offenders.push(path.relative(root, file));
  }
  assert.deepEqual(offenders, []);
});

test('package manifest has no install lifecycle scripts', () => {
  const pkg = JSON.parse(readFile(path.join(root, 'package.json')));
  for (const script of ['preinstall', 'install', 'postinstall', 'prepublish', 'prepublishOnly']) {
    assert.equal(pkg.scripts[script], undefined, script);
  }
});

test('package manifest keeps runtime dependencies empty and fast-check development-only', () => {
  const pkg = JSON.parse(readFile(path.join(root, 'package.json')));
  assert.deepEqual(pkg.dependencies, {});
  assert.deepEqual(pkg.devDependencies, { 'fast-check': '4.10.3' });
  assert.equal(pkg.peerDependencies, undefined);
  assert.equal(pkg.optionalDependencies, undefined);
});

test('library source imports only node:crypto', () => {
  const source = readFile(path.join(root, 'src', 'index.mjs'));
  const imports = source.match(/^import .*$/gm) || [];
  assert.deepEqual(imports, ["import { createHmac, timingSafeEqual } from 'node:crypto';"]);
});

test('library source contains no eval Function constructor child process or network API', () => {
  const source = readFile(path.join(root, 'src', 'index.mjs'));
  for (const forbidden of ['eval(', 'new Function', 'child_process', 'fetch(', 'XMLHttpRequest', 'node:http', 'node:https', 'node:net']) {
    assert.equal(source.includes(forbidden), false, forbidden);
  }
});

test('README avoids unsupported marketing claims', () => {
  const readme = readFile(path.join(root, 'README.md')).toLowerCase();
  for (const word of ['blazing', 'revolutionary', 'world-class', 'unhackable', 'military grade']) {
    assert.equal(readme.includes(word), false, word);
  }
});

test('gitignore excludes dependency and archive artifacts', () => {
  const gitignore = readFile(path.join(root, '.gitignore'));
  assert.match(gitignore, /node_modules\//);
  assert.match(gitignore, /\*\.tgz/);
});

test('CI does not publish packages', () => {
  const ci = readFile(path.join(root, '.github', 'workflows', 'ci.yml'));
  const publishText = 'npm' + ' ' + 'publish';
  assert.equal(ci.includes(publishText), false);
});

test('CI verifies deterministic CJS and package tarball', () => {
  const ci = readFile(path.join(root, '.github', 'workflows', 'ci.yml'));
  assert.match(ci, /build-cjs\.mjs --check/);
  assert.match(ci, /npm pack --dry-run/);
});

test('tests do not contain real vendor key prefixes', () => {
  const offenders = [];
  const prefixes = [
    'tskey' + '-', 's' + 'k-', 'gh' + 'p_', 'github' + '_pat_', 'AK' + 'IA',
    'xo' + 'x', 'gs' + 'k_', 'nvapi' + '-', 'tvly' + '-', 'AI' + 'za'
  ];
  for (const file of trackedTextFiles()) {
    const relative = path.relative(root, file);
    if (!relative.startsWith('tests/')) continue;
    const text = readFile(file);
    if (prefixes.some((prefix) => text.includes(prefix))) offenders.push(relative);
  }
  assert.deepEqual(offenders, []);
});

test('package files list excludes tests and scripts from publication', () => {
  const pkg = JSON.parse(readFile(path.join(root, 'package.json')));
  assert.equal(pkg.files.includes('tests'), false);
  assert.equal(pkg.files.includes('scripts'), false);
});

test('gitattributes includes LF rules for text formats', () => {
  const attributes = readFile(path.join(root, '.gitattributes'));
  for (const extension of ['mjs', 'cjs', 'js', 'json', 'md', 'yml', 'yaml']) {
    assert.match(attributes, new RegExp('\\*\\.' + extension + ' text eol=lf'), extension);
  }
});

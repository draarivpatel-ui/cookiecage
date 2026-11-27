import test from 'node:test';
import assert from 'node:assert/strict';
import { performance } from 'node:perf_hooks';
import { esm as api, throwsCode, withProtoKey } from './helpers.mjs';

const {
  CODE,
  parseCookieHeader
} = api;

test('parses one cookie into a null-prototype object', () => {
  const parsed = parseCookieHeader('sid=abc');
  assert.equal(parsed.sid, 'abc');
  assert.equal(Object.getPrototypeOf(parsed), null);
});

test('parses multiple cookies separated by semicolon and one space', () => {
  const parsed = parseCookieHeader('a=1; b=2; c=3');
  assert.deepEqual({ ...parsed }, { a: '1', b: '2', c: '3' });
});

test('parses multiple spaces after semicolon as transport whitespace', () => {
  const parsed = parseCookieHeader('a=1;  b=2');
  assert.equal(parsed.b, '2');
});

test('parses empty values', () => {
  assert.equal(parseCookieHeader('sid=').sid, '');
});

test('preserves additional equals signs inside the value', () => {
  assert.equal(parseCookieHeader('token=a=b=c').token, 'a=b=c');
});

test('preserves percent-encoded data by default', () => {
  assert.equal(parseCookieHeader('q=a%20b%2Fc').q, 'a%20b%2Fc');
});

test('decodeValues decodes strict UTF-8 percent encoding', () => {
  assert.equal(parseCookieHeader('q=caf%C3%A9', { decodeValues: true }).q, 'café');
});

test('decodeValues decodes encoded spaces and semicolons as data', () => {
  assert.equal(parseCookieHeader('q=a%20b%3Bc', { decodeValues: true }).q, 'a b;c');
});

test('decodeValues decodes lowercase hex escapes', () => {
  assert.equal(parseCookieHeader('q=a%2fb', { decodeValues: true }).q, 'a/b');
});

test('quoted cookie values are preserved as part of the exact value', () => {
  assert.equal(parseCookieHeader('sid="abc123"').sid, '"abc123"');
});

test('empty quoted cookie values preserve both quote characters', () => {
  assert.equal(parseCookieHeader('sid=""').sid, '""');
});

test('quoted values may contain percent escapes inside the preserved quotes', () => {
  assert.equal(parseCookieHeader('sid="a%20b"', { decodeValues: true }).sid, '"a b"');
});

test('quoted and unquoted cookie values do not collide', () => {
  assert.notEqual(parseCookieHeader('sid="abc"').sid, parseCookieHeader('sid=abc').sid);
  assert.equal(parseCookieHeader('sid="abc"').sid, '"abc"');
  assert.equal(parseCookieHeader('sid=abc').sid, 'abc');
});

test('Object method names are isolated as own data in the null-prototype map', () => {
  const parsed = parseCookieHeader('toString=one; valueOf=two; hasOwnProperty=three');
  assert.equal(parsed.toString, 'one');
  assert.equal(parsed.valueOf, 'two');
  assert.equal(parsed.hasOwnProperty, 'three');
  assert.equal(Object.getPrototypeOf(parsed), null);
  assert.equal({}.polluted, undefined);
});

test('strictPercentEncoding false preserves a literal percent sign', () => {
  assert.equal(parseCookieHeader('q=100%', { strictPercentEncoding: false }).q, '100%');
});

test('cookie names are case sensitive', () => {
  const parsed = parseCookieHeader('Sid=1; sid=2');
  assert.equal(parsed.Sid, '1');
  assert.equal(parsed.sid, '2');
});

test('cookie-tossing duplicate names reject by default', () => {
  for (const header of ['sid=first; sid=second', 'sid=first;  sid=second']) {
    throwsCode(() => parseCookieHeader(header), CODE.DUPLICATE);
  }
});

test('duplicate error does not expose cookie values', () => {
  const error = throwsCode(() => parseCookieHeader('sid=first-secret; sid=second-secret'), CODE.DUPLICATE);
  assert.equal(JSON.stringify(error).includes('first-secret'), false);
  assert.equal(JSON.stringify(error).includes('second-secret'), false);
});

test('duplicatePolicy first keeps the first cookie explicitly', () => {
  assert.equal(parseCookieHeader('sid=first; sid=second', { duplicatePolicy: 'first' }).sid, 'first');
});

test('duplicatePolicy last keeps the last cookie explicitly', () => {
  assert.equal(parseCookieHeader('sid=first; sid=second', { duplicatePolicy: 'last' }).sid, 'second');
});

test('duplicatePolicy applies across three duplicates', () => {
  assert.equal(parseCookieHeader('a=1; a=2; a=3', { duplicatePolicy: 'first' }).a, '1');
  assert.equal(parseCookieHeader('a=1; a=2; a=3', { duplicatePolicy: 'last' }).a, '3');
});

test('result object safely accepts hasOwnProperty as a cookie name', () => {
  const parsed = parseCookieHeader('hasOwnProperty=x');
  assert.equal(parsed.hasOwnProperty, 'x');
  assert.equal(Object.getPrototypeOf(parsed), null);
});

test('prototype pollution names are rejected before object assignment', () => {
  assert.equal({}.polluted, undefined);
  for (const name of ['__proto__', 'constructor', 'prototype']) {
    throwsCode(() => parseCookieHeader(name + '=x'), CODE.PROTOTYPE_KEY);
  }
  assert.equal({}.polluted, undefined);
});

for (const input of [undefined, null, 1, {}, []]) {
  test('non-string header rejected: ' + String(input), () => {
    throwsCode(() => parseCookieHeader(input), CODE.INVALID_INPUT);
  });
}

const malformedHeaders = [
  ['', CODE.PARSE, 'empty'],
  ['sid', CODE.PARSE, 'missing equals'],
  ['=value', CODE.PARSE, 'empty name'],
  ['; sid=1', CODE.PARSE, 'leading semicolon'],
  ['sid=1;', CODE.PARSE, 'trailing semicolon'],
  ['sid=1;; theme=light', CODE.PARSE, 'empty middle segment'],
  ['sid=1;   ', CODE.PARSE, 'whitespace-only segment'],
  ['sid=1; =2', CODE.PARSE, 'empty later name'],
  ['sid=1; theme', CODE.PARSE, 'later missing equals']
];
for (const [header, code, label] of malformedHeaders) {
  test('malformed header rejected: ' + label, () => {
    throwsCode(() => parseCookieHeader(header), code);
  });
}

const hostileHeaders = [
  ['sid=abc\r\nX-Evil: 1', CODE.CRLF, 'CRLF header splitting'],
  ['sid=abc\nX-Evil: 1', CODE.CRLF, 'LF header splitting'],
  ['sid=abc\rX-Evil: 1', CODE.CRLF, 'CR header splitting'],
  ['sid=abc\x00def', CODE.CONTROL_CHARACTER, 'NUL'],
  ['sid=abc\x07def', CODE.CONTROL_CHARACTER, 'BEL'],
  ['sid=abc\x1fdef', CODE.CONTROL_CHARACTER, 'C0 control'],
  ['sid=abc\x7fdef', CODE.CONTROL_CHARACTER, 'DEL'],
  ['sid=abc\x85def', CODE.CONTROL_CHARACTER, 'C1 control'],
  ['sid=caf\u00e9', CODE.NON_ASCII, 'non-ASCII value'],
  ['s\u00eed=abc', CODE.NON_ASCII, 'non-ASCII name']
];
for (const [header, code, label] of hostileHeaders) {
  test('hostile header rejected: ' + label, () => {
    throwsCode(() => parseCookieHeader(header), code);
  });
}

for (const [name, label] of [
  ['a b', 'space'],
  ['a,b', 'comma'],
  ['a"b', 'quote'],
  ['a\\b', 'backslash'],
  ['a/b', 'slash'],
  ['a[b', 'open bracket'],
  ['a]b', 'close bracket'],
  ['a?b', 'question mark'],
  ['a{b', 'open brace'],
  ['a}b', 'close brace'],
  ['a:b', 'colon'],
  ['a@b', 'at sign'],
  ['a(b', 'open parenthesis'],
  ['a)b', 'close parenthesis'],
  ['a<b', 'less than'],
  ['a>b', 'greater than']
]) {
  test('invalid parsed cookie name rejected: ' + label, () => {
    throwsCode(() => parseCookieHeader(name + '=x'), CODE.NAME);
  });
}

const invalidParseValues = [
  ['a b', CODE.VALUE, 'raw space'],
  ['a;b', CODE.PARSE, 'raw semicolon splits the header'],
  ['a,b', CODE.VALUE, 'raw comma'],
  ['a"b', CODE.VALUE, 'raw quote'],
  ['a\\b', CODE.VALUE, 'raw backslash'],
  ['100%', CODE.ENCODING, 'bare percent'],
  ['a%2', CODE.ENCODING, 'truncated percent'],
  ['a%zz', CODE.ENCODING, 'bad percent hex'],
  ['a%0ab', CODE.CONTROL_CHARACTER, 'encoded LF'],
  ['a%0db', CODE.CONTROL_CHARACTER, 'encoded CR'],
  ['a%00b', CODE.CONTROL_CHARACTER, 'encoded NUL'],
  ['a%1fb', CODE.CONTROL_CHARACTER, 'encoded C0'],
  ['a%7fb', CODE.CONTROL_CHARACTER, 'encoded DEL']
];
for (const [value, code, label] of invalidParseValues) {
  test('invalid parsed value rejected: ' + label, () => {
    const header = value.includes(';') ? 'x=' + value : 'x=' + value;
    throwsCode(() => parseCookieHeader(header), code);
  });
}

test('mismatched opening quote rejected', () => {
  throwsCode(() => parseCookieHeader('x="abc'), CODE.VALUE);
});

test('mismatched closing quote rejected', () => {
  throwsCode(() => parseCookieHeader('x=abc"'), CODE.VALUE);
});

test('interior quote rejected even inside quoted value', () => {
  throwsCode(() => parseCookieHeader('x="a"b"'), CODE.VALUE);
});

test('decodeValues rejects percent bytes that are not valid UTF-8', () => {
  throwsCode(() => parseCookieHeader('x=%FF', { decodeValues: true }), CODE.ENCODING);
});

test('decodeValues rejects overlong UTF-8 sequences', () => {
  throwsCode(() => parseCookieHeader('x=%C0%AF', { decodeValues: true }), CODE.ENCODING);
});

test('decodeValues rejects UTF-8 decoded C1 controls', () => {
  throwsCode(() => parseCookieHeader('x=%C2%85', { decodeValues: true }), CODE.CONTROL_CHARACTER);
});

test('decodeValues rejects truncated multi-byte UTF-8', () => {
  throwsCode(() => parseCookieHeader('x=%E2%98', { decodeValues: true }), CODE.ENCODING);
});

test('decodeValues false does not reject valid syntax for non-UTF8 bytes', () => {
  assert.equal(parseCookieHeader('x=%FF').x, '%FF');
});

test('header byte limit rejects before scanning a large header', () => {
  const header = 'pad=' + 'x'.repeat(100 * 1024);
  parseCookieHeader('warmup=1');
  let best = Infinity;
  for (let iteration = 0; iteration < 8; iteration += 1) {
    const start = performance.now();
    throwsCode(() => parseCookieHeader(header), CODE.LIMIT_EXCEEDED);
    best = Math.min(best, performance.now() - start);
  }
  assert.ok(best < 5, '100KB over-limit header best-of-eight took ' + best.toFixed(3) + 'ms');
});

test('delimiter-heavy oversized input rejects within configured bounds', () => {
  throwsCode(() => parseCookieHeader(';'.repeat(100000), { maxHeaderBytes: 100001 }), CODE.LIMIT_EXCEEDED);
});

test('large but explicitly permitted header parses within five milliseconds', () => {
  const segments = [];
  for (let index = 0; index < 95; index += 1) {
    segments.push('c' + String(index).padStart(2, '0') + '=' + 'x'.repeat(1100));
  }
  const header = segments.join('; ');
  assert.ok(header.length > 100 * 1024, 'fixture must exceed 100KB');
  const options = { maxHeaderBytes: 200000, maxCookies: 100, maxCookieBytes: 1200 };
  parseCookieHeader(header, options);
  let best = Infinity;
  let parsed;
  for (let iteration = 0; iteration < 8; iteration += 1) {
    const start = performance.now();
    parsed = parseCookieHeader(header, options);
    best = Math.min(best, performance.now() - start);
  }
  assert.equal(Object.keys(parsed).length, 95);
  assert.ok(best < 5, '100KB permitted header best-of-eight took ' + best.toFixed(3) + 'ms');
});

test('default cookie count bound rejects 101 cookies', () => {
  const header = Array.from({ length: 101 }, (_, index) => 'c' + index + '=x').join(';');
  throwsCode(() => parseCookieHeader(header), CODE.LIMIT_EXCEEDED);
});

test('custom cookie count bound is enforced', () => {
  throwsCode(() => parseCookieHeader('a=1;b=2', { maxCookies: 1 }), CODE.LIMIT_EXCEEDED);
});

test('custom cookie byte bound is enforced per segment', () => {
  throwsCode(() => parseCookieHeader('a=12345', { maxCookieBytes: 6 }), CODE.LIMIT_EXCEEDED);
});

test('custom cookie byte bound permits a segment at the exact boundary', () => {
  assert.equal(parseCookieHeader('a=1234', { maxCookieBytes: 6 }).a, '1234');
});

test('custom header byte bound permits a header at the exact boundary', () => {
  assert.equal(parseCookieHeader('a=1', { maxHeaderBytes: 3 }).a, '1');
});

test('custom header byte bound rejects one byte over the boundary', () => {
  throwsCode(() => parseCookieHeader('a=1', { maxHeaderBytes: 2 }), CODE.LIMIT_EXCEEDED);
});

test('duplicatePolicy invalid value rejected', () => {
  throwsCode(() => parseCookieHeader('a=1', { duplicatePolicy: 'shadow' }), CODE.OPTIONS);
});

test('decodeValues type enforced', () => {
  throwsCode(() => parseCookieHeader('a=1', { decodeValues: 'true' }), CODE.OPTIONS);
});

test('strictPercentEncoding type enforced', () => {
  throwsCode(() => parseCookieHeader('a=1', { strictPercentEncoding: 1 }), CODE.OPTIONS);
});

for (const key of ['maxHeaderBytes', 'maxCookies', 'maxCookieBytes']) {
  for (const value of [0, -1, 1.5, NaN, Infinity, '10']) {
    test('parse numeric limit enforced for ' + key + ': ' + String(value), () => {
      throwsCode(() => parseCookieHeader('a=1', { [key]: value }), CODE.OPTIONS);
    });
  }
}

test('unknown parse option rejected', () => {
  throwsCode(() => parseCookieHeader('a=1', { strict: true }), CODE.OPTIONS);
});

test('null parse options rejected', () => {
  throwsCode(() => parseCookieHeader('a=1', null), CODE.OPTIONS);
});

test('array parse options rejected', () => {
  throwsCode(() => parseCookieHeader('a=1', []), CODE.OPTIONS);
});

test('prototype key in parse options rejected', () => {
  throwsCode(() => parseCookieHeader('a=1', withProtoKey()), CODE.PROTOTYPE_KEY);
});

test('parser output is independent for repeated calls', () => {
  const first = parseCookieHeader('a=1');
  const second = parseCookieHeader('a=1');
  first.a = 'changed';
  assert.equal(second.a, '1');
});

test('leading spaces before the first pair are tolerated as transport whitespace', () => {
  assert.equal(parseCookieHeader('  a=1').a, '1');
});

test('trailing spaces inside a value are rejected as invalid cookie octets', () => {
  throwsCode(() => parseCookieHeader('a=1 '), CODE.VALUE);
});

test('raw tab whitespace is rejected as a control character', () => {
  throwsCode(() => parseCookieHeader('a=1;\tb=2'), CODE.CONTROL_CHARACTER);
});

test('single cookie at default maximum segment size is accepted', () => {
  const value = 'x'.repeat(4094);
  assert.equal(parseCookieHeader('a=' + value).a.length, 4094);
});

test('single cookie over default maximum segment size is rejected', () => {
  const value = 'x'.repeat(4095);
  throwsCode(() => parseCookieHeader('a=' + value), CODE.LIMIT_EXCEEDED);
});

test('many distinct cookies parse within the default count bound', () => {
  const header = Array.from({ length: 100 }, (_, index) => 'c' + index + '=x').join(';');
  const parsed = parseCookieHeader(header);
  assert.equal(Object.keys(parsed).length, 100);
});

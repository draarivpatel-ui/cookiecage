import test from 'node:test';
import assert from 'node:assert/strict';
import { esm as api, throwsCode, withProtoKey } from './helpers.mjs';

const {
  CODE,
  serializeCookie,
  deleteCookie
} = api;

test('default serialization uses hardened RFC 6265bis attributes', () => {
  assert.equal(
    serializeCookie('sid', 'abc123'),
    'sid=abc123; Path=/; HttpOnly; Secure; SameSite=Lax'
  );
});

test('empty cookie values serialize as an empty pair value', () => {
  assert.equal(serializeCookie('sid', ''), 'sid=; Path=/; HttpOnly; Secure; SameSite=Lax');
});

test('all attributes serialize in a deterministic order', () => {
  assert.equal(
    serializeCookie('sid', 'abc', {
      domain: 'Example.COM',
      path: '/app',
      maxAge: 60,
      expires: new Date(Date.UTC(2030, 0, 1, 2, 3, 4)),
      httpOnly: true,
      secure: true,
      sameSite: 'Strict',
      partitioned: true
    }),
    'sid=abc; Domain=example.com; Path=/app; Max-Age=60; Expires=Tue, 01 Jan 2030 02:03:04 GMT; HttpOnly; Secure; SameSite=Strict; Partitioned'
  );
});

test('secure and HttpOnly can be explicitly disabled for unprefixed cookies', () => {
  assert.equal(
    serializeCookie('sid', 'abc', { secure: false, httpOnly: false }),
    'sid=abc; Path=/; SameSite=Lax'
  );
});

for (const [input, canonical] of [['lax', 'Lax'], ['strict', 'Strict'], ['none', 'None'], ['LAX', 'Lax'], ['STRICT', 'Strict'], ['NONE', 'None']]) {
  test('sameSite input case is canonicalized for ' + input, () => {
    assert.match(serializeCookie('sid', 'abc', { sameSite: input }), new RegExp('SameSite=' + canonical + '$'));
  });
}

for (const name of ['token', 'a', 'A-Z_a-z_0-9', '!#$%&\'*+-.^_`|~']) {
  test('valid RFC token cookie name accepted: ' + name, () => {
    assert.match(serializeCookie(name, 'x'), new RegExp('^' + name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '='));
  });
}

const invalidNames = [
  ['', CODE.NAME],
  ['a b', CODE.NAME],
  ['a;b', CODE.NAME],
  ['a,b', CODE.NAME],
  ['a=b', CODE.NAME],
  ['a"b', CODE.NAME],
  ['a\\b', CODE.NAME],
  ['a/b', CODE.NAME],
  ['a[b', CODE.NAME],
  ['a]b', CODE.NAME],
  ['a?b', CODE.NAME],
  ['a{b', CODE.NAME],
  ['a}b', CODE.NAME],
  ['a:b', CODE.NAME],
  ['a@b', CODE.NAME],
  ['a(b', CODE.NAME],
  ['a)b', CODE.NAME],
  ['a<b', CODE.NAME],
  ['a>b', CODE.NAME],
  ['a\rb', CODE.CRLF],
  ['a\nb', CODE.CRLF],
  ['a\r\nb', CODE.CRLF],
  ['a\x00b', CODE.CONTROL_CHARACTER],
  ['a\tb', CODE.CONTROL_CHARACTER],
  ['a\x7Fb', CODE.CONTROL_CHARACTER],
  ['a\x85b', CODE.CONTROL_CHARACTER],
  ['aéb', CODE.NON_ASCII],
  ['__proto__', CODE.PROTOTYPE_KEY],
  ['constructor', CODE.PROTOTYPE_KEY],
  ['prototype', CODE.PROTOTYPE_KEY]
];
for (const [name, code] of invalidNames) {
  test('invalid cookie name rejected ' + JSON.stringify(name), () => {
    throwsCode(() => serializeCookie(name, 'x'), code);
  });
}

test('non-string cookie name rejected', () => {
  throwsCode(() => serializeCookie(1, 'x'), CODE.INVALID_INPUT);
});

test('null cookie name rejected', () => {
  throwsCode(() => serializeCookie(null, 'x'), CODE.INVALID_INPUT);
});

for (const [input, encoded] of [
  ['a b', 'a%20b'],
  ['a;b', 'a%3Bb'],
  ['a,b', 'a%2Cb'],
  ['a"b', 'a%22b'],
  ['a\\b', 'a%5Cb'],
  ['a%b', 'a%25b'],
  ['caf\u00e9', 'caf%C3%A9'],
  ['snowman \u2603', 'snowman%20%E2%98%83']
]) {
  test('encodeValue percent-encodes ' + JSON.stringify(input), () => {
    assert.match(serializeCookie('sid', input, { encodeValue: true }), new RegExp('^sid=' + encoded.replace(/%/g, '%') + ';'));
  });
}

test('valid existing percent escapes are preserved without re-encoding', () => {
  assert.match(serializeCookie('sid', 'a%20b%2Fc'), /^sid=a%20b%2Fc;/);
});

test('lowercase valid percent escapes are preserved', () => {
  assert.match(serializeCookie('sid', 'a%2fb'), /^sid=a%2fb;/);
});

test('strictPercentEncoding false permits a literal percent sign', () => {
  assert.match(serializeCookie('sid', '100%', { strictPercentEncoding: false }), /^sid=100%;/);
});

const invalidValues = [
  ['a b', CODE.VALUE],
  ['a;b', CODE.VALUE],
  ['a,b', CODE.VALUE],
  ['a"b', CODE.VALUE],
  ['a\\b', CODE.VALUE],
  ['a\rb', CODE.CRLF],
  ['a\nb', CODE.CRLF],
  ['a\r\nb', CODE.CRLF],
  ['a\x00b', CODE.CONTROL_CHARACTER],
  ['a\tb', CODE.CONTROL_CHARACTER],
  ['a\x7Fb', CODE.CONTROL_CHARACTER],
  ['a\x85b', CODE.CONTROL_CHARACTER],
  ['caf\u00e9', CODE.NON_ASCII],
  ['100%', CODE.ENCODING],
  ['a%2', CODE.ENCODING],
  ['a%zz', CODE.ENCODING],
  ['a%0ab', CODE.CONTROL_CHARACTER],
  ['a%0Ab', CODE.CONTROL_CHARACTER],
  ['a%0db', CODE.CONTROL_CHARACTER],
  ['a%00b', CODE.CONTROL_CHARACTER],
  ['a%1fb', CODE.CONTROL_CHARACTER],
  ['a%7fb', CODE.CONTROL_CHARACTER]
];
for (const [value, code] of invalidValues) {
  test('invalid cookie value rejected ' + JSON.stringify(value), () => {
    throwsCode(() => serializeCookie('sid', value), code);
  });
}

test('non-string cookie value rejected', () => {
  throwsCode(() => serializeCookie('sid', 42), CODE.INVALID_INPUT);
});

test('null cookie value rejected', () => {
  throwsCode(() => serializeCookie('sid', null), CODE.INVALID_INPUT);
});

test('value byte limit rejects oversized raw values', () => {
  throwsCode(() => serializeCookie('sid', 'x'.repeat(4097), { maxSerializedBytes: 5000 }), CODE.LIMIT_EXCEEDED);
});

test('value byte limit counts encoded output bytes', () => {
  throwsCode(() => serializeCookie('sid', '\u2603'.repeat(500), { encodeValue: true, maxValueBytes: 4096 }), CODE.LIMIT_EXCEEDED);
});

test('custom maxValueBytes is enforced before serialization', () => {
  throwsCode(() => serializeCookie('sid', 'abcde', { maxValueBytes: 4, maxSerializedBytes: 5000 }), CODE.LIMIT_EXCEEDED);
  assert.match(serializeCookie('sid', 'abcd', { maxValueBytes: 4, maxSerializedBytes: 5000 }), /^sid=abcd;/);
});

test('complete serialized Set-Cookie header has a 4096 byte default limit', () => {
  throwsCode(() => serializeCookie('sid', 'x'.repeat(4096)), CODE.LIMIT_EXCEEDED);
});

test('maxSerializedBytes can be raised explicitly within the hard cap', () => {
  const output = serializeCookie('sid', 'x'.repeat(4000), { maxSerializedBytes: 4100 });
  assert.equal(output.length <= 4100, true);
});

for (const value of [-1, 1.5, NaN, Infinity, -Infinity, true, '10', null, 34560001]) {
  test('invalid maxAge rejected: ' + String(value), () => {
    throwsCode(() => serializeCookie('sid', 'x', { maxAge: value }), CODE.MAX_AGE);
  });
}

for (const value of [0, 1, 34560000]) {
  test('valid maxAge accepted: ' + String(value), () => {
    assert.match(serializeCookie('sid', 'x', { maxAge: value }), new RegExp('Max-Age=' + value));
  });
}

test('expires serializes as exact RFC 7231 IMF-fixdate', () => {
  assert.match(
    serializeCookie('sid', 'x', { expires: new Date(Date.UTC(2015, 9, 21, 7, 28, 0)) }),
    /Expires=Wed, 21 Oct 2015 07:28:00 GMT/
  );
});

test('expires year is padded to four digits', () => {
  const date = new Date(Date.UTC(120, 0, 1));
  assert.match(serializeCookie('sid', 'x', { expires: date }), /Expires=[A-Z][a-z]{2}, 01 Jan 0120 /);
});

for (const value of [new Date('invalid'), 'Wed, 21 Oct 2015 07:28:00 GMT', 0, null, true]) {
  test('invalid expires rejected: ' + String(value), () => {
    throwsCode(() => serializeCookie('sid', 'x', { expires: value }), CODE.EXPIRES);
  });
}

test('expires years above 9999 are rejected for IMF-fixdate output', () => {
  throwsCode(() => serializeCookie('sid', 'x', { expires: new Date(Date.UTC(10000, 0, 1)) }), CODE.EXPIRES);
});

test('deleteCookie emits exact epoch deletion attributes', () => {
  assert.equal(
    deleteCookie('sid'),
    'sid=; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; Secure; SameSite=Lax'
  );
});

test('deleteCookie preserves secure deletion for __Host- cookies', () => {
  assert.equal(
    deleteCookie('__Host-sid'),
    '__Host-sid=; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; Secure; SameSite=Lax'
  );
});

test('deleteCookie rejects an overriding Max-Age option', () => {
  throwsCode(() => deleteCookie('sid', { maxAge: 100 }), CODE.OPTIONS);
});

test('deleteCookie rejects an overriding Expires option', () => {
  throwsCode(() => deleteCookie('sid', { expires: new Date() }), CODE.OPTIONS);
});

test('deleteCookie preserves custom path for unprefixed cookies', () => {
  assert.match(deleteCookie('sid', { path: '/app' }), /Path=\/app/);
});

test('deleteCookie enforces __Host- root path invariant', () => {
  throwsCode(() => deleteCookie('__Host-sid', { path: '/app' }), CODE.PREFIX);
});

test('deleteCookie rejects domain for __Host- cookies', () => {
  throwsCode(() => deleteCookie('__Host-sid', { domain: 'example.com' }), CODE.PREFIX);
});

test('deleteCookie honors sameSite configuration', () => {
  assert.match(deleteCookie('sid', { sameSite: 'Strict' }), /SameSite=Strict$/);
});

test('__Host- cookie valid with required invariants', () => {
  assert.match(serializeCookie('__Host-sid', 'x'), /^__Host-sid=x; Path=\/; HttpOnly; Secure; SameSite=Lax$/);
});

for (const options of [
  [{ secure: false }, 'secure false'],
  [{ path: '/app' }, 'non-root path'],
  [{ path: '//' }, 'double slash path'],
  [{ domain: 'example.com' }, 'domain attribute']
]) {
  test('__Host- invariant rejected with ' + options[1], () => {
    throwsCode(() => serializeCookie('__Host-sid', 'x', options[0]), CODE.PREFIX);
  });
}

test('lowercase __host- is not treated as the exact RFC prefix', () => {
  assert.match(serializeCookie('__host-sid', 'x', { secure: false, path: '/app', domain: 'example.com' }), /^__host-sid=x;/);
});

test('__Secure- cookie valid with Secure', () => {
  assert.match(serializeCookie('__Secure-sid', 'x'), /^__Secure-sid=x; Path=\/; HttpOnly; Secure/);
});

test('__Secure- cookie rejects Secure false', () => {
  throwsCode(() => serializeCookie('__Secure-sid', 'x', { secure: false }), CODE.PREFIX);
});

test('lowercase __secure- is not treated as the exact RFC prefix', () => {
  assert.match(serializeCookie('__secure-sid', 'x', { secure: false }), /^__secure-sid=x;/);
});

test('SameSite=None requires Secure', () => {
  throwsCode(() => serializeCookie('sid', 'x', { sameSite: 'None', secure: false }), CODE.SAMESITE);
});

test('SameSite=None succeeds with Secure', () => {
  assert.match(serializeCookie('sid', 'x', { sameSite: 'None' }), /SameSite=None$/);
});

test('Partitioned requires Secure', () => {
  throwsCode(() => serializeCookie('sid', 'x', { partitioned: true, secure: false }), CODE.PARTITIONED);
});

test('Partitioned succeeds with Secure', () => {
  assert.match(serializeCookie('sid', 'x', { partitioned: true }), /Partitioned$/);
});

test('SameSite=None and Partitioned can serialize together with Secure', () => {
  assert.match(serializeCookie('sid', 'x', { sameSite: 'None', partitioned: true }), /SameSite=None; Partitioned$/);
});

for (const domain of ['example.com', 'sub.example.co.uk', 'xn--bcher-kva.example', 'a-b.example.com', '123.example.com']) {
  test('valid domain accepted: ' + domain, () => {
    assert.match(serializeCookie('sid', 'x', { domain }), new RegExp('Domain=' + domain.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  });
}

test('uppercase domain is canonicalized to lowercase', () => {
  assert.match(serializeCookie('sid', 'x', { domain: 'ExAmPle.COM' }), /Domain=example\.com/);
});

test('one leading domain dot is normalized away', () => {
  assert.match(serializeCookie('sid', 'x', { domain: '.example.com' }), /Domain=example\.com/);
});

test('valid IPv4 literal accepted only when explicitly allowed', () => {
  assert.match(serializeCookie('sid', 'x', { domain: '192.0.2.1', allowIpLiteral: true }), /Domain=192\.0\.2\.1/);
});

const invalidDomains = [
  ['', 'empty'],
  [' example.com', 'leading whitespace'],
  ['example.com ', 'trailing whitespace'],
  ['example.com.', 'trailing root dot'],
  ['..example.com', 'empty leading label'],
  ['example..com', 'empty inner label'],
  ['exa_mple.com', 'underscore'],
  ['-example.com', 'leading hyphen'],
  ['example-.com', 'trailing hyphen'],
  ['example.c_m', 'underscore in tld'],
  ['example.com/path', 'slash'],
  ['example.com:443', 'port'],
  ['example.com;Secure', 'semicolon smuggling'],
  ['bad domain.example', 'embedded space'],
  ['example', 'single label'],
  ['localhost', 'localhost single label'],
  ['com', 'bare com tld'],
  ['.com', 'dotted com tld'],
  ['org', 'bare org tld'],
  ['co.uk', 'multi-part public suffix'],
  ['com.au', 'Australian public suffix'],
  ['192.0.2.1', 'IPv4 literal'],
  ['999.1.1.1', 'malformed IPv4 literal'],
  ['01.2.3.4', 'leading zero IPv4 literal'],
  ['[2001:db8::1]', 'IPv6 literal'],
  ['caf\u00e9.example', 'non-ASCII domain', CODE.NON_ASCII],
  ['exam\rple.com', 'CR control', CODE.CRLF],
  ['exam\nple.com', 'LF control', CODE.CRLF],
  ['exam\x00ple.com', 'NUL control', CODE.CONTROL_CHARACTER]
];
for (const row of invalidDomains) {
  const [domain, label, code = CODE.DOMAIN] = row;
  test('invalid domain rejected: ' + label, () => {
    throwsCode(() => serializeCookie('sid', 'x', { domain }), code);
  });
}

test('overlong DNS label is rejected', () => {
  throwsCode(() => serializeCookie('sid', 'x', { domain: 'a'.repeat(64) + '.example.com' }), CODE.DOMAIN);
});

test('overlong complete domain is rejected', () => {
  const domain = Array.from({ length: 130 }, () => 'ab').join('.') + '.com';
  throwsCode(() => serializeCookie('sid', 'x', { domain }), CODE.DOMAIN);
});

test('additional public suffix entries are enforced', () => {
  throwsCode(() => serializeCookie('sid', 'x', {
    domain: 'city.example',
    additionalPublicSuffixes: ['city.example']
  }), CODE.DOMAIN);
});

test('additional public suffix entries accept leading dot input but normalize before comparison', () => {
  throwsCode(() => serializeCookie('sid', 'x', {
    domain: 'city.example',
    additionalPublicSuffixes: ['.city.example']
  }), CODE.DOMAIN);
});

test('additional public suffix entries validate item type', () => {
  throwsCode(() => serializeCookie('sid', 'x', { additionalPublicSuffixes: [1] }), CODE.OPTIONS);
});

test('additional public suffix entries reject invalid DNS syntax', () => {
  throwsCode(() => serializeCookie('sid', 'x', { additionalPublicSuffixes: ['bad_suffix'] }), CODE.OPTIONS);
});

for (const path of ['/', '/app', '/app/', '/%20spaces', '/a/b/c', '/0-9A-Z_a-z']) {
  test('valid path accepted: ' + path, () => {
    assert.match(serializeCookie('sid', 'x', { path }), new RegExp('Path=' + path.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  });
}

const invalidPaths = [
  ['', 'empty'],
  ['relative', 'does not start slash'],
  ['/a;b', 'semicolon'],
  ['/a b', 'space'],
  ['/a,b', 'comma'],
  ['/a"b', 'double quote'],
  ['/a\\b', 'backslash'],
  ['/a\rb', 'CR'],
  ['/a\nb', 'LF'],
  ['/a\x00b', 'NUL'],
  ['/a\tb', 'tab'],
  ['/caf\u00e9', 'non-ASCII'],
  ['/a%b', 'malformed percent'],
  ['/a%0ab', 'encoded LF'],
  ['/a%zz', 'bad hex percent']
];
for (const [path, label] of invalidPaths) {
  test('invalid path rejected: ' + label, () => {
    const expected = path.includes('\r') || path.includes('\n') ? CODE.CRLF : undefined;
    try {
      serializeCookie('sid', 'x', { path });
      assert.fail('expected path rejection');
    } catch (error) {
      assert.equal(error.name, 'CookieCageError');
      if (expected) assert.equal(error.code, expected);
    }
  });
}

test('strictPercentEncoding false permits literal percent in path', () => {
  assert.match(serializeCookie('sid', 'x', { path: '/100%', strictPercentEncoding: false }), /Path=\/100%/);
});

test('non-string path rejected', () => {
  throwsCode(() => serializeCookie('sid', 'x', { path: 1 }), CODE.INVALID_INPUT);
});

test('non-string domain rejected', () => {
  throwsCode(() => serializeCookie('sid', 'x', { domain: 1 }), CODE.INVALID_INPUT);
});

test('unknown serialize option rejected', () => {
  throwsCode(() => serializeCookie('sid', 'x', { samesite: 'Lax' }), CODE.OPTIONS);
});

test('null serialize options rejected', () => {
  throwsCode(() => serializeCookie('sid', 'x', null), CODE.OPTIONS);
});

test('array serialize options rejected', () => {
  throwsCode(() => serializeCookie('sid', 'x', []), CODE.OPTIONS);
});

test('prototype key in serialize options rejected', () => {
  throwsCode(() => serializeCookie('sid', 'x', withProtoKey()), CODE.PROTOTYPE_KEY);
});

for (const key of ['httpOnly', 'secure', 'partitioned', 'encodeValue', 'strictPercentEncoding', 'allowIpLiteral']) {
  test('boolean option type enforced for ' + key, () => {
    throwsCode(() => serializeCookie('sid', 'x', { [key]: 'true' }), CODE.OPTIONS);
  });
}

for (const key of ['maxValueBytes', 'maxSerializedBytes']) {
  for (const value of [0, -1, 1.5, NaN, Infinity, '4096']) {
    test('numeric limit type enforced for ' + key + ': ' + String(value), () => {
      throwsCode(() => serializeCookie('sid', 'x', { [key]: value }), CODE.OPTIONS);
    });
  }
}

test('sameSite invalid string rejected', () => {
  throwsCode(() => serializeCookie('sid', 'x', { sameSite: 'Sometimes' }), CODE.SAMESITE);
});

test('sameSite whitespace padded value rejected', () => {
  throwsCode(() => serializeCookie('sid', 'x', { sameSite: ' Lax' }), CODE.SAMESITE);
});

test('sameSite non-string value rejected', () => {
  throwsCode(() => serializeCookie('sid', 'x', { sameSite: true }), CODE.SAMESITE);
});

test('serialized output never contains raw CR or LF for hostile attempted input', () => {
  for (const fn of [
    () => serializeCookie('sid', 'x\r\nX-Evil: 1', { encodeValue: true }),
    () => serializeCookie('sid\r\nX', 'x'),
    () => serializeCookie('sid', 'x', { path: '/\r\nX' }),
    () => serializeCookie('sid', 'x', { domain: 'example.com\r\nX' })
  ]) {
    assert.throws(fn, /CookieCage/);
  }
});

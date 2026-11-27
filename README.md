# cookiecage

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/draarivpatel-ui/cookiecage/badge)](https://scorecard.dev/viewer/?uri=github.com/draarivpatel-ui/cookiecage)

Zero-dependency RFC 6265bis cookie serialization, parsing, prefix validation and constant-time HMAC-signed cookie protection for Node.js.

`cookiecage` is a small, auditable security library for applications that need strict cookie boundaries rather than permissive string concatenation. It serializes hardened `Set-Cookie` values, parses incoming `Cookie` request headers into a null-prototype object, enforces `__Host-`, `__Secure-`, `SameSite=None` and CHIPS `Partitioned` invariants, and signs cookie values with HMAC-SHA256 while binding the cookie name, key id and optional expiration into the authenticated data.

- **Zero dependencies.** Only `node:crypto` is used, and only for HMAC-SHA256 and constant-time tag comparison.
- **Dual module.** Native ESM (`import`) and CommonJS (`require`) entry points generated from one source of truth.
- **Fail closed.** Invalid names, values, attributes, options, keys and signed values throw before unsafe output is produced.
- **Cookie-tossing defense.** Duplicate cookie names in a request header reject by default. Compatibility modes are explicit.
- **Prototype-pollution defense.** Parsed objects use `Object.create(null)` and dangerous names are rejected.
- **Rotation-ready signing.** Keyrings sign with the first key, verify with active retired keys, and report `rotated: true` when a non-primary key verifies.

**Tests:** 588 passing with `npm test` (Node 18+).

## Install

```sh
npm install cookiecage
```

No install scripts, no native builds, no transitive dependencies.

## Quick start

### ESM

```js
import {
  serializeCookie,
  parseCookieHeader,
  signCookieValue,
  verifyCookieValue
} from 'cookiecage';

const key = process.env.COOKIE_SIGNING_KEY;

const signed = signCookieValue('__Host-session', sessionId, key, {
  maxAge: 3600
});

const header = serializeCookie('__Host-session', signed, {
  sameSite: 'Strict',
  maxAge: 3600
});

// Later, in a request handler:
const cookies = req.headers.cookie
  ? parseCookieHeader(req.headers.cookie)
  : Object.create(null);
const verified = verifyCookieValue('__Host-session', cookies['__Host-session'], key);
```

### CommonJS

```js
const {
  serializeCookie,
  parseCookieHeader,
  signCookieValue,
  verifyCookieValue
} = require('cookiecage');
```

## Secure serialization defaults

`serializeCookie(name, value, options?)` emits a complete `Set-Cookie` value. The defaults are intentionally strict:

| Attribute | Default |
| --- | --- |
| `Path` | `/` |
| `HttpOnly` | present |
| `Secure` | present |
| `SameSite` | `Lax` |

Example:

```js
serializeCookie('session', 'abc123');
// session=abc123; Path=/; HttpOnly; Secure; SameSite=Lax
```

Attributes serialize in deterministic order: `Domain`, `Path`, `Max-Age`, `Expires`, `HttpOnly`, `Secure`, `SameSite`, `Partitioned`.

### Prefix and attribute invariants

Prefix enforcement is ASCII case-insensitive, matching the RFC 6265bis user-agent storage requirements. Use the canonical `__Host-` and `__Secure-` spellings; mixed-case variants cannot bypass the invariants:

- `__Host-` requires `Secure`, `Path=/` and no `Domain` attribute.
- `__Secure-` requires `Secure`.
- `SameSite=None` requires `Secure`.
- `Partitioned` requires `Secure`.

Violations throw `CookieCageError`; they are never silently corrected.

### Cookie names

Names must be RFC 6265 tokens. Empty names, whitespace, separators, control characters, CR, LF, non-ASCII characters and the prototype-pollution names `__proto__`, `constructor` and `prototype` are rejected.

### Cookie values

By default values must already be valid RFC 6265 cookie-octet data. Raw spaces, commas, semicolons, quotes, backslashes, controls and non-ASCII characters are rejected. A percent sign must begin a two-digit hexadecimal escape. Percent-encoded C0 and DEL controls are rejected as defense in depth.

Set `encodeValue: true` when the input is a logical UTF-8 string that should be percent-encoded:

```js
serializeCookie('prefs', 'dark mode', { encodeValue: true });
// prefs=dark%20mode; Path=/; HttpOnly; Secure; SameSite=Lax
```

Controls are rejected even when `encodeValue` is true. This library does not silently encode CRLF. It cannot make a control character safe to place in a header.

The encoded value is limited to 4096 bytes by default. The complete serialized `Set-Cookie` value is also limited to 4096 bytes by default. Applications with tighter cookie budgets should lower these limits rather than raise them.

### Domain validation

The preferred secure design is host-only cookies with no `Domain` attribute. When `domain` is supplied, cookiecage canonicalizes it to lowercase, removes one leading dot, rejects trailing root dots, whitespace, controls, semicolons, ports, paths, empty labels, invalid DNS labels, single-label names, common public suffixes and IPv4 literals. `allowIpLiteral: true` permits valid dotted decimal IPv4 literals; IPv6 literals remain rejected.

The public suffix check is conservative and includes common multi-part suffixes such as `co.uk` and `com.au`. It is not a complete Public Suffix List implementation. Use `additionalPublicSuffixes` for organization-specific suffixes, and prefer host-only cookies whenever possible.

### Path validation

Paths must start with `/` and be RFC 6265 cookie-octet data. Spaces, commas, quotes, backslashes, semicolons, controls and non-ASCII characters are rejected; use percent encoding for characters outside the grammar.

### Max-Age and Expires

`maxAge` must be a safe integer from 0 through 34560000 seconds (400 days). `NaN`, infinity, booleans, strings and fractional values are rejected.

`expires` must be a valid finite `Date`. It is serialized as an RFC 7231 IMF-fixdate with correct weekday and a four-digit year.

### Deleting cookies

`deleteCookie(name, options?)` emits an expiration cookie with `Max-Age=0` and `Expires=Thu, 01 Jan 1970 00:00:00 GMT` while preserving the same prefix, path, SameSite and Secure invariants:

```js
deleteCookie('__Host-session');
// __Host-session=; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; Secure; SameSite=Lax
```

`Max-Age` and `Expires` are managed by the helper and cannot be overridden.

## Strict request-header parsing

`parseCookieHeader(header, options?)` parses an incoming `Cookie` header into `Object.create(null)`:

```js
const cookies = parseCookieHeader('session=abc; theme=dark');
cookies.session; // abc
```

Balanced quoted cookie values are accepted, and the quote characters are preserved as part of the exact value. RFC 6265bis states that the quotes are not stripped, so `"abc"` and `abc` must never collapse into the same application value. Percent escapes inside or outside quotes are preserved unless `decodeValues: true` is explicitly enabled. Decoding uses strict UTF-8 and rejects malformed input and decoded control characters.

ASCII spaces before a cookie pair are tolerated as transport whitespace, including multiple spaces after a semicolon. Tabs are rejected as control characters. Spaces after a value are not trimmed; they make the value invalid because spaces are outside the cookie-octet grammar.

### Cookie-tossing duplicate policy

Duplicate names are rejected by default:

```js
parseCookieHeader('session=real; session=attacker');
// throws ERR_COOKIECAGE_DUPLICATE_COOKIE
```

This matters because a compromised or attacker-controlled subdomain can sometimes cause a browser to send multiple cookies with the same name. If an application cannot yet reject duplicates, it must make an explicit compatibility choice:

- `duplicatePolicy: 'first'` keeps the first occurrence.
- `duplicatePolicy: 'last'` keeps the last occurrence.

Neither compatibility mode is proof that the selected cookie is the intended one. They exist only so the choice is visible in application code.

### Parser denial-of-service bounds

Defaults are `maxHeaderBytes: 16384`, `maxCookies: 100` and `maxCookieBytes: 4096`. The header size is checked before parsing. Each segment is bounded before value validation. No regex in the parser uses nested quantifiers or backtracking-dependent constructions.

## Signed cookie values

`signCookieValue(name, value, keyOrKeyring, options?)` signs a UTF-8 string with HMAC-SHA256 and returns a compact ASCII v1 value. `verifyCookieValue` authenticates it with `timingSafeEqual` and returns:

```js
{
  value: 'original value',
  keyId: 'key2026',
  rotated: false,
  expiresAt: null
}
```

The HMAC input binds all of the following:

- the cookie name, preventing cross-cookie substitution;
- the key id, preventing key-identifier substitution;
- the embedded expiration field;
- the payload bytes.

The payload is base64url encoded, not encrypted. Do not place secrets in a signed cookie unless they are encrypted by a separate appropriate mechanism.

The v1 envelope is canonical. It rejects standard base64 `+` and `/` spellings, padding, noncanonical base64url trailing bits, noncanonical expiration fields, wrong-length tags and extra or missing parts.

### Keys

A direct string or `Uint8Array` uses the implicit key id `k1`. Production secrets must be at least 32 bytes, contain reasonable byte diversity and not look like placeholders. Whitespace-padded secrets are rejected.

```js
const keyring = {
  keys: [
    { id: 'key2026', secret: process.env.COOKIE_KEY_2026 },
    { id: 'key2025', secret: process.env.COOKIE_KEY_2025 }
  ]
};
```

The first key signs. Every active key may verify. If `key2025` verifies a value, the result has `keyId: 'key2025'` and `rotated: true`. Remove an old key from the keyring when its values should stop verifying. A keyring may contain at most 32 keys.

`allowWeakKeysForTests: true` is an explicit test-only escape hatch. It is not a production compatibility setting. In a configured guard, the escape is scoped to the operation options where it appears; sign-only test configuration does not make verification accept a weak key.

### Expiration

Pass `maxAge` in seconds when signing. The absolute expiration is embedded in the authenticated payload and checked during verification. An expired value throws `ERR_COOKIECAGE_COOKIE_EXPIRED` after its MAC has been authenticated. For deterministic tests, pass `now` as a nonnegative millisecond timestamp or a `Date` at or after the Unix epoch.

## Reusable guard

`createCookieJarGuard` creates a frozen configured facade:

```js
const guard = createCookieJarGuard({
  keyOrKeyring: keyring,
  serialize: { sameSite: 'Strict' },
  parse: { duplicatePolicy: 'reject' },
  sign: { maxAge: 3600 }
});

const value = guard.sign('__Host-session', sessionId);
const header = guard.serialize('__Host-session', value);
const cookies = req.headers.cookie
  ? guard.parse(req.headers.cookie)
  : Object.create(null);
const verified = guard.verify('__Host-session', cookies['__Host-session']);
const deletion = guard.delete('__Host-session');
```

Per-call options override guard defaults. `keyOrKeyring` can also be supplied in `sign` or `verify` configuration or per call.

## Errors

All validation failures throw `CookieCageError` with stable machine-readable `code` values such as:

- `ERR_COOKIECAGE_CRLF`
- `ERR_COOKIECAGE_CONTROL_CHARACTER`
- `ERR_COOKIECAGE_PREFIX_INVARIANT`
- `ERR_COOKIECAGE_INVALID_DOMAIN`
- `ERR_COOKIECAGE_DUPLICATE_COOKIE`
- `ERR_COOKIECAGE_WEAK_KEY`
- `ERR_COOKIECAGE_INVALID_SIGNATURE`
- `ERR_COOKIECAGE_COOKIE_EXPIRED`

Error messages and `toJSON()` deliberately omit cookie values and secrets. Numeric sizes and safe field names may be included.

## Scope and limitations

- This library validates and constructs cookie values. It is not a browser cookie jar and does not implement origin, domain or path matching.
- `parseCookieHeader` parses the `Cookie` request header. It does not parse `Set-Cookie` response attributes. Empty input is invalid because the RFC grammar requires at least one cookie pair; call the parser only when a Cookie header is present.
- The public suffix defense is conservative, not a complete Public Suffix List. Host-only cookies remain the safer default.
- Signing is authentication, not encryption. Payloads are visible to anyone who can read the cookie.
- Constant-time comparison is used for fixed-length HMAC tags. JavaScript cannot remove every higher-level timing signal in an application or runtime.
- Percent encoding is not encryption or canonicalization across every framework. If downstream middleware decodes values differently, use signed values or keep values restricted to plain cookie octets.
- Node.js 18 or newer is required.

## Development

No install step is required because the package has no dependencies.

```sh
npm test
node scripts/build-cjs.mjs --check
npm pack --dry-run
```

The test suite covers RFC prefix invariants, CRLF and control-character rejection, attribute smuggling, cookie tossing, prototype pollution, deterministic size bounds, signed-value tampering, key rotation, expiry enforcement, ESM/CJS parity, TypeScript declaration surface and repository hygiene.

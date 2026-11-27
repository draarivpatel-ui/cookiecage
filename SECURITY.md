# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| 1.x | Yes |
| < 1.0 | No |

## Reporting a vulnerability

Use the private GitHub Security Advisories form: [Report a vulnerability](https://github.com/draarivpatel-ui/cookiecage/security/advisories/new). Do not open a public issue for an exploitable finding.

Include:

- A minimal proof of concept input or signed value using synthetic secrets.
- The affected version and Node.js version.
- The expected security boundary and the observed violation.
- Whether the issue permits header injection, cookie-tossing shadowing, signature forgery, expiration bypass, prototype pollution or a documented limit bypass.

Never include a real session cookie, signing key, production value or personal data in a report. Use synthetic values that reproduce the behavior.

We acknowledge reports within 48 hours. We aim to confirm or reject the report within 7 days, release a fix as soon as practical, and coordinate public disclosure with the reporter. Unless a shorter deadline is required by an actively exploited issue, please allow up to 90 days for a coordinated fix and disclosure.

## Scope

The following are in scope:

- CRLF or other control characters reaching serialized header output.
- Failure to enforce documented `__Host-`, `__Secure-`, `SameSite=None` or `Partitioned` invariants.
- Domain, path, Max-Age or Expires validation bypasses that contradict documented rules.
- Prototype pollution through cookie names, parser output, keyrings or option objects.
- Duplicate cookie handling that differs from the configured `duplicatePolicy`.
- Signature verification bypasses, cross-cookie substitution, key-id substitution, tag truncation acceptance or expiration bypass.
- Use of non-constant-time comparison for complete fixed-length HMAC tags.
- Secret values appearing in errors, `toJSON()` output or other diagnostics.
- Documented parser or serializer size-limit bypasses.

The following are generally out of scope:

- Disclosure of data intentionally placed in a signed payload. Signing is authentication, not encryption.
- An attacker who can already execute JavaScript in the same process or inspect process memory.
- Weak secrets explicitly accepted with `allowWeakKeysForTests`.
- Browser behavior outside the documented RFC validation boundary.
- Resource use within documented input size limits that is proportional to input size.
- The absence of a complete Public Suffix List. The built-in suffix defense is documented as conservative.

## Security design notes

- Errors never include raw cookie values or key material.
- Request-header parsing returns a null-prototype object and rejects `__proto__`, `constructor` and `prototype` cookie names.
- Duplicate cookie names reject by default because silently choosing one can enable cookie-tossing attacks.
- Signed values authenticate the cookie name, key id, expiration field and payload in one HMAC input.
- HMAC tags are decoded to fixed 32-byte values before `timingSafeEqual` is used.
- Keyrings are capped at 32 active keys so verification work remains bounded.
- Size limits are applied before large parser inputs are scanned or split.

## Disclosure history

No published advisories yet. Fixed versions will be listed here with their advisory links.

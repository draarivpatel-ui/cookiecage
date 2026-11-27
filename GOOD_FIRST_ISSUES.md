# Good first issues

These 10 tasks are intentionally narrow. Each can be completed without changing the public architecture. Before starting, read CONTRIBUTING.md and open or claim the matching issue.

## 1. RFC token character matrix

Add a complete character-class test matrix for cookie names covering every rejected RFC separator and every permitted printable symbol. Keep the implementation unchanged unless a matrix entry proves a real mismatch.

Acceptance checklist:

- Tests identify each character by numeric code point.
- Control characters and separators are separated into independent rows.
- No implementation change without a documented RFC citation in the pull request.

## 2. Public suffix documentation examples

Add documentation and tests showing the difference between a bare TLD, a common multi-part suffix, a registrable domain and a subdomain.

Acceptance checklist:

- Document that the built-in suffix set is conservative and not the complete Public Suffix List.
- Add examples for `co.uk` and `com.au`.
- Do not vendor a large suffix list into the package.

## 3. Quoted value compatibility matrix

Add tests pinning the exact treatment of empty quotes, balanced quotes, mismatched quotes, interior quotes and percent escapes inside quotes.

Acceptance checklist:

- Tests state whether quotes are syntactic or part of the application value.
- README.md matches the tested behavior.
- No behavior change unless the issue explicitly approves one.

## 4. Whitespace strictness decision record

Research the exact RFC whitespace grammar for Cookie request headers and compare it with the parser's compatibility behavior. Add a short documentation note and hostile whitespace regression tests.

Acceptance checklist:

- Cover no space, one space, multiple spaces and tab after semicolons.
- Cover leading and trailing whitespace around the complete header.
- Do not silently change behavior; propose any change explicitly in the issue first.

## 5. Additional public suffix validation tests

Add boundary tests for `additionalPublicSuffixes`, including mixed case, leading dots, invalid labels, too many entries, non-ASCII input and duplicate entries.

Acceptance checklist:

- Error output never includes the untrusted suffix string.
- Valid organization-specific suffixes still reject exact matches.
- Subdomains below those suffixes remain accepted.

## 6. Signed format canonicalization review

Add tests for noncanonical expiration fields, base64url spelling, empty payloads and malformed part boundaries. Propose whether strict canonical form should reject representations the current HMAC already makes unforgeable.

Acceptance checklist:

- No secret-bearing fixture.
- Every malformed form throws `CookieCageError` rather than a platform type error.
- Document any intentional compatibility acceptance.

## 7. TypeScript compile fixture

Add a small TypeScript compile fixture in tests or CI without adding runtime dependencies. If the TypeScript compiler is needed, it must be a development-only CI tool rather than a package dependency.

Acceptance checklist:

- Exercise every public function and option surface.
- Prove `VerifiedCookieValue.rotated` and `expiresAt` are typed.
- `dependencies` and `devDependencies` in package.json remain empty.

## 8. Cross-module keyring regression tests

Add tests that sign through ESM with one keyring and verify through CommonJS after simulated rotation, then repeat in the opposite direction.

Acceptance checklist:

- `rotated` metadata is identical in both directions.
- Removed keys stop verifying in both entry points.
- Synthetic keys remain at least 32 bytes.

## 9. Package tarball audit automation

Extend the package hygiene test with explicit expectations for the files included by `npm pack --dry-run`.

Acceptance checklist:

- The test does not require network access.
- It verifies source, CJS, types, README, SECURITY, CONTRIBUTING, GOOD_FIRST_ISSUES and LICENSE inclusion.
- It verifies tests and git metadata are not published.

## 10. Deterministic fuzz seed expansion

Add a fixed-seed mutation corpus for Cookie headers and signed values. The goal is crash freedom and stable error types, not random coverage that changes between runs.

Acceptance checklist:

- Use a fixed seed and fixed iteration count.
- Assert no object prototype is polluted.
- Assert errors are `CookieCageError` instances with documented code strings.
- Keep total added runtime below 100 ms on a typical development machine.

/** Error codes emitted by cookiecage. */
export const CODE: Readonly<{
  INVALID_INPUT: 'ERR_COOKIECAGE_INVALID_INPUT';
  OPTIONS: 'ERR_COOKIECAGE_INVALID_OPTIONS';
  NAME: 'ERR_COOKIECAGE_INVALID_NAME';
  VALUE: 'ERR_COOKIECAGE_INVALID_VALUE';
  CRLF: 'ERR_COOKIECAGE_CRLF';
  CONTROL_CHARACTER: 'ERR_COOKIECAGE_CONTROL_CHARACTER';
  NON_ASCII: 'ERR_COOKIECAGE_NON_ASCII';
  PROTOTYPE_KEY: 'ERR_COOKIECAGE_PROTOTYPE_KEY';
  PREFIX: 'ERR_COOKIECAGE_PREFIX_INVARIANT';
  SAMESITE: 'ERR_COOKIECAGE_SAMESITE_INVARIANT';
  PARTITIONED: 'ERR_COOKIECAGE_PARTITIONED_INVARIANT';
  DOMAIN: 'ERR_COOKIECAGE_INVALID_DOMAIN';
  PATH: 'ERR_COOKIECAGE_INVALID_PATH';
  MAX_AGE: 'ERR_COOKIECAGE_INVALID_MAX_AGE';
  EXPIRES: 'ERR_COOKIECAGE_INVALID_EXPIRES';
  LIMIT_EXCEEDED: 'ERR_COOKIECAGE_LIMIT_EXCEEDED';
  PARSE: 'ERR_COOKIECAGE_PARSE';
  DUPLICATE: 'ERR_COOKIECAGE_DUPLICATE_COOKIE';
  ENCODING: 'ERR_COOKIECAGE_ENCODING';
  WEAK_KEY: 'ERR_COOKIECAGE_WEAK_KEY';
  KEYRING: 'ERR_COOKIECAGE_INVALID_KEYRING';
  SIGNATURE: 'ERR_COOKIECAGE_INVALID_SIGNATURE';
  EXPIRED: 'ERR_COOKIECAGE_COOKIE_EXPIRED';
}>;

export type CookieCageErrorCode =
  'ERR_COOKIECAGE_INVALID_INPUT' | 'ERR_COOKIECAGE_INVALID_OPTIONS' |
  'ERR_COOKIECAGE_INVALID_NAME' | 'ERR_COOKIECAGE_INVALID_VALUE' |
  'ERR_COOKIECAGE_CRLF' | 'ERR_COOKIECAGE_CONTROL_CHARACTER' |
  'ERR_COOKIECAGE_NON_ASCII' | 'ERR_COOKIECAGE_PROTOTYPE_KEY' |
  'ERR_COOKIECAGE_PREFIX_INVARIANT' | 'ERR_COOKIECAGE_SAMESITE_INVARIANT' |
  'ERR_COOKIECAGE_PARTITIONED_INVARIANT' | 'ERR_COOKIECAGE_INVALID_DOMAIN' |
  'ERR_COOKIECAGE_INVALID_PATH' | 'ERR_COOKIECAGE_INVALID_MAX_AGE' |
  'ERR_COOKIECAGE_INVALID_EXPIRES' | 'ERR_COOKIECAGE_LIMIT_EXCEEDED' |
  'ERR_COOKIECAGE_PARSE' | 'ERR_COOKIECAGE_DUPLICATE_COOKIE' |
  'ERR_COOKIECAGE_ENCODING' | 'ERR_COOKIECAGE_WEAK_KEY' |
  'ERR_COOKIECAGE_INVALID_KEYRING' | 'ERR_COOKIECAGE_INVALID_SIGNATURE' |
  'ERR_COOKIECAGE_COOKIE_EXPIRED';

/** Structured error thrown for validation failures and unsafe input. Raw values and secrets are never exposed. */
export declare class CookieCageError extends Error {
  constructor(code: CookieCageErrorCode | string, reason: string, details?: {
    field?: string;
    keyId?: string;
    limit?: number;
    actual?: number;
    index?: number;
  });
  readonly name: 'CookieCageError';
  readonly code: CookieCageErrorCode | string;
  readonly reason: string;
  readonly field?: string;
  readonly keyId?: string;
  readonly limit?: number;
  readonly actual?: number;
  readonly index?: number;
  toJSON(): {
    name: string;
    code: string;
    reason: string;
    message: string;
    field?: string;
    keyId?: string;
    limit?: number;
    actual?: number;
    index?: number;
  };
}

export type SameSiteInput = 'Strict' | 'Lax' | 'None' | 'strict' | 'lax' | 'none';

export interface SerializeCookieOptions {
  /** Canonical DNS host name. Leading dot is normalized away. Single-label and known public suffixes are rejected. */
  domain?: string;
  /** Cookie path. Must start with `/` and must not contain semicolons, controls or non-ASCII characters. */
  path?: string;
  /** Seconds, integer from 0 through 34560000 (400 days). */
  maxAge?: number;
  /** Valid finite Date with a year from 0000 through 9999. Serialized as an RFC 7231 IMF-fixdate. */
  expires?: Date;
  /** Default true. */
  httpOnly?: boolean;
  /** Default true. Explicit false is rejected when a prefix or attribute invariant requires Secure. */
  secure?: boolean;
  /** Default Lax. Input case is canonicalized. */
  sameSite?: SameSiteInput;
  /** Default false. True requires Secure. */
  partitioned?: boolean;
  /** Default false. When true, disallowed value characters are UTF-8 percent-encoded. Controls are always rejected. */
  encodeValue?: boolean;
  /** Default true. Requires every percent sign to begin a two-digit hex escape and rejects encoded C0 and DEL controls. */
  strictPercentEncoding?: boolean;
  /** Maximum encoded value bytes. Default 4096. */
  maxValueBytes?: number;
  /** Maximum complete Set-Cookie header bytes. Default 4096. */
  maxSerializedBytes?: number;
  /** Default false. When true, valid dotted decimal IPv4 literals are accepted. IPv6 literals remain rejected. */
  allowIpLiteral?: boolean;
  /** Extra lowercase or mixed-case DNS suffixes to treat as public suffixes. */
  additionalPublicSuffixes?: readonly string[];
}

export type DeleteCookieOptions = Omit<SerializeCookieOptions, 'maxAge' | 'expires'>;

export type DuplicatePolicy = 'reject' | 'first' | 'last';

export interface ParseCookieHeaderOptions {
  /** Maximum complete Cookie header bytes. Default 16384. */
  maxHeaderBytes?: number;
  /** Maximum number of cookie segments. Default 100. */
  maxCookies?: number;
  /** Maximum bytes in one cookie segment and one undecoded value. Default 4096. */
  maxCookieBytes?: number;
  /** Default reject. first and last are explicit compatibility modes for cookie-tossing environments. */
  duplicatePolicy?: DuplicatePolicy;
  /** Default false. When true, percent escapes are decoded as strict UTF-8 after validation. */
  decodeValues?: boolean;
  /** Default true. Rejects malformed percent escapes and percent-encoded C0 or DEL controls. */
  strictPercentEncoding?: boolean;
}

/** Null-prototype map returned by parseCookieHeader. */
export type CookieMap = Record<string, string>;

export interface CookieSigningKey {
  /** URL-safe key identifier, 1 to 64 characters from ASCII alphanumeric, underscore or hyphen, starting alphanumeric. */
  id: string;
  /** String or binary HMAC secret. At least 32 bytes unless allowWeakKeysForTests is explicitly true. */
  secret: string | Uint8Array;
}

export interface CookieKeyring {
  /** First key signs. Every active key may verify. Maximum 32 keys. */
  keys: readonly CookieSigningKey[];
}

export type KeyOrKeyring = string | Uint8Array | CookieKeyring;

export interface SignCookieValueOptions {
  /** Optional embedded expiration lifetime in seconds, integer from 1 through 34560000. */
  maxAge?: number;
  /** Deterministic clock override for tests, as nonnegative milliseconds since the Unix epoch or a valid Date. */
  now?: number | Date;
  /** Minimum secret bytes. Values below 32 are honored only with allowWeakKeysForTests. Default 32. */
  minSecretBytes?: number;
  /** Test-only escape hatch for weak or short keys. Never use in production. */
  allowWeakKeysForTests?: boolean;
  /** Maximum unsigned value bytes. Default 4096. */
  maxValueBytes?: number;
  /** Maximum complete signed cookie value bytes. Default 4096. */
  maxSignedBytes?: number;
}

export interface VerifyCookieValueOptions {
  /** Deterministic clock override for tests, as nonnegative milliseconds since the Unix epoch or a valid Date. */
  now?: number | Date;
  /** Minimum secret bytes. Values below 32 are honored only with allowWeakKeysForTests. Default 32. */
  minSecretBytes?: number;
  /** Test-only escape hatch for weak or short keys. Never use in production. */
  allowWeakKeysForTests?: boolean;
  /** Maximum decoded payload bytes. Default 4096. */
  maxValueBytes?: number;
  /** Maximum complete signed cookie value bytes. Default 4096. */
  maxSignedBytes?: number;
}

export interface VerifiedCookieValue {
  /** Original unsigned UTF-8 value. */
  readonly value: string;
  /** Key identifier that verified the value. */
  readonly keyId: string;
  /** True when the verifying key is not the first signing key in the keyring. */
  readonly rotated: boolean;
  /** Embedded expiration timestamp in milliseconds, or null when no expiration was embedded. */
  readonly expiresAt: number | null;
}

export interface GuardSignOptions extends SignCookieValueOptions {
  /** Per-call or per-guard override for the top-level keyOrKeyring. */
  keyOrKeyring?: KeyOrKeyring;
}

export interface GuardVerifyOptions extends VerifyCookieValueOptions {
  /** Per-call or per-guard override for the top-level keyOrKeyring. */
  keyOrKeyring?: KeyOrKeyring;
}

export interface CookieJarGuardOptions {
  serialize?: SerializeCookieOptions;
  delete?: DeleteCookieOptions;
  parse?: ParseCookieHeaderOptions;
  sign?: GuardSignOptions;
  verify?: GuardVerifyOptions;
  keyOrKeyring?: KeyOrKeyring;
}

export interface CookieJarGuard {
  serialize(name: string, value: string, options?: SerializeCookieOptions): string;
  delete(name: string, options?: DeleteCookieOptions): string;
  parse(header: string, options?: ParseCookieHeaderOptions): CookieMap;
  sign(name: string, value: string, options?: GuardSignOptions): string;
  verify(name: string, signedValue: string, options?: GuardVerifyOptions): VerifiedCookieValue;
}

/** Serialize a hardened Set-Cookie header with secure defaults. */
export function serializeCookie(name: string, value: string, options?: SerializeCookieOptions): string;

/** Serialize an expiration cookie. Max-Age and Expires are managed by the helper and cannot be supplied. */
export function deleteCookie(name: string, options?: DeleteCookieOptions): string;

/** Parse a Cookie request header into a null-prototype object. Duplicate names reject by default. */
export function parseCookieHeader(header: string, options?: ParseCookieHeaderOptions): CookieMap;

/** Sign a value with HMAC-SHA256. The cookie name, key id and expiration are bound into the MAC input. */
export function signCookieValue(name: string, value: string, keyOrKeyring: KeyOrKeyring, options?: SignCookieValueOptions): string;

/** Verify a signed value in constant time and return the original value with key rotation metadata. */
export function verifyCookieValue(name: string, signedValue: string, keyOrKeyring: KeyOrKeyring, options?: VerifyCookieValueOptions): VerifiedCookieValue;

/** Create a reusable configured guard. */
export function createCookieJarGuard(options?: CookieJarGuardOptions): CookieJarGuard;

declare const cookiecage: Readonly<{
  CODE: typeof CODE;
  CookieCageError: typeof CookieCageError;
  serializeCookie: typeof serializeCookie;
  deleteCookie: typeof deleteCookie;
  parseCookieHeader: typeof parseCookieHeader;
  signCookieValue: typeof signCookieValue;
  verifyCookieValue: typeof verifyCookieValue;
  createCookieJarGuard: typeof createCookieJarGuard;
}>;

export default cookiecage;

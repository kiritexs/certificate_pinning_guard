# Changelog

## 0.1.0

- Initial release.
- `createPinnedHttpClient` — handshake (anchor) pinning via a private trust
  store (`SecurityContext(withTrustedRoots: false)`), the bypass-resistant
  primary mechanism.
- `CertificatePinner` — optional leaf / SPKI defense-in-depth pinning, any-match
  over multiple pins, backup-pin support, enforce vs report-only, fail-closed.
- `Pin` — canonical `sha256/<base64>` pins with explicit (never inferred)
  encoding and constant-time comparison.
- `extractSpkiDer` (opt-in) — strict, bounds-checked ASN.1 SPKI extractor for
  public-key pinning.
- Runs on Android, iOS, Linux, macOS and Windows, and in Dart command-line
  and server programs; not on the web, where the browser owns TLS.

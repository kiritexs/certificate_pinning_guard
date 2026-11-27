# certificate_pinning_guard

Reusable, **bypass-resistant** TLS certificate pinning for Dart & Flutter apps.
Pure Dart (`dart:io` + `crypto`), no Flutter dependency — drop it into any
project.

It exists because the naive Flutter pinning recipe you'll find everywhere is
**fail-open**, and getting pinning subtly wrong gives you *zero* protection
while looking like it works.

## When to use it

Choose it when your app talks to your own API and must refuse anyone in the
middle, including a certificate authority the user or a device manager
installed.

- Only the root or intermediate certificates you pin are trusted, checked
  during the TLS handshake before a single byte of your request is sent.
- Optional leaf or public-key pins on top, for the exact certificate or key.
- It fails closed: a mismatch, a missing certificate or a misconfiguration
  is an error, never a silent pass.
- Pure Dart, so it works the same in Flutter apps, command-line tools and
  servers, with `package:http`, `dio` or a raw `HttpClient`.

---

## The trap this avoids

The common advice is:

```dart
// ❌ DOES NOT PIN. Silently accepts a MITM.
httpClient.badCertificateCallback = (cert, host, port) => sha256(cert.der) == myPin;
```

`badCertificateCallback` **only fires when the default trust check FAILS.** On
the normal system trust store, a certificate that chains to *any* trusted
root — a public CA, or an **attacker/MDM/proxy root installed on the device**
(Charles, mitmproxy, Burp, a corporate MDM profile) — passes validation, so the
callback, and therefore your pin check, **never runs.** The connection is
accepted.

**This package moves enforcement into the TLS handshake instead**, against a
*private* trust store, so a cert that doesn't chain to *your* anchor fails
before a single request byte is sent.

---

## Two layers

| Layer | Mechanism | Strength | Works with |
|------|-----------|----------|-----------|
| **1. Anchor pin (primary)** | `SecurityContext(withTrustedRoots: false)` + your CA/intermediate PEM | Strongest — enforced in the handshake, **pre-send**, defeats MITM roots | `http`, `dio`, raw `HttpClient` |
| **2. Leaf / SPKI pin (defense-in-depth)** | `CertificatePinner` checks the negotiated leaf's SHA-256 / public-key hash | Pins the exact cert/key, catches a mis-issued cert under your own CA | `dio` (`validateCertificate`), raw `HttpClient` (`response.certificate`) |

Anchor pinning alone is legitimate, strong pinning. Add layer 2 when you want to
pin the exact leaf or key as well.

---

## Install

```yaml
dependencies:
  certificate_pinning_guard:
    path: ../certificate_pinning_guard   # or git:, or publish it internally
```

Only `crypto` is pulled in. `http` / `dio` stay *your* app's dependencies — the
wiring below is copy-paste so this package never forces a transport on you.

---

## Scoping (read this)

**Pin one service per client.** A pinned client trusts *only* your anchor, so
route that service's calls through it and send everything else (analytics, CDNs,
image hosts) through a normal client. Give each pinned service its own anchor +
client so one service's anchor can never validate another service's host.

---

## Usage

### Raw `dart:io HttpClient`

```dart
import 'package:certificate_pinning_guard/certificate_pinning_guard.dart';

final client = createPinnedHttpClient(
  trustedAnchorsPem: await rootBundleOrFileBytes('assets/api_ca.pem'),
);
// Handshake now pins to your CA. (Optional) also pin the leaf/key:
final pinner = CertificatePinner(pins: [Pin.parse('sha256/…'), Pin.parse('sha256/…backup')]);

final res = await (await client.getUrl(uri)).close();
verifyResponseCertificate(pinner, res, host: uri.host); // throws on mismatch
```

### `package:http`

`http`'s `IOClient` does not expose the negotiated certificate, so with `http`
you get **anchor pinning** (which is strong). Wrap the pinned client:

```dart
import 'package:http/io_client.dart';
import 'package:certificate_pinning_guard/certificate_pinning_guard.dart';

final httpClient = IOClient(
  createPinnedHttpClient(trustedAnchorsPem: caPem),
);
// Use httpClient for this service only.
```

### `dio`

Layer `validateCertificate` (leaf/SPKI) **over** the anchor client so the
handshake fails pre-send. Copy this ~15-line adapter (keeps `dio` out of this
package's deps):

```dart
import 'package:dio/dio.dart';
import 'package:dio/io.dart';
import 'package:certificate_pinning_guard/certificate_pinning_guard.dart';

void applyPinning(Dio dio, {required List<int> caPem, required CertificatePinner pinner}) {
  dio.httpClientAdapter = IOHttpClientAdapter(
    createHttpClient: () => createPinnedHttpClient(trustedAnchorsPem: caPem), // pre-send anchor gate
    validateCertificate: (cert, host, port) {                                 // per-connection leaf/SPKI gate
      // In enforce mode this throws on mismatch; returning true only reaches
      // here for anchor-valid certs.
      return pinner.verifyCertificate(cert, host: host);
    },
  );
}
```

> Note (dio #2418): `validateCertificate` currently runs *after* request bytes
> are flushed, so it can only reject the response — which is why the anchor
> client under it (pre-send) is what actually protects the request.

### SPKI (public-key) pinning — opt-in

`X509Certificate` exposes no public key, so SPKI pins need the extractor:

```dart
import 'package:certificate_pinning_guard/certificate_pinning_guard.dart';
import 'package:certificate_pinning_guard/spki.dart';

final pinner = CertificatePinner(
  pins: [Pin.parse('sha256/…', kind: PinKind.publicKey)],
  spkiExtractor: extractSpkiDer,
);
```

---

## Getting your pins

```bash
# Whole-certificate SHA-256 pin (PinKind.certificate)
openssl x509 -in server.crt -outform DER \
  | openssl dgst -sha256 -binary | base64
# -> use as: sha256/<output>

# Public-key (SPKI) SHA-256 pin (PinKind.publicKey) — survives cert renewal
openssl x509 -in server.crt -pubkey -noout \
  | openssl pkey -pubin -outform DER \
  | openssl dgst -sha256 -binary | base64
# -> use as: sha256/<output>   with kind: PinKind.publicKey
```

Pin the **issuing intermediate CA** as the trust anchor and use an **SPKI** pin
on a stable key when you can — that combination survives routine leaf renewals
with no app update.

---

## Rotation runbook (don't brick your users)

An installed app can't be updated instantly, so **always ship a backup pin
before you rotate.** `CertificatePinner` accepts a match against *any* pin.

1. **Before** rotating the server cert, generate the next key/cert (or identify
   the incoming intermediate) and **add its pin** as a second entry in `pins`.
2. **Ship** the app update carrying both the current and the new pin. Wait for
   adoption.
3. **Rotate** the server certificate — already-updated clients trust it (any-match).
4. In a **later** release, drop the retired pin.

⚠️ A `PinKind.certificate` (whole-cert) pin changes on *every* reissue — always
keep a backup, or pin by SPKI / by the intermediate instead.

---

## Fail-closed guarantees

- Empty pin set → throws at construction.
- `PinKind.publicKey` pin without an `spkiExtractor` → throws at construction.
- Null/empty negotiated certificate → rejected.
- SPKI extraction failure → rejected (can't prove a match ⇒ deny).
- Malformed pin string → `PinFormatException` at parse time (no encoding guessing).
- No API to "disable pinning for one request" or turn a
  `CertificatePinningException` into success. **Do not catch that exception to
  retry unpinned** — it defeats the whole thing.

`PinningMode.reportOnly` is the *only* mode that proceeds on mismatch; it runs
over system roots (no pre-send protection) and always fires `onViolation`. Use
it to measure coverage, then switch to `enforce`.

---

## Platform support

| Android | iOS | Linux | macOS | Windows | Web |
|---|---|---|---|---|---|
| yes | yes | yes | yes | yes | no |

It runs wherever `dart:io` does: Flutter apps on the five native platforms,
and Dart command-line and server programs. Web is not supported and cannot
be: the browser makes every TLS connection itself and gives a page no say over
which certificates it trusts.

---

## Coverage boundary

This covers `dart:io`-backed clients (`http`'s `IOClient`, `dio`'s
`IOHttpClientAdapter`, raw `HttpClient`). It does **not** intercept
`package:cronet_http` (Android Cronet) or `package:cupertino_http` (iOS
URLSession) — those need platform-native pinning. It also does not defend a
rooted/jailbroken device with a Frida-hooked TLS stack; pinning raises the bar,
it is not anti-tamper.

---

## License

MPL-2.0, © 2026 Kiritex.

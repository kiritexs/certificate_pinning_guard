import 'dart:io';

import 'package:certificate_pinning_guard/certificate_pinning_guard.dart';

// Only needed if you use PinKind.publicKey (SPKI) pins:
// import 'package:certificate_pinning_guard/spki.dart';

/// Minimal raw-`dart:io` example. See the README for `package:http` and `dio`.
Future<void> main() async {
  // 1) Load your pinned CA / intermediate PEM (bundle it as an asset, or embed
  //    it as a string). This is the trust anchor the handshake is pinned to.
  final anchorPem = File('assets/api_root_ca.pem').readAsBytesSync();

  // 2) Build a client scoped to THIS service. Only certs chaining to your
  //    anchor pass the handshake — a MITM/proxy root fails before any byte is
  //    sent. Use a normal HttpClient for unrelated hosts.
  final client = createPinnedHttpClient(trustedAnchorsPem: anchorPem);

  // 3) (Optional) defense-in-depth: also pin the exact leaf or public key.
  final pinner = CertificatePinner(
    pins: [
      Pin.parse('sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='),
      // Keep a BACKUP pin so certificate rotation never bricks the app:
      Pin.parse('sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB='),
    ],
    onViolation: (v) => stderr.writeln('PIN VIOLATION: $v'),
  );

  try {
    final request = await client.getUrl(
      Uri.parse('https://api.example.com/v1/ping'),
    );
    final response = await request.close();

    // Post-handshake leaf check (throws in enforce mode on mismatch).
    verifyResponseCertificate(pinner, response, host: 'api.example.com');

    stdout.writeln('OK: ${response.statusCode}');
    await response.drain<void>();
  } on CertificatePinningException catch (e) {
    // Do NOT retry unpinned — this is a security failure.
    stderr.writeln('Refused (pin mismatch): $e');
  } finally {
    client.close();
  }
}

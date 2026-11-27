import 'dart:io';

import 'certificate_pinner.dart';

/// Builds a dart:io [HttpClient] whose TLS handshake trusts only the supplied PEM anchor(s).
HttpClient createPinnedHttpClient({
  required List<int> trustedAnchorsPem,
  Duration? connectionTimeout,
}) {
  final context = SecurityContext(withTrustedRoots: false)
    ..setTrustedCertificatesBytes(trustedAnchorsPem);

  final client = HttpClient(context: context);
  client.badCertificateCallback = (cert, host, port) => false;
  if (connectionTimeout != null) client.connectionTimeout = connectionTimeout;
  return client;
}

/// Defense-in-depth: verify the negotiated leaf certificate against [pinner].
void verifyResponseCertificate(
  CertificatePinner pinner,
  HttpClientResponse response, {
  required String host,
}) {
  pinner.verifyCertificate(response.certificate, host: host);
}

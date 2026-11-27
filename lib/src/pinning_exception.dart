/// Thrown when a presented certificate matches none of the configured pins in enforce mode.
class CertificatePinningException implements Exception {
  /// The host whose certificate failed the pin check.
  final String host;

  /// Canonical `sha256/<base64>` pins computed from the presented certificate.
  final List<String> presentedPins;

  /// The canonical pins that were configured for the host.
  final List<String> expectedPins;

  /// What went wrong, for logs. It names the host, never the pins.
  final String message;

  /// A mismatch for [host]; [message] defaults to one naming the host.
  CertificatePinningException(
    this.host, {
    this.presentedPins = const [],
    this.expectedPins = const [],
    String? message,
  }) : message =
           message ??
           'Certificate for "$host" did not match any configured pin.';

  @override
  String toString() => 'CertificatePinningException: $message';
}

/// Thrown at parse time for a malformed pin string.
class PinFormatException implements Exception {
  /// Why the pin string was turned down.
  final String message;

  /// A malformed pin, with the reason in [message].
  PinFormatException(this.message);

  @override
  String toString() => 'PinFormatException: $message';
}

/// Thrown by the SPKI extractor when a certificate's DER cannot be parsed safely.
class SpkiExtractionException implements Exception {
  /// Which part of the certificate's DER could not be read.
  final String message;

  /// A certificate that could not be parsed, with the reason in [message].
  SpkiExtractionException(this.message);

  @override
  String toString() => 'SpkiExtractionException: $message';
}

import 'pinning_mode.dart';

/// A pin-check failure, delivered to `CertificatePinner.onViolation` in both modes.
class PinningViolation {
  /// The host whose certificate failed the check.
  final String host;

  /// Canonical `sha256/<base64>` pins computed from the presented certificate.
  final List<String> presentedPins;

  /// The canonical pins configured for the host.
  final List<String> expectedPins;

  /// The pinner's mode: whether the connection was refused or only reported.
  final PinningMode mode;

  /// A violation for [host]; built by `CertificatePinner`.
  const PinningViolation({
    required this.host,
    required this.presentedPins,
    required this.expectedPins,
    required this.mode,
  });

  @override
  String toString() =>
      'PinningViolation(host: $host, mode: ${mode.name}, '
      'expected: $expectedPins, presented: $presentedPins)';
}

import 'dart:io';
import 'dart:typed_data';

import 'pin.dart';
import 'pinning_exception.dart';
import 'pinning_mode.dart';
import 'pinning_violation.dart';

/// Extracts the DER-encoded `SubjectPublicKeyInfo` from a certificate's DER.
typedef SpkiExtractor = Uint8List Function(List<int> certificateDer);

/// The single source of pinning policy for one logical service.
class CertificatePinner {
  /// The configured pins; a certificate is accepted if it matches any of them.
  final List<Pin> pins;

  /// [PinningMode.enforce] (default) throws on mismatch; reportOnly reports and allows.
  final PinningMode mode;

  /// Called on every mismatch, in both modes, before enforce throws.
  final void Function(PinningViolation violation)? onViolation;

  /// Required if any pin is [PinKind.publicKey].
  final SpkiExtractor? spkiExtractor;

  /// A pinner over [pins]. Throws [ArgumentError] when [pins] is empty, or
  /// when a [PinKind.publicKey] pin comes without a [spkiExtractor].
  CertificatePinner({
    required this.pins,
    this.mode = PinningMode.enforce,
    this.onViolation,
    this.spkiExtractor,
  }) {
    if (pins.isEmpty) {
      throw ArgumentError.value(
        pins,
        'pins',
        'must not be empty — a pinner with no pins is a configuration error',
      );
    }
    if (pins.any((p) => p.kind == PinKind.publicKey) && spkiExtractor == null) {
      throw ArgumentError(
        'A PinKind.publicKey (SPKI) pin requires an spkiExtractor. Import '
        "'package:certificate_pinning_guard/spki.dart' and pass extractSpkiDer.",
      );
    }
  }

  /// Verify a negotiated leaf certificate by its DER bytes.
  bool verifyDer(List<int>? der, {required String host}) {
    if (der == null || der.isEmpty) {
      return _fail(host, der: const []);
    }
    if (_matches(der)) return true;
    return _fail(host, der: der);
  }

  /// Convenience wrapper for a dart:io [X509Certificate] (uses its `.der`).
  bool verifyCertificate(X509Certificate? cert, {required String host}) =>
      verifyDer(cert?.der, host: host);

  bool _matches(List<int> der) {
    Uint8List? certDigest;
    Uint8List? spkiDigest;
    var spkiComputed = false;

    for (final pin in pins) {
      switch (pin.kind) {
        case PinKind.certificate:
          certDigest ??= sha256Bytes(der);
          if (pin.matchesDigest(certDigest)) return true;
        case PinKind.publicKey:
          if (!spkiComputed) {
            spkiComputed = true;
            try {
              spkiDigest = sha256Bytes(spkiExtractor!(der));
            } catch (_) {
              spkiDigest = null;
            }
          }
          if (spkiDigest != null && pin.matchesDigest(spkiDigest)) return true;
      }
    }
    return false;
  }

  Never _throwOrReport(String host, List<String> presented) {
    throw CertificatePinningException(
      host,
      presentedPins: presented,
      expectedPins: pins.map((p) => p.value).toList(),
    );
  }

  bool _fail(String host, {required List<int> der}) {
    final presented = der.isEmpty ? const <String>[] : _presentedPins(der);
    final expected = pins.map((p) => p.value).toList();
    onViolation?.call(
      PinningViolation(
        host: host,
        presentedPins: presented,
        expectedPins: expected,
        mode: mode,
      ),
    );
    if (mode == PinningMode.reportOnly) return true;
    _throwOrReport(host, presented);
  }

  List<String> _presentedPins(List<int> der) {
    final out = <String>[Pin.ofCertificateDer(der).value];
    final ex = spkiExtractor;
    if (ex != null) {
      try {
        out.add(Pin.ofSpkiDer(ex(der)).value);
      } catch (_) {
        // Diagnostic only.
      }
    }
    return out;
  }
}

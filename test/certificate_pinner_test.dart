import 'dart:typed_data';

import 'package:certificate_pinning_guard/certificate_pinning_guard.dart';
import 'package:certificate_pinning_guard/spki.dart';
import 'package:test/test.dart';

import 'support/der.dart';

void main() {
  final der = Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8]);
  final otherDer = Uint8List.fromList([9, 9, 9, 9]);
  final matchingPin = Pin.ofCertificateDer(der);

  group('construction fails closed', () {
    test('empty pin set throws', () {
      expect(
        () => CertificatePinner(pins: const []),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('publicKey pin without an extractor throws', () {
      expect(
        () => CertificatePinner(
          pins: [Pin.parse(matchingPin.value, kind: PinKind.publicKey)],
        ),
        throwsA(isA<ArgumentError>()),
      );
    });
  });

  group('enforce mode', () {
    test('accepts a matching certificate', () {
      final pinner = CertificatePinner(pins: [matchingPin]);
      expect(pinner.verifyDer(der, host: 'api.example.com'), isTrue);
    });

    test('throws on mismatch with useful detail', () {
      final pinner = CertificatePinner(pins: [matchingPin]);
      expect(
        () => pinner.verifyDer(otherDer, host: 'api.example.com'),
        throwsA(
          isA<CertificatePinningException>()
              .having((e) => e.host, 'host', 'api.example.com')
              .having((e) => e.expectedPins, 'expected', [matchingPin.value]),
        ),
      );
    });

    test('null / empty certificate fails closed', () {
      final pinner = CertificatePinner(pins: [matchingPin]);
      expect(
        () => pinner.verifyDer(null, host: 'h'),
        throwsA(isA<CertificatePinningException>()),
      );
      expect(
        () => pinner.verifyDer(const [], host: 'h'),
        throwsA(isA<CertificatePinningException>()),
      );
    });

    test('any-match: a backup pin covers the certificate', () {
      final pinner = CertificatePinner(
        pins: [Pin.ofCertificateDer(otherDer), matchingPin],
      );
      expect(pinner.verifyDer(der, host: 'h'), isTrue);
    });
  });

  group('report-only mode', () {
    test('allows a mismatch but reports it', () {
      PinningViolation? seen;
      final pinner = CertificatePinner(
        pins: [matchingPin],
        mode: PinningMode.reportOnly,
        onViolation: (v) => seen = v,
      );
      expect(pinner.verifyDer(otherDer, host: 'api.example.com'), isTrue);
      expect(seen, isNotNull);
      expect(seen!.mode, PinningMode.reportOnly);
      expect(seen!.host, 'api.example.com');
      expect(seen!.expectedPins, [matchingPin.value]);
      expect(seen!.presentedPins, [Pin.ofCertificateDer(otherDer).value]);
    });
  });

  group('SPKI (public-key) pinning', () {
    test('matches when the SPKI pin matches the certificate key', () {
      final cert = syntheticCertificate(spkiDer: sampleSpki());
      final spkiPin = Pin.ofSpkiDer(extractSpkiDer(cert));
      final pinner = CertificatePinner(
        pins: [Pin.parse(spkiPin.value, kind: PinKind.publicKey)],
        spkiExtractor: extractSpkiDer,
      );
      expect(pinner.verifyDer(cert, host: 'h'), isTrue);
    });

    test('throws when the certificate presents a different key', () {
      final pinnedCert = syntheticCertificate(spkiDer: sampleSpki(0x2A));
      final attackerCert = syntheticCertificate(spkiDer: sampleSpki(0x7F));
      final spkiPin = Pin.ofSpkiDer(extractSpkiDer(pinnedCert));
      final pinner = CertificatePinner(
        pins: [Pin.parse(spkiPin.value, kind: PinKind.publicKey)],
        spkiExtractor: extractSpkiDer,
      );
      expect(
        () => pinner.verifyDer(attackerCert, host: 'h'),
        throwsA(isA<CertificatePinningException>()),
      );
    });

    test('fails closed when SPKI extraction throws', () {
      final spkiPin = Pin.ofSpkiDer(sampleSpki());
      final pinner = CertificatePinner(
        pins: [Pin.parse(spkiPin.value, kind: PinKind.publicKey)],
        spkiExtractor: extractSpkiDer,
      );
      // Not a certificate at all -> extractor throws -> must reject.
      expect(
        () => pinner.verifyDer([0x00, 0x01, 0x02], host: 'h'),
        throwsA(isA<CertificatePinningException>()),
      );
    });
  });
}

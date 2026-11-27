import 'dart:typed_data';

import 'package:certificate_pinning_guard/certificate_pinning_guard.dart';
import 'package:certificate_pinning_guard/spki.dart';
import 'package:test/test.dart';

import 'support/der.dart';

void main() {
  group('extractSpkiDer', () {
    test('extracts the SPKI from a cert WITH a [0] version', () {
      final spki = sampleSpki();
      final cert = syntheticCertificate(spkiDer: spki, withVersion: true);
      expect(extractSpkiDer(cert), spki);
    });

    test('extracts the SPKI from a cert WITHOUT a version element', () {
      final spki = sampleSpki(0x55);
      final cert = syntheticCertificate(spkiDer: spki, withVersion: false);
      expect(extractSpkiDer(cert), spki);
    });

    test('handles a long-form (>127 byte) SPKI', () {
      final big = tlv(0x30, List<int>.filled(200, 0x41)); // 200-byte SEQUENCE
      final cert = syntheticCertificate(spkiDer: big);
      expect(extractSpkiDer(cert), Uint8List.fromList(big));
    });

    test('is stable enough to produce a repeatable pin', () {
      final cert = syntheticCertificate(spkiDer: sampleSpki());
      final a = Pin.ofSpkiDer(extractSpkiDer(cert)).value;
      final b = Pin.ofSpkiDer(extractSpkiDer(cert)).value;
      expect(a, b);
    });
  });

  group('rejects malformed DER (never mis-extracts)', () {
    test('empty input', () {
      expect(
        () => extractSpkiDer(const []),
        throwsA(isA<SpkiExtractionException>()),
      );
    });

    test('truncated certificate', () {
      final cert = syntheticCertificate(spkiDer: sampleSpki());
      final truncated = cert.sublist(0, cert.length - 1);
      expect(
        () => extractSpkiDer(truncated),
        throwsA(isA<SpkiExtractionException>()),
      );
    });

    test('indefinite length is rejected', () {
      // SEQUENCE with indefinite length (0x80) is illegal in DER.
      expect(
        () => extractSpkiDer([0x30, 0x80, 0x00, 0x00]),
        throwsA(isA<SpkiExtractionException>()),
      );
    });

    test('non-minimal long-form length is rejected', () {
      // 0x81 0x01 encodes length 1 in long form (should be short form).
      expect(
        () => extractSpkiDer([0x30, 0x81, 0x01, 0x00]),
        throwsA(isA<SpkiExtractionException>()),
      );
    });

    test('leading-zero long-form length is rejected', () {
      // 0x82 0x00 0xFF has a leading zero byte in the length.
      expect(
        () => extractSpkiDer([0x30, 0x82, 0x00, 0xFF]),
        throwsA(isA<SpkiExtractionException>()),
      );
    });

    test('content that overruns its container is rejected', () {
      // SEQUENCE claims 5 bytes but only 1 follows.
      expect(
        () => extractSpkiDer([0x30, 0x05, 0x00]),
        throwsA(isA<SpkiExtractionException>()),
      );
    });

    test('top-level that is not a SEQUENCE is rejected', () {
      expect(
        () => extractSpkiDer([0x02, 0x01, 0x00]),
        throwsA(isA<SpkiExtractionException>()),
      );
    });
  });
}

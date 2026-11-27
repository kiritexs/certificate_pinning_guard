import 'dart:convert';
import 'dart:typed_data';

import 'package:certificate_pinning_guard/certificate_pinning_guard.dart';
import 'package:test/test.dart';

void main() {
  group('Pin.parse', () {
    final digest = Uint8List.fromList(List<int>.generate(32, (i) => i));
    final validSpec = 'sha256/${base64.encode(digest)}';

    test('parses a valid sha256/<base64> pin and round-trips', () {
      final pin = Pin.parse(validSpec);
      expect(pin.kind, PinKind.certificate);
      expect(pin.bytes, digest);
      expect(pin.value, validSpec);
    });

    test('honours the declared kind', () {
      expect(
        Pin.parse(validSpec, kind: PinKind.publicKey).kind,
        PinKind.publicKey,
      );
    });

    test('rejects a pin without the sha256/ prefix (no encoding guessing)', () {
      expect(
        () => Pin.parse(base64.encode(digest)),
        throwsA(isA<PinFormatException>()),
      );
      expect(
        () => Pin.parse('sha1/${base64.encode(digest)}'),
        throwsA(isA<PinFormatException>()),
      );
    });

    test('rejects a payload that is not 32 bytes', () {
      final short = base64.encode(Uint8List(10));
      expect(
        () => Pin.parse('sha256/$short'),
        throwsA(isA<PinFormatException>()),
      );
    });

    test('rejects invalid base64', () {
      expect(
        () => Pin.parse('sha256/!!!not-base64!!!'),
        throwsA(isA<PinFormatException>()),
      );
    });
  });

  group('matching', () {
    test('ofCertificateDer matches its own digest and rejects others', () {
      final der = Uint8List.fromList([1, 2, 3, 4, 5]);
      final pin = Pin.ofCertificateDer(der);
      expect(pin.matchesDigest(sha256Bytes(der)), isTrue);
      expect(pin.matchesDigest(sha256Bytes([9, 9, 9])), isFalse);
    });

    test('constantTimeBytesEqual is length-safe', () {
      expect(constantTimeBytesEqual([1, 2, 3], [1, 2, 3]), isTrue);
      expect(constantTimeBytesEqual([1, 2, 3], [1, 2, 4]), isFalse);
      expect(constantTimeBytesEqual([1, 2, 3], [1, 2]), isFalse);
      expect(constantTimeBytesEqual(const [], const []), isTrue);
    });
  });

  group('equality', () {
    final der = Uint8List.fromList([10, 20, 30]);
    test('same digest + kind are equal; different kind are not', () {
      expect(Pin.ofCertificateDer(der), equals(Pin.ofCertificateDer(der)));
      expect(
        Pin.parse(Pin.ofCertificateDer(der).value, kind: PinKind.publicKey),
        isNot(equals(Pin.ofCertificateDer(der))),
      );
    });
  });
}

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';

import 'pinning_exception.dart';

/// What a pin's SHA-256 digest is computed over.
enum PinKind {
  /// SHA-256 over the whole DER-encoded certificate (`X509Certificate.der`).
  certificate,

  /// SHA-256 over the DER-encoded `SubjectPublicKeyInfo` (the public key).
  publicKey,
}

/// A single certificate pin: a 32-byte SHA-256 digest plus its [PinKind].
class Pin {
  /// What this pin's digest was computed over.
  final PinKind kind;
  final Uint8List _digest;

  Pin._(this.kind, this._digest)
    : assert(_digest.length == 32, 'digest must be 32 bytes');

  /// Canonical `sha256/<base64>` string form.
  String get value => 'sha256/${base64.encode(_digest)}';

  /// A defensive copy of the raw 32 digest bytes.
  Uint8List get bytes => Uint8List.fromList(_digest);

  /// Parse a pin in the canonical `sha256/<base64>` form.
  factory Pin.parse(String spec, {PinKind kind = PinKind.certificate}) {
    const prefix = 'sha256/';
    if (!spec.startsWith(prefix)) {
      throw PinFormatException(
        'Pin must be in "sha256/<base64>" form (got "${_preview(spec)}").',
      );
    }
    final b64 = spec.substring(prefix.length);
    Uint8List digest;
    try {
      digest = base64.decode(base64.normalize(b64));
    } on FormatException catch (e) {
      throw PinFormatException('Pin payload is not valid base64: ${e.message}');
    }
    if (digest.length != 32) {
      throw PinFormatException(
        'A SHA-256 pin must decode to 32 bytes, got ${digest.length}.',
      );
    }
    return Pin._(kind, digest);
  }

  /// Build a [PinKind.certificate] pin from raw certificate DER bytes.
  factory Pin.ofCertificateDer(List<int> der) =>
      Pin._(PinKind.certificate, sha256Bytes(der));

  /// Build a [PinKind.publicKey] pin from raw SubjectPublicKeyInfo DER bytes.
  factory Pin.ofSpkiDer(List<int> spkiDer) =>
      Pin._(PinKind.publicKey, sha256Bytes(spkiDer));

  /// Constant-time comparison against a raw 32-byte digest.
  bool matchesDigest(List<int> other) => constantTimeBytesEqual(_digest, other);

  @override
  bool operator ==(Object other) =>
      other is Pin &&
      other.kind == kind &&
      constantTimeBytesEqual(_digest, other._digest);

  @override
  int get hashCode => Object.hash(kind, Object.hashAll(_digest));

  @override
  String toString() => '$value (${kind.name})';

  static String _preview(String s) =>
      s.length <= 16 ? s : '${s.substring(0, 16)}…';
}

/// SHA-256 of [data] as raw bytes.
Uint8List sha256Bytes(List<int> data) =>
    Uint8List.fromList(sha256.convert(data).bytes);

/// Length-checked, non-early-exit (constant-time) byte comparison.
bool constantTimeBytesEqual(List<int> a, List<int> b) {
  var diff = a.length ^ b.length;
  final n = a.length < b.length ? a.length : b.length;
  for (var i = 0; i < n; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}

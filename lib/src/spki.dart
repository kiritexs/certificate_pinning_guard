import 'dart:typed_data';

import 'pinning_exception.dart';

/// Extracts the DER-encoded `SubjectPublicKeyInfo` (SPKI) from an X.509 certificate's DER.
Uint8List extractSpkiDer(List<int> certificateDer) {
  final bytes = certificateDer is Uint8List
      ? certificateDer
      : Uint8List.fromList(certificateDer);

  final top = _DerReader(bytes);
  final certificate = top.readTlv();
  if (certificate.tag != _sequence) {
    throw SpkiExtractionException('Certificate is not a SEQUENCE.');
  }

  final certInner = _DerReader(
    bytes,
    certificate.contentStart,
    certificate.end,
  );
  final tbs = certInner.readTlv();
  if (tbs.tag != _sequence) {
    throw SpkiExtractionException('tbsCertificate is not a SEQUENCE.');
  }

  final tbsInner = _DerReader(bytes, tbs.contentStart, tbs.end);
  var field = tbsInner.readTlv();

  if (field.tag == _contextExplicit0) {
    field = tbsInner.readTlv();
  }
  for (var i = 0; i < 4; i++) {
    tbsInner.readTlv();
  }
  final spki = tbsInner.readTlv();
  if (spki.tag != _sequence) {
    throw SpkiExtractionException('subjectPublicKeyInfo is not a SEQUENCE.');
  }
  return Uint8List.sublistView(bytes, spki.headerStart, spki.end);
}

const int _sequence = 0x30;
const int _contextExplicit0 = 0xA0;

class _Tlv {
  final int tag;
  final int headerStart;
  final int contentStart;
  final int end;

  _Tlv(this.tag, this.headerStart, this.contentStart, this.end);
}

class _DerReader {
  final Uint8List _buf;
  final int _limit;
  int _pos;

  _DerReader(this._buf, [int start = 0, int? end])
    : _pos = start,
      _limit = end ?? _buf.length;

  _Tlv readTlv() {
    final headerStart = _pos;
    if (_pos >= _limit) {
      throw SpkiExtractionException('Unexpected end of data reading tag.');
    }
    final tag = _buf[_pos++];

    if (_pos >= _limit) {
      throw SpkiExtractionException('Unexpected end of data reading length.');
    }
    final first = _buf[_pos++];
    int length;
    if (first < 0x80) {
      length = first;
    } else if (first == 0x80) {
      throw SpkiExtractionException('Indefinite length is not valid DER.');
    } else {
      final numBytes = first & 0x7f;
      if (numBytes > 4) {
        throw SpkiExtractionException(
          'Length field too large ($numBytes bytes).',
        );
      }
      if (_pos + numBytes > _limit) {
        throw SpkiExtractionException('Truncated long-form length.');
      }
      if (_buf[_pos] == 0x00) {
        throw SpkiExtractionException(
          'Non-minimal length (leading zero byte).',
        );
      }
      var value = 0;
      for (var i = 0; i < numBytes; i++) {
        value = (value << 8) | _buf[_pos++];
      }
      if (value < 0x80) {
        throw SpkiExtractionException(
          'Non-minimal length (should be short form).',
        );
      }
      length = value;
    }

    final contentStart = _pos;
    final end = contentStart + length;
    if (end > _limit || end < contentStart) {
      throw SpkiExtractionException('Content overruns its container.');
    }
    _pos = end;
    return _Tlv(tag, headerStart, contentStart, end);
  }
}

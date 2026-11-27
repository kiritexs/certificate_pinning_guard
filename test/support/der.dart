import 'dart:typed_data';

/// Encode a DER TLV with minimal-length rules (short form < 128, else long
/// form). Test-only helper for building structurally-valid certificate bytes
/// without needing openssl or a real cert.
List<int> tlv(int tag, List<int> content) {
  final out = <int>[tag];
  final len = content.length;
  if (len < 0x80) {
    out.add(len);
  } else {
    final lenBytes = <int>[];
    var v = len;
    while (v > 0) {
      lenBytes.insert(0, v & 0xff);
      v >>= 8;
    }
    out.add(0x80 | lenBytes.length);
    out.addAll(lenBytes);
  }
  out.addAll(content);
  return out;
}

/// A sample `SubjectPublicKeyInfo` SEQUENCE. Content is arbitrary — only the
/// TLV framing matters for extraction. Vary [marker] to get a distinct SPKI.
Uint8List sampleSpki([int marker = 0x2A]) =>
    Uint8List.fromList(tlv(0x30, [0x02, 0x01, marker]));

/// Build a minimal but structurally-valid X.509 certificate DER that wraps
/// [spkiDer] in the subjectPublicKeyInfo position.
Uint8List syntheticCertificate({
  required List<int> spkiDer,
  bool withVersion = true,
}) {
  final tbsFields = <int>[
    if (withVersion) ...tlv(0xA0, [0x02, 0x01, 0x02]), // [0] version v3
    0x02, 0x01, 0x01, // serialNumber INTEGER 1
    ...tlv(0x30, const []), // signature AlgorithmIdentifier
    ...tlv(0x30, const []), // issuer Name
    ...tlv(0x30, const []), // validity
    ...tlv(0x30, const []), // subject Name
    ...spkiDer, // subjectPublicKeyInfo
  ];
  final tbs = tlv(0x30, tbsFields);
  final cert = tlv(0x30, [
    ...tbs,
    ...tlv(0x30, const []), // signatureAlgorithm
    0x03, 0x01, 0x00, // signatureValue BIT STRING
  ]);
  return Uint8List.fromList(cert);
}

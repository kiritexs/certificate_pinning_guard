/// Optional SPKI (public-key) pinning support.
///
/// Import this ONLY when you use [PinKind.publicKey] pins, then pass
/// [extractSpkiDer] as the `spkiExtractor` of your [CertificatePinner]:
///
/// ```dart
/// import 'package:certificate_pinning_guard/certificate_pinning_guard.dart';
/// import 'package:certificate_pinning_guard/spki.dart';
///
/// final pinner = CertificatePinner(
///   pins: [Pin.parse('sha256/AAAA...', kind: PinKind.publicKey)],
///   spkiExtractor: extractSpkiDer,
/// );
/// ```
library;

export 'src/spki.dart' show extractSpkiDer;

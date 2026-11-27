/// How a pin mismatch is handled.
enum PinningMode {
  /// A mismatch throws [CertificatePinningException] and the connection fails.
  enforce,

  /// A mismatch is reported via `onViolation` but the connection is allowed to proceed.
  reportOnly,
}

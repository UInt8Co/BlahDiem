import DiemSwiftCrypto

extension SoftwareDeviceCrypto {
  public func makeDevice(
    signing: KeyAlgorithm = .ed25519,
    wrapping: KeyAlgorithm = .x25519
  ) throws -> DeviceSigner {
    try DeviceSigner(
      signingKey: SoftwareSigningKey(algorithm: signing),
      wrappingKey: SoftwareWrappingKey(algorithm: wrapping))
  }
}

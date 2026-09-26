import DiemSwiftCrypto

extension DeviceSigner {
  public func sign(
    _ payload: [UInt8], purpose: DeviceProofPurpose, profile: SignedProfile,
    at now: UInt64, using crypto: any DeviceCrypto
  ) throws -> DeviceProof {
    let body = CBOR.array([
      .textString("Diem/device-proof"), .unsignedInt(2),
      .textString(purpose.rawValue), bytes(profile.id),
      bytes(signingKey.publicKey.id(using: crypto)),
      bytes(profile.digest(using: crypto)), bytes(payload),
    ])
    let encoded = try CanonicalCBOR.encode(body)
    let proof = try DeviceProof(
      payloadBytes: encoded, signature: signingKey.signature(for: encoded))
    try proof.verify(purpose: purpose, profile: profile, at: now, using: crypto)
    return proof
  }
}

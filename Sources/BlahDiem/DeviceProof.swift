public enum DeviceProofPurpose: String, Sendable, CaseIterable {
  case login, action, message, checkpoint
}

/// Credential-free generic signature container; applications own the payload contract.
/// Profiles and rosters have separate formats and cannot be used as these proofs.
public struct DeviceProof: Sendable {
  public let payloadBytes: [UInt8]
  public let signature: [UInt8]
  public let purpose: DeviceProofPurpose
  public let identityID: [UInt8]
  public let deviceID: [UInt8]
  public let profileDigest: [UInt8]
  public let payload: [UInt8]

  public init(payloadBytes: [UInt8], signature: [UInt8]) throws {
    let a = try CanonicalCBOR.array(payloadBytes, count: 7)
    guard try string(a[0]) == "Diem/device-proof", try uint(a[1]) == 2,
      let purpose = try DeviceProofPurpose(rawValue: string(a[2]))
    else { throw DiemError.invalidCBOR }
    self.purpose = purpose
    self.identityID = try octets(a[3], count: 32)
    self.deviceID = try octets(a[4], count: 32)
    self.profileDigest = try octets(a[5], count: 32)
    self.payload = try octets(a[6])
    self.payloadBytes = payloadBytes
    self.signature = signature
  }
  public var encoding: [UInt8] { CBOR.array([bytes(payloadBytes), bytes(signature)]).encode() }
  public static func decode(_ encoded: [UInt8]) throws -> Self {
    let a = try CanonicalCBOR.array(encoded, count: 2)
    return try Self(payloadBytes: octets(a[0]), signature: octets(a[1]))
  }
  public func verify(
    purpose expectedPurpose: DeviceProofPurpose, profile: SignedProfile,
    at now: UInt64, using crypto: some DeviceCrypto
  ) throws {
    try profile.verify(at: now, using: crypto)
    guard purpose == expectedPurpose else { throw DeviceIdentityError.roleConfusion }
    guard identityID == profile.id, profileDigest == profile.digest(using: crypto) else {
      throw DeviceIdentityError.identityMismatch
    }
    guard
      let device = profile.deviceList.body.devices.first(where: { $0.id(using: crypto) == deviceID }
      )
    else {
      throw DeviceIdentityError.deviceNotListed
    }
    guard try crypto.verify(signature, message: payloadBytes, key: device.signingKey) else {
      throw DeviceIdentityError.invalidSignature
    }
  }
}

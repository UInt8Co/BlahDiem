import DiemSwiftCrypto

/// A local device can update a profile without a controller envelope.
public struct DeviceSigner: Sendable {
  public let signingKey: any DeviceSigningKey
  public let wrappingKey: any DeviceWrappingKey
  public init(signingKey: any DeviceSigningKey, wrappingKey: any DeviceWrappingKey) throws {
    guard signingKey.publicKey.algorithm.isSigning, !wrappingKey.publicKey.algorithm.isSigning
    else {
      throw DeviceIdentityError.roleConfusion
    }
    self.signingKey = signingKey
    self.wrappingKey = wrappingKey
  }
  public func entry(identityController: Bool = false) throws -> DeviceEntry {
    try DeviceEntry(
      signingKey: signingKey.publicKey, wrappingKey: wrappingKey.publicKey,
      identityController: identityController)
  }
  public func signProfile(
    identityKey: DevicePublicKey, deviceList: SignedDeviceList,
    revision: UInt64, previousDigest: [UInt8], validity: AuthorityValidity,
    fields: CBOR, at now: UInt64, using crypto: any DeviceCrypto
  ) throws -> SignedProfile {
    let body = try DeviceProfileBody(
      identityID: identityKey.id(using: crypto),
      deviceListDigest: deviceList.digest(using: crypto), revision: revision,
      previousDigest: previousDigest, validity: validity,
      signerDeviceID: signingKey.publicKey.id(using: crypto), fields: fields)
    let result = try SignedProfile(
      identityKey: identityKey, deviceList: deviceList,
      payloadBytes: body.encoding, signature: signingKey.signature(for: body.encoding))
    try result.verify(at: now, using: crypto)
    return result
  }
}

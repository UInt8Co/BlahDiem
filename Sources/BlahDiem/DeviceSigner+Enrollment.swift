import DiemSwiftCrypto

extension DeviceSigner {
  public func enrollmentRequest(
    identityID: [UInt8], at now: UInt64,
    using crypto: any DeviceCrypto
  ) throws -> DeviceEnrollmentRequest {
    guard now <= UInt64.max - 600 else { throw DeviceIdentityError.invalidValidity }
    let request = try DeviceEnrollmentRequest(
      identityID: identityID, device: entry(),
      nonce: crypto.randomBytes(count: 32), validity: .init(notBefore: now, expiresAt: now + 600),
      signature: [])
    return DeviceEnrollmentRequest(
      identityID: request.identityID, device: request.device,
      nonce: request.nonce, validity: request.validity,
      signature: try signingKey.signature(for: request.payloadBytes))
  }
  public func confirmEnrollment(
    _ pending: PendingDeviceEnrollment, at now: UInt64,
    using crypto: any DeviceCrypto
  ) throws -> EnrollmentConfirmation {
    try pending.request.verify(at: now, using: crypto)
    guard pending.request.device == (try entry()) else {
      throw DeviceIdentityError.invalidEnrollment
    }
    let secret = try wrappingKey.open(pending.challenge, context: pending.requestDigest)
    let response = EnrollmentConfirmation(
      requestDigest: pending.requestDigest, secret: secret, signature: [])
    return EnrollmentConfirmation(
      requestDigest: response.requestDigest, secret: secret,
      signature: try signingKey.signature(for: response.payloadBytes))
  }
}

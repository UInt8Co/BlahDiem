public struct DeviceEnrollmentRequest: Sendable {
  public let identityID: [UInt8]
  public let device: DeviceEntry
  public let nonce: [UInt8]
  public let validity: AuthorityValidity
  public let signature: [UInt8]

  package init(
    identityID: [UInt8], device: DeviceEntry, nonce: [UInt8],
    validity: AuthorityValidity, signature: [UInt8]
  ) {
    self.identityID = identityID
    self.device = device
    self.nonce = nonce
    self.validity = validity
    self.signature = signature
  }

  public var payloadBytes: [UInt8] {
    CBOR.array([
      .textString("Diem/enrollment"), .unsignedInt(2), bytes(identityID),
      device.cbor, bytes(nonce), .unsignedInt(validity.notBefore),
      .unsignedInt(validity.expiresAt),
    ]).encode()
  }
  public var encoding: [UInt8] { CBOR.array([bytes(payloadBytes), bytes(signature)]).encode() }
  public func digest(using crypto: some DeviceCrypto) -> [UInt8] { crypto.sha256(payloadBytes) }
  public func verify(at now: UInt64, using crypto: some DeviceCrypto) throws {
    guard identityID.count == 32, nonce.count == 32, !device.identityController else {
      throw DeviceIdentityError.invalidEnrollment
    }
    try validity.validate(at: now, maximumLifetime: 600)
    guard try crypto.verify(signature, message: payloadBytes, key: device.signingKey) else {
      throw DeviceIdentityError.invalidSignature
    }
  }
  public static func decode(_ encoded: [UInt8]) throws -> Self {
    let a = try CanonicalCBOR.array(encoded, count: 2)
    let p = try CanonicalCBOR.array(octets(a[0]), count: 7)
    guard try string(p[0]) == "Diem/enrollment", try uint(p[1]) == 2 else {
      throw DiemError.invalidCBOR
    }
    return try Self(
      identityID: octets(p[2]), device: .init(cbor: p[3]), nonce: octets(p[4]),
      validity: .init(notBefore: uint(p[5]), expiresAt: uint(p[6])), signature: octets(a[1]))
  }
}

/// Contains the wrapping proof challenge, not an identity key. The caller must
/// compare requestDigest with the QR/authenticated-channel transcript before approval.
public struct PendingDeviceEnrollment: Sendable {
  public let request: DeviceEnrollmentRequest
  public let challenge: WrappedSecret
  public let challengeDigest: [UInt8]
  public let requestDigest: [UInt8]

  public init(
    request: DeviceEnrollmentRequest, confirmedPairingDigest: [UInt8],
    at now: UInt64, using crypto: some DeviceCrypto
  ) throws {
    try request.verify(at: now, using: crypto)
    let digest = request.digest(using: crypto)
    guard digest == confirmedPairingDigest else { throw DeviceIdentityError.pairingNotConfirmed }
    let secret = crypto.randomBytes(count: 32)
    self.challenge = try crypto.seal(secret, to: request.device.wrappingKey, context: digest)
    self.challengeDigest = crypto.sha256(secret)
    self.request = request
    self.requestDigest = digest
  }

  public func confirm(
    _ response: EnrollmentConfirmation, at now: UInt64,
    using crypto: some DeviceCrypto
  ) throws -> DeviceEntry {
    try request.verify(at: now, using: crypto)
    guard response.requestDigest == requestDigest,
      response.secret.count == 32, crypto.sha256(response.secret) == challengeDigest,
      try crypto.verify(
        response.signature, message: response.payloadBytes,
        key: request.device.signingKey)
    else { throw DeviceIdentityError.invalidEnrollment }
    return request.device
  }
}

public struct EnrollmentConfirmation: Sendable {
  public let requestDigest: [UInt8]
  public let secret: [UInt8]
  public let signature: [UInt8]
  package init(requestDigest: [UInt8], secret: [UInt8], signature: [UInt8]) {
    self.requestDigest = requestDigest
    self.secret = secret
    self.signature = signature
  }
  public var payloadBytes: [UInt8] {
    CBOR.array([
      .textString("Diem/enrollment-confirm"), .unsignedInt(2),
      bytes(requestDigest), bytes(secret),
    ]).encode()
  }
  public var encoding: [UInt8] { CBOR.array([bytes(payloadBytes), bytes(signature)]).encode() }
  public static func decode(_ encoded: [UInt8]) throws -> Self {
    let a = try CanonicalCBOR.array(encoded, count: 2)
    let p = try CanonicalCBOR.array(octets(a[0]), count: 4)
    guard try string(p[0]) == "Diem/enrollment-confirm", try uint(p[1]) == 2 else {
      throw DiemError.invalidCBOR
    }
    return try Self(
      requestDigest: octets(p[2], count: 32), secret: octets(p[3], count: 32),
      signature: octets(a[1]))
  }
}

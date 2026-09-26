import Foundation

/// Both endpoints authenticate the exact live encrypted session with devices
/// listed by their operator-pinned DC identities. DC numbers never appear in
/// the transcript.
public struct BIDCOMFederationBind: Sendable, Equatable {
  public let source: FederationDestination
  public let destination: FederationDestination
  public let authKeyID: Int64
  public let sessionID: Int64
  public let nonce: [UInt8]

  public init(
    source: FederationDestination, destination: FederationDestination,
    authKeyID: Int64, sessionID: Int64, nonce: [UInt8]
  ) throws {
    guard source.keyID != destination.keyID, authKeyID != 0, sessionID != 0, nonce.count == 32
    else { throw FederationError.invalidChallenge }
    self.source = source
    self.destination = destination
    self.authKeyID = authKeyID
    self.sessionID = sessionID
    self.nonce = nonce
  }

  public var encoding: [UInt8] {
    CBOR.array([
      .unsignedInt(BlahDiemTag.bidcomBind.rawValue), .unsignedInt(3),
      .textString(source.domain), .byteString(source.keyID[...]),
      .textString(destination.domain), .byteString(destination.keyID[...]),
      .unsignedInt(UInt64(bitPattern: authKeyID)), .unsignedInt(UInt64(bitPattern: sessionID)),
      .byteString(nonce[...]),
    ]).encode()
  }

  public func signed(by identity: FederationIdentity) throws -> Data {
    guard identity.destination == source else { throw FederationError.wrongHome }
    return try Self.proof(payload: encoding, signer: identity)
  }

  /// Decoding is not authentication. Look up the asserted source's admitted DC
  /// profile, then verify with its listed device and the actual session binding.
  public static func read(_ proof: Data) throws -> Self {
    let (payload, _) = try unpack(proof)
    let a = try CanonicalCBOR.array(payload, count: 9)
    guard a[0] == .unsignedInt(BlahDiemTag.bidcomBind.rawValue), a[1] == .unsignedInt(3),
      case .textString(let source) = a[2], case .byteString(let fromKey) = a[3],
      case .textString(let target) = a[4], case .byteString(let toKey) = a[5],
      case .unsignedInt(let auth) = a[6], case .unsignedInt(let session) = a[7],
      case .byteString(let nonce) = a[8]
    else { throw FederationError.invalidChallenge }
    return try .init(
      source: .init(domain: source, keyID: Array(fromKey)),
      destination: .init(domain: target, keyID: Array(toKey)), authKeyID: Int64(bitPattern: auth),
      sessionID: Int64(bitPattern: session), nonce: Array(nonce))
  }

  public func verify(
    _ proof: Data, sourceKey: DevicePublicKey,
    destination expected: FederationDestination, authKeyID expectedKey: Int64,
    sessionID expectedSession: Int64
  ) throws {
    let crypto = SoftwareDeviceCrypto()
    guard destination == expected, authKeyID == expectedKey, sessionID == expectedSession
    else { throw FederationError.invalidChallenge }
    let (payload, signature) = try Self.unpack(proof)
    guard payload == encoding else { throw FederationError.invalidChallenge }
    guard try crypto.verify(signature, message: payload, key: sourceKey)
    else { throw FederationError.invalidChallenge }
  }

  private var acceptance: BIDCOMFederationAcceptance { .init(bind: self) }

  public func accepted(by identity: FederationIdentity) throws -> Data {
    guard identity.destination == destination else { throw FederationError.wrongHome }
    return try Self.proof(payload: acceptance.encoding, signer: identity)
  }

  public func verifyAcceptance(_ proof: Data, destinationKey: DevicePublicKey) throws {
    let crypto = SoftwareDeviceCrypto()
    let (payload, signature) = try Self.unpack(proof)
    guard try BIDCOMFederationAcceptance.decode(payload) == acceptance else {
      throw FederationError.invalidChallenge
    }
    guard try crypto.verify(signature, message: payload, key: destinationKey)
    else { throw FederationError.invalidChallenge }
  }

  private static func proof(payload: [UInt8], signer: FederationIdentity) throws -> Data {
    Data(
      try CBOR.array([
        .byteString(payload[...]),
        .byteString(signer.device.signingKey.signature(for: payload)[...]),
      ]).encode())
  }

  private static func unpack(_ data: Data) throws -> ([UInt8], [UInt8]) {
    guard data.count <= 4096 else { throw FederationError.invalidChallenge }
    let a = try CanonicalCBOR.array(Array(data), count: 2)
    guard case .byteString(let payload) = a[0], case .byteString(let signature) = a[1],
      payload.count <= 2048, signature.count <= 144
    else { throw FederationError.invalidChallenge }
    return (Array(payload), Array(signature))
  }
}

/// The destination's signed response binds the exact source transcript.
public struct BIDCOMFederationAcceptance: Sendable, Equatable {
  public let bindDigest: [UInt8]

  public init(bind: BIDCOMFederationBind) {
    bindDigest = SoftwareDeviceCrypto().sha256(bind.encoding)
  }

  private init(bindDigest: [UInt8]) { self.bindDigest = bindDigest }

  public var encoding: [UInt8] {
    CBOR.array([
      .unsignedInt(BlahDiemTag.bidcomAccept.rawValue), .unsignedInt(1),
      .byteString(bindDigest[...]),
    ]).encode()
  }

  public static func decode(_ bytes: [UInt8]) throws -> Self {
    let fields = try CanonicalCBOR.array(bytes, count: 3)
    guard fields[0] == .unsignedInt(BlahDiemTag.bidcomAccept.rawValue),
      fields[1] == .unsignedInt(1), case .byteString(let digest) = fields[2], digest.count == 32
    else { throw FederationError.invalidChallenge }
    return Self(bindDigest: Array(digest))
  }
}

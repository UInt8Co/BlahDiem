import Crypto
import Foundation

/// A short-lived, single-use request challenge. The domain is the address from
/// which the verifier must fetch the identity's current public profile.
public struct IdentityInvocationChallenge: Sendable, Equatable {
  public let domain: String
  public let nonce: [UInt8]
  public let expiresAt: UInt64
  public let destinationID: [UInt8]
  public let transportKeyID: Int64
  public let sessionID: UInt64

  public init(
    domain: String, nonce: [UInt8], expiresAt: UInt64, destinationID: [UInt8],
    transportKeyID: Int64, sessionID: UInt64
  ) throws {
    guard DomainName.isValid(domain), nonce.count == 32, destinationID.count == 32,
      expiresAt <= UInt64(Int64.max), transportKeyID != 0, sessionID != 0
    else { throw FederationError.invalidChallenge }
    self.domain = domain
    self.nonce = nonce
    self.expiresAt = expiresAt
    self.destinationID = destinationID
    self.transportKeyID = transportKeyID
    self.sessionID = sessionID
  }

  public var encoding: [UInt8] {
    CBOR.array([
      .unsignedInt(BlahDiemTag.identityChallenge.rawValue), .unsignedInt(1), .textString(domain),
      .byteString(nonce[...]), .unsignedInt(expiresAt),
      .byteString(destinationID[...]), .unsignedInt(UInt64(bitPattern: transportKeyID)),
      .unsignedInt(sessionID),
    ]).encode()
  }

  public static func decode(_ bytes: [UInt8]) throws -> Self {
    let a = try CanonicalCBOR.array(bytes, count: 8)
    guard a[0] == .unsignedInt(BlahDiemTag.identityChallenge.rawValue), a[1] == .unsignedInt(1),
      case .textString(let domain) = a[2], case .byteString(let nonce) = a[3],
      case .unsignedInt(let expiry) = a[4], case .byteString(let destination) = a[5],
      case .unsignedInt(let key) = a[6], case .unsignedInt(let session) = a[7]
    else { throw FederationError.invalidChallenge }
    return try .init(
      domain: domain, nonce: Array(nonce), expiresAt: expiry,
      destinationID: Array(destination), transportKeyID: Int64(bitPattern: key),
      sessionID: session)
  }
}

/// The Diem signed message's content for one exact wrapped MTProto payload.
/// The hash name is signed beside its digest so future algorithms cannot be
/// confused with SHA-512. `challenge` is opaque to the client.
public struct IdentityInvocationStatement: Sendable, Equatable {
  public let challenge: [UInt8]
  public let payloadDigest: [UInt8]

  public init(challenge: [UInt8], wrappedPayload: [UInt8]) {
    self.challenge = challenge
    self.payloadDigest = Array(SHA512.hash(data: wrappedPayload))
  }

  private init(challenge: [UInt8], payloadDigest: [UInt8]) {
    self.challenge = challenge
    self.payloadDigest = payloadDigest
  }

  public var encoding: [UInt8] {
    CBOR.array([
      .unsignedInt(BlahDiemTag.identityInvocation.rawValue), .unsignedInt(1),
      .byteString(challenge[...]), .unsignedInt(1),
      .byteString(payloadDigest[...]),
    ]).encode()
  }

  public static func decode(_ bytes: [UInt8]) throws -> Self {
    let a = try CanonicalCBOR.array(bytes, count: 5)
    guard a[0] == .unsignedInt(BlahDiemTag.identityInvocation.rawValue), a[1] == .unsignedInt(1),
      case .byteString(let challenge) = a[2], a[3] == .unsignedInt(1),
      case .byteString(let digest) = a[4], digest.count == 64,
      challenge.count <= CanonicalCBOR.maximumBytes
    else { throw FederationError.invalidChallenge }
    return Self(challenge: Array(challenge), payloadDigest: Array(digest))
  }

  public func matches(_ wrappedPayload: [UInt8]) -> Bool {
    payloadDigest == Array(SHA512.hash(data: wrappedPayload))
  }
}

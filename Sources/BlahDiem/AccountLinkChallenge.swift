/// A device approves each private read or change of an external-account link.
/// Confirmation names the provider-verified account and the binding it replaces.
public struct AccountLinkChallenge: Sendable {
  public enum Operation: String, Sendable { case read, start, confirm, unlink }
  public let destination: FederationDestination
  public let nonce: [UInt8]
  public let expiresAt: UInt64
  public let operation: Operation
  public let identityID: [UInt8]
  public let requestID: [UInt8]
  public let externalID: String
  public let previousExternalID: String
  public let label: String

  public init(
    destination: FederationDestination, nonce: [UInt8], expiresAt: UInt64,
    operation: Operation, identityID: [UInt8] = [], requestID: [UInt8] = [],
    externalID: String = "", previousExternalID: String = "", label: String = ""
  ) throws {
    func validID(_ string: String) -> Bool {
      if string.isEmpty { return true }
      guard let value = Int64(string), value > 0 else { return false }
      return String(value) == string
    }
    guard nonce.count == 32, expiresAt <= UInt64(Int64.max), label.utf8.count <= 256,
      validID(externalID), validID(previousExternalID)
    else { throw FederationError.invalidChallenge }
    switch operation {
    case .read:
      guard identityID.isEmpty, requestID.isEmpty, externalID.isEmpty,
        previousExternalID.isEmpty, label.isEmpty
      else { throw FederationError.invalidChallenge }
    case .start:
      guard identityID.isEmpty, requestID.isEmpty, externalID.isEmpty, label.isEmpty else {
        throw FederationError.invalidChallenge
      }
    case .unlink:
      guard identityID.isEmpty, requestID.isEmpty, !externalID.isEmpty,
        previousExternalID.isEmpty, label.isEmpty
      else { throw FederationError.invalidChallenge }
    case .confirm:
      guard identityID.count == 32, requestID.count == 32, !externalID.isEmpty else {
        throw FederationError.invalidChallenge
      }
    }
    self.destination = destination
    self.nonce = nonce
    self.expiresAt = expiresAt
    self.operation = operation
    self.identityID = identityID
    self.requestID = requestID
    self.externalID = externalID
    self.previousExternalID = previousExternalID
    self.label = label
  }
  public var encoding: [UInt8] {
    CBOR.array([
      .unsignedInt(BlahDiemTag.accountLink.rawValue), .unsignedInt(1), .textString(destination.domain),
      .byteString(destination.keyID[...]), .byteString(nonce[...]), .unsignedInt(expiresAt),
      .unsignedInt(operation.wireCode), .unsignedInt(1), .byteString(identityID[...]),
      .byteString(requestID[...]), .textString(externalID), .textString(previousExternalID),
      .textString(label),
    ]).encode()
  }
  public static func decode(_ bytes: [UInt8]) throws -> Self {
    let a = try CanonicalCBOR.array(bytes, count: 13)
    guard a[0] == .unsignedInt(BlahDiemTag.accountLink.rawValue), a[1] == .unsignedInt(1),
      case .textString(let domain) = a[2], case .byteString(let key) = a[3],
      case .byteString(let nonce) = a[4], case .unsignedInt(let expiry) = a[5],
      case .unsignedInt(let op) = a[6], let operation = Operation(wireCode: op),
      a[7] == .unsignedInt(1), case .byteString(let identity) = a[8],
      case .byteString(let request) = a[9], case .textString(let external) = a[10],
      case .textString(let previous) = a[11], case .textString(let label) = a[12]
    else { throw FederationError.invalidChallenge }
    return try .init(
      destination: .init(domain: domain, keyID: Array(key)), nonce: Array(nonce),
      expiresAt: expiry, operation: operation, identityID: Array(identity),
      requestID: Array(request),
      externalID: external, previousExternalID: previous, label: label)
  }

  public func approve(device: DeviceSigner, profile: SignedProfile, reviewed: Self, at now: UInt64)
    throws -> DeviceProof
  {
    guard encoding == reviewed.encoding, expiresAt > now, expiresAt - now <= 120,
      identityID.isEmpty || identityID == profile.id
    else { throw FederationError.invalidChallenge }
    try HomeDelegation(profile: profile, at: now).requireHome(destination)
    return try device.sign(
      encoding, purpose: .action, profile: profile, at: now, using: SoftwareDeviceCrypto())
  }
}

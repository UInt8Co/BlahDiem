/// A one-use device approval for the exact DC administration request. This is
/// an application action, never a human-login credential or an identity-key use.
public struct DCAdminChallenge: Sendable {
  /// `linkBot` asks a bot's owner to let it speak for an application; its
  /// document names the app and the bot, and approving it grants nothing yet.
  public enum Operation: String, Sendable { case read, replace, linkBot }
  public let destination: FederationDestination
  public let nonce: [UInt8]
  public let expiresAt: UInt64
  public let operation: Operation
  public let revision: UInt64
  public let document: [UInt8]

  public init(
    destination: FederationDestination, nonce: [UInt8], expiresAt: UInt64,
    operation: Operation, revision: UInt64, document: [UInt8]
  ) throws {
    guard nonce.count == 32, expiresAt <= UInt64(Int64.max), revision < UInt64(Int64.max),
      document.count <= 131072, operation != .read || (document.isEmpty && revision == 0),
      operation != .replace || (revision > 0 && !document.isEmpty),
      operation != .linkBot || (revision == 0 && !document.isEmpty)
    else { throw FederationError.invalidChallenge }
    self.destination = destination
    self.nonce = nonce
    self.expiresAt = expiresAt
    self.operation = operation
    self.revision = revision
    self.document = document
  }
  public var encoding: [UInt8] {
    CBOR.array([
      .unsignedInt(BlahDiemTag.dcAdmin.rawValue), .unsignedInt(1), .textString(destination.domain),
      .byteString(destination.keyID[...]), .byteString(nonce[...]), .unsignedInt(expiresAt),
      .unsignedInt(operation.wireCode), .unsignedInt(revision), .byteString(document[...]),
    ]).encode()
  }
  public static func decode(_ bytes: [UInt8]) throws -> Self {
    let a = try CanonicalCBOR.array(bytes, count: 9)
    guard a[0] == .unsignedInt(BlahDiemTag.dcAdmin.rawValue), a[1] == .unsignedInt(1),
      case .textString(let domain) = a[2], case .byteString(let key) = a[3],
      case .byteString(let nonce) = a[4], case .unsignedInt(let expiry) = a[5],
      case .unsignedInt(let op) = a[6], let operation = Operation(wireCode: op),
      case .unsignedInt(let revision) = a[7], case .byteString(let document) = a[8]
    else { throw FederationError.invalidChallenge }
    return try .init(
      destination: .init(domain: domain, keyID: Array(key)), nonce: Array(nonce),
      expiresAt: expiry, operation: operation, revision: revision, document: Array(document))
  }

  /// The application presents the document for approval before calling this.
  /// Requiring the expected values prevents a relay from substituting an action.
  public func approve(
    device: DeviceSigner, profile: SignedProfile, destination expected: FederationDestination,
    operation expectedOperation: Operation, revision expectedRevision: UInt64,
    document expectedDocument: [UInt8], at now: UInt64
  ) throws -> DeviceProof {
    guard destination == expected, operation == expectedOperation, revision == expectedRevision,
      document == expectedDocument, expiresAt > now, expiresAt - now <= 120
    else { throw FederationError.invalidChallenge }
    try HomeDelegation(profile: profile, at: now).requireHome(expected)
    return try device.sign(
      encoding, purpose: .action, profile: profile, at: now,
      using: SoftwareDeviceCrypto())
  }
}

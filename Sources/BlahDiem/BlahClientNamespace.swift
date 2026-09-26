import Foundation

public enum BlahClientLeaseError: Error, Equatable, Sendable {
  case invalidNamespace, wrongNamespace, wrongDevice, invalidIncarnation, retired, wrongScope
  case leaseInUse
}

/// The canonical cache boundary. Endpoint/RSA rotation and profile renewal do
/// not change it; a different account, home, database generation or home epoch does.
public struct BlahClientNamespace: Equatable, Sendable {
  public let identityID: [UInt8]
  public let destination: FederationDestination
  public let publicKey: DevicePublicKey
  public let generation: UInt64
  public let homeEpoch: UInt64
  public let encoding: [UInt8]
  public var identifier: String { Self.hex(SoftwareDeviceCrypto().sha256(encoding)) }

  /// Bootstrap trust belongs to the application. In particular, generation is
  /// pinned before opening storage, never learned from an unverified response.
  public init(profile: SignedProfile, bootstrap: KnownDCConfiguration,
    at now: UInt64 = UInt64(Date().timeIntervalSince1970)) throws {
    let crypto = SoftwareDeviceCrypto()
    try profile.verify(at: now, using: crypto)
    let destination = try bootstrap.validatedDestination()
    let home = try HomeDelegation(profile: profile, at: now)
    try home.requireHome(destination)
    guard let text = bootstrap.namespaceVersion, let generation = UInt64(text),
      generation > 0, generation <= UInt64(Int64.max), String(generation) == text
    else { throw BlahClientLeaseError.invalidNamespace }
    identityID = profile.id; self.destination = destination
    publicKey = try DevicePublicKey.decode(Array(bootstrap.publicKey))
    self.generation = generation; homeEpoch = home.epoch
    encoding = CBOR.array([.unsignedInt(BlahDiemTag.clientNamespace.rawValue), .unsignedInt(1),
      .byteString(profile.id[...]), .textString(destination.domain), .byteString(destination.keyID[...]),
      .unsignedInt(generation), .unsignedInt(home.epoch)]).encode()
  }

  public func require(profile: SignedProfile, at now: UInt64 = UInt64(Date().timeIntervalSince1970)) throws {
    try profile.verify(at: now, using: SoftwareDeviceCrypto())
    let home = try HomeDelegation(profile: profile, at: now)
    try home.requireHome(destination)
    guard profile.id == identityID, home.epoch == homeEpoch else { throw BlahClientLeaseError.wrongNamespace }
  }

  public static func hex(_ bytes: [UInt8]) -> String { bytes.map { String(format: "%02x", $0) }.joined() }
}

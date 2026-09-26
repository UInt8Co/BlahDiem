/// Monotonic authority state for profile storage. Roster authority is independent of
/// profile availability, so learning a revocation immediately invalidates an old profile.
public struct ProfileAuthorityState: Sendable {
  public let identityKey: DevicePublicKey
  public private(set) var deviceList: SignedDeviceList
  public private(set) var profile: SignedProfile?

  public init(
    identityKey: DevicePublicKey, deviceList: SignedDeviceList, profile: SignedProfile? = nil
  ) {
    self.identityKey = identityKey
    self.deviceList = deviceList
    self.profile = profile
  }

  public mutating func accept(
    _ incoming: SignedDeviceList, identityKey key: DevicePublicKey,
    at now: UInt64, using crypto: some DeviceCrypto
  ) throws {
    try incoming.verify(identityKey: key, at: now, using: crypto)
    guard key == identityKey else { throw DeviceIdentityError.identityMismatch }
    guard incoming.body.revision >= deviceList.body.revision else {
      throw DeviceIdentityError.staleVersion
    }
    if incoming.body.revision == deviceList.body.revision {
      guard incoming.digest(using: crypto) == deviceList.digest(using: crypto) else {
        throw DeviceIdentityError.versionConflict
      }
      return
    }
    if incoming.body.revision == deviceList.body.revision + 1 {
      guard incoming.body.previousDigest == deviceList.digest(using: crypto) else {
        throw DeviceIdentityError.versionConflict
      }
    }
    deviceList = incoming
    profile = nil
  }

  public mutating func accept(
    _ incoming: SignedProfile, at now: UInt64,
    expecting: ProfileExpectation = .any, using crypto: some DeviceCrypto
  ) throws {
    try incoming.verify(at: now, using: crypto)
    try expecting.check(profile, using: crypto)
    var proposed = self
    try proposed.accept(
      incoming.deviceList, identityKey: incoming.identityKey, at: now, using: crypto)
    if let current = proposed.profile {
      guard incoming.body.revision >= current.body.revision else {
        throw DeviceIdentityError.staleVersion
      }
      if incoming.body.revision == current.body.revision {
        guard incoming.digest(using: crypto) == current.digest(using: crypto) else {
          throw DeviceIdentityError.versionConflict
        }
        return
      }
      if incoming.body.revision == current.body.revision + 1 {
        guard incoming.body.previousDigest == current.digest(using: crypto) else {
          throw DeviceIdentityError.versionConflict
        }
      }
    }
    proposed.profile = incoming
    self = proposed
  }

  public func current(at now: UInt64, using crypto: some DeviceCrypto) throws
    -> SignedProfile?
  {
    guard let profile else { return nil }
    try profile.verify(at: now, using: crypto)
    guard profile.deviceList.digest(using: crypto) == deviceList.digest(using: crypto) else {
      throw DeviceIdentityError.staleVersion
    }
    return profile
  }
}

public enum ProfileExpectation: Sendable {
  case any, missing
  case digest([UInt8])
  public func check(_ profile: SignedProfile?, using crypto: some DeviceCrypto) throws {
    switch self {
    case .any: return
    case .missing:
      guard profile == nil else { throw DeviceIdentityError.compareAndSwapFailed }
    case .digest(let digest):
      guard profile?.digest(using: crypto) == digest else {
        throw DeviceIdentityError.compareAndSwapFailed
      }
    }
  }
}

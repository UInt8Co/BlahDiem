import BlahDiem
import JavaScriptKit

@JS public struct DCSetupRequest {
  public let data: [UInt8]
  public let profile: [UInt8]?
  public let now: Double
  public let profileLifetime: Double
  public let deviceLifetime: Double

  public init(data: [UInt8], profile: [UInt8]?, now: Double,
    profileLifetime: Double, deviceLifetime: Double) {
    self.data = data
    self.profile = profile
    self.now = now
    self.profileLifetime = profileLifetime
    self.deviceLifetime = deviceLifetime
  }
}

@JS public struct DCSetupResult {
  public let id: String
  public let profile: [UInt8]
  public let expiresAt: Double
  public let devices: [DeviceInfo]

  public init(id: String, profile: [UInt8], expiresAt: Double, devices: [DeviceInfo]) {
    self.id = id
    self.profile = profile
    self.expiresAt = expiresAt
    self.devices = devices
  }
}

/// Creates or renews a DC profile entirely in the operator's browser.
@JS public func dcSetup(input: DCSetupRequest, crypto: JSObject) async throws(JSException) -> DCSetupResult {
  do {
    guard let now = UInt64(exactly: input.now), now <= 9007199254740991,
      let profileLifetime = UInt64(exactly: input.profileLifetime), profileLifetime > 0,
      let deviceLifetime = UInt64(exactly: input.deviceLifetime), deviceLifetime >= profileLifetime,
      deviceLifetime <= 9007199254740991 - now else {
      throw BlahError.invalidProfile
    }
    let backend = BrowserBackend(now: now, crypto: crypto)
    let data = try DCProfile(data: input.data).encoded()
    let identityKey = try await IdentityPrivateKey(backend.makePrivateKey(.ed25519, for: .identity))
    let deviceKey = try await DevicePrivateKey(backend.makePrivateKey(.ed25519, for: .device))
    var identity: Identity
    if let profile = input.profile {
      let existing = try Profile(encoding: profile)
      _ = try DCProfile(existing)
      identity = try await Identity(profile: existing,
        deviceKey: deviceKey, identityKey: identityKey,
        profileLifetime: profileLifetime, deviceLifetime: deviceLifetime, using: backend)
      try await identity.renew()
      try await identity.update(data: data)
    } else {
      identity = try await Identity(data: data, identityKey: identityKey, deviceKey: deviceKey,
        profileLifetime: profileLifetime, deviceLifetime: deviceLifetime, using: backend)
    }
    return DCSetupResult(id: identity.id.description, profile: identity.profile.encoding,
      expiresAt: Double(identity.profile.validity.expiresAt), devices: deviceInfo(identity))
  } catch {
    throw JSException(message: bridgeError(error))
  }
}

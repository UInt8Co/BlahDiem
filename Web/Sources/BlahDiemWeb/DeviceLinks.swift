import BlahDiem
import DiemWeb
import JavaScriptKit

// Diem's web library owns link sessions (`beginDeviceLink`, `inspectDeviceLink`,
// `destroyDeviceLink`). Blah opens and responds with its acceptance rules and its metadata
// in the grant's `com.blahim` field.

@JS public struct DeviceLinkOpening {
  public let profile: [UInt8]
  public let domain: String
  public let seed: [UInt8]?
  public let metadata: [UInt8]?

  public init(profile: [UInt8], domain: String, seed: [UInt8]?, metadata: [UInt8]?) {
    self.profile = profile; self.domain = domain; self.seed = seed; self.metadata = metadata
  }
}

/// Ends `session` and opens its response as a Blah user homed at `expectedDC`. Blah's
/// checks run before a transferred seed is opened.
@JS public func openDeviceLink(session: String, response: [UInt8], expectedDC: [UInt8], now: Double)
  async throws(JSException) -> DeviceLinkOpening {
  do {
    // The session ends first, whatever the inputs; `open` rejects an invalid time.
    let dc = try? Digest(bytes: expectedDC), time = seconds(now) ?? 0
    let opened = try await WebDeviceLink.open(session: session, response: response, now: now,
      as: AnyBlahProfile.self) { profile, grant in
      guard let dc else { throw BlahError.wrongHome }
      try grant.acceptLink(of: profile, at: time, expectedDC: dc)
    }
    return DeviceLinkOpening(profile: opened.grant.profile, domain: opened.grant.domain.name,
      seed: opened.seed?.entropy, metadata: opened.grant.metadata)
  } catch { throw JSException(message: blahBridgeError(error)) }
}

@JS public struct DeviceLinkApproval {
  public let code: String
  public let request: [UInt8]
  public let profile: [UInt8]
  public let domain: String
  public let seed: [UInt8]?
  public let metadata: [UInt8]?
  public let now: Double

  public init(code: String, request: [UInt8], profile: [UInt8], domain: String,
    seed: [UInt8]?, metadata: [UInt8]?, now: Double) {
    self.code = code; self.request = request; self.profile = profile; self.domain = domain
    self.seed = seed; self.metadata = metadata; self.now = now
  }
}

/// Seals a grant of a Blah user profile, with `metadata` only alongside a seed.
@JS public func respondToDeviceLink(input: DeviceLinkApproval, crypto: JSObject)
  async throws(JSException) -> [UInt8] {
  do {
    guard input.seed != nil || input.metadata == nil else { throw BlahError.invalidDeviceLink }
    let time = seconds(input.now) ?? 0
    return try await WebDeviceLink.respond(code: input.code, request: input.request,
      profile: input.profile, domain: input.domain, seed: input.seed,
      applications: input.metadata.map { [.blah: .bytes($0)] } ?? [:], now: input.now,
      crypto: crypto, as: AnyBlahProfile.self) { profile, grant in
      try grant.acceptLink(of: profile, at: time, expectedDC: nil)
    }
  } catch { throw JSException(message: blahBridgeError(error)) }
}

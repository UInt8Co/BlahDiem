import BlahDiem
import JavaScriptKit

/// Public profile facts. Decimal strings preserve all wire integers exactly.
@JS public struct ProfileInfo {
  public let id: String
  public let kind: String
  public let generation: String
  public let revision: String
  public let notBefore: String
  public let expiresAt: String
  public let lapsed: Bool
  public let domains: [String]
  public let home: ProfileHomeInfo?

  public init(id: String, kind: String, generation: String, revision: String,
    notBefore: String, expiresAt: String, lapsed: Bool, domains: [String], home: ProfileHomeInfo?) {
    self.id = id; self.kind = kind; self.generation = generation; self.revision = revision
    self.notBefore = notBefore; self.expiresAt = expiresAt; self.lapsed = lapsed
    self.domains = domains; self.home = home
  }
}

@JS public struct ProfileHomeInfo {
  public let dc: String
  public let account: String?
  public let epoch: String

  public init(dc: String, account: String?, epoch: String) {
    self.dc = dc; self.account = account; self.epoch = epoch
  }
}

/// Verifies public profiles without a discovery domain or any private keys.
@JS public func verifyProfile(encoding: [UInt8], now: Double,
  crypto: JSObject) async throws(JSException) -> ProfileInfo {
  do {
    guard let time = UInt64(exactly: now), time <= 9007199254740991 else {
      throw BlahError.invalidProfile
    }
    let profile = try await AnyBlahProfile(verifying: encoding,
      using: BrowserBackend(now: time, crypto: crypto))
    let kind: String
    switch profile {
    case .user: kind = "user"
    case .channel: kind = "channel"
    case .bot: kind = "bot"
    case .stickerSet: kind = "stickerSet"
    case .dc: kind = "dc"
    }
    return ProfileInfo(id: profile.id.description, kind: kind,
      generation: String(profile.generation), revision: String(profile.revision),
      notBefore: String(profile.validity.notBefore), expiresAt: String(profile.validity.expiresAt),
      lapsed: !profile.validity.contains(time), domains: profile.domains.map { $0.name },
      home: profile.home.map {
        ProfileHomeInfo(dc: $0.dc.description, account: $0.account.map(String.init), epoch: String($0.epoch))
      })
  } catch {
    throw JSException(message: bridgeError(error))
  }
}

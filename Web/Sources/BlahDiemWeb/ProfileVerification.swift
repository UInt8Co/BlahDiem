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
  /// Decoded content, present only for `application` profiles.
  public let application: ApplicationInfo?

  public init(id: String, kind: String, generation: String, revision: String,
    notBefore: String, expiresAt: String, lapsed: Bool, domains: [String], home: ProfileHomeInfo?,
    application: ApplicationInfo? = nil) {
    self.id = id; self.kind = kind; self.generation = generation; self.revision = revision
    self.notBefore = notBefore; self.expiresAt = expiresAt; self.lapsed = lapsed
    self.domains = domains; self.home = home; self.application = application
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

@JS public struct ApplicationBotInfo {
  public let id: String
  public let dc: String

  public init(id: String, dc: String) { self.id = id; self.dc = dc }
}

@JS public struct ApplicationClientKeyInfo {
  public let keyID: String
  /// JWS algorithm: `EdDSA` or `ES256`.
  public let algorithm: String
  public let publicKey: [UInt8]

  public init(keyID: String, algorithm: String, publicKey: [UInt8]) {
    self.keyID = keyID; self.algorithm = algorithm; self.publicKey = publicKey
  }
}

@JS public struct ApplicationOAuthInfo {
  public let publicClient: Bool
  public let redirectURIs: [String]
  public let clientKeys: [ApplicationClientKeyInfo]

  public init(publicClient: Bool, redirectURIs: [String], clientKeys: [ApplicationClientKeyInfo]) {
    self.publicClient = publicClient; self.redirectURIs = redirectURIs; self.clientKeys = clientKeys
  }
}

@JS public struct ApplicationAPNSInfo {
  public let topic: String
  public let productionURL: String
  public let sandboxURL: String

  public init(topic: String, productionURL: String, sandboxURL: String) {
    self.topic = topic; self.productionURL = productionURL; self.sandboxURL = sandboxURL
  }
}

@JS public struct ApplicationWebPushInfo {
  public let proxyURL: String
  public let vapidPublicKey: [UInt8]

  public init(proxyURL: String, vapidPublicKey: [UInt8]) {
    self.proxyURL = proxyURL; self.vapidPublicKey = vapidPublicKey
  }
}

@JS public struct ApplicationPushInfo {
  public let credentialsURL: String
  public let apns: ApplicationAPNSInfo?
  public let webPush: ApplicationWebPushInfo?

  public init(credentialsURL: String, apns: ApplicationAPNSInfo?, webPush: ApplicationWebPushInfo?) {
    self.credentialsURL = credentialsURL; self.apns = apns; self.webPush = webPush
  }
}

/// An application profile's decoded content. Version boundaries are decimal strings.
@JS public struct ApplicationInfo {
  public let name: String
  public let downloadURL: String?
  public let bot: ApplicationBotInfo?
  public let oauth: ApplicationOAuthInfo?
  public let push: ApplicationPushInfo?
  public let versions: [String]?

  public init(name: String, downloadURL: String?, bot: ApplicationBotInfo?,
    oauth: ApplicationOAuthInfo?, push: ApplicationPushInfo?, versions: [String]?) {
    self.name = name; self.downloadURL = downloadURL; self.bot = bot
    self.oauth = oauth; self.push = push; self.versions = versions
  }

  init(_ content: ApplicationProfile.Content) {
    self.init(name: content.name, downloadURL: content.downloadURL,
      bot: content.bot.map { ApplicationBotInfo(id: $0.id.description, dc: $0.dc.description) },
      oauth: content.oauth.map { oauth in
        ApplicationOAuthInfo(publicClient: oauth.publicClient, redirectURIs: oauth.redirectURIs,
          clientKeys: oauth.clientKeys.map { key in
            ApplicationClientKeyInfo(keyID: key.keyID,
              algorithm: key.algorithm == .edDSA ? "EdDSA" : "ES256", publicKey: key.rawRepresentation)
          })
      },
      push: content.push.map { push in
        ApplicationPushInfo(credentialsURL: push.credentialsURL,
          apns: push.apns.map {
            ApplicationAPNSInfo(topic: $0.topic, productionURL: $0.productionURL, sandboxURL: $0.sandboxURL)
          },
          webPush: push.webPush.map {
            ApplicationWebPushInfo(proxyURL: $0.proxyURL, vapidPublicKey: $0.vapidPublicKey)
          })
      },
      versions: content.versions.map { $0.map(String.init) })
  }
}

/// The MTProto `api_id` and `api_hash` derived from an application identity.
@JS public struct ApplicationWirePairInfo {
  public let apiID: Double
  public let apiHash: String

  public init(apiID: Double, apiHash: String) { self.apiID = apiID; self.apiHash = apiHash }
}

/// Derives an application's wire pair from its 32-byte identity ID. The caller decides
/// whether that identity is a verified application; see `verifyProfile`.
@JS public func applicationWirePair(id: [UInt8]) throws(JSException) -> ApplicationWirePairInfo {
  do {
    let pair = ApplicationWirePair(application: try Digest(bytes: id))
    return ApplicationWirePairInfo(apiID: Double(pair.apiID), apiHash: pair.apiHash)
  } catch {
    throw JSException(message: bridgeError(error))
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
    case .application: kind = "application"
    }
    var application: ApplicationInfo?
    if case .application(let content) = profile.content { application = ApplicationInfo(content) }
    return ProfileInfo(id: profile.id.description, kind: kind,
      generation: String(profile.generation), revision: String(profile.revision),
      notBefore: String(profile.validity.notBefore), expiresAt: String(profile.validity.expiresAt),
      lapsed: !profile.validity.contains(time), domains: profile.domains.map { $0.name },
      home: profile.home.map {
        ProfileHomeInfo(dc: $0.dc.description, account: $0.account.map(String.init), epoch: String($0.epoch))
      }, application: application)
  } catch {
    throw JSException(message: bridgeError(error))
  }
}

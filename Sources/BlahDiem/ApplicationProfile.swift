/// An application's public profile: the client software that connects to any DC, its
/// optional bot, OAuth client data, push proxies and enabled versions.
///
/// The identity, not a DC, names the application. Its MTProto `api_id` and `api_hash`
/// derive from the identity ID; see ``ApplicationWirePair``.
public struct ApplicationProfile: BlahProfile {
  /// CBOR field keys in the signed profile content.
  public static let cborKeyKind: UInt64 = UserProfile.cborKeyKind
  public static let cborKeyName: UInt64 = UserProfile.cborKeyHome + 1
  public static let cborKeyDownloadURL: UInt64 = cborKeyName + 1
  public static let cborKeyBot: UInt64 = cborKeyDownloadURL + 1
  public static let cborKeyOAuth: UInt64 = cborKeyBot + 1
  public static let cborKeyPush: UInt64 = cborKeyOAuth + 1
  public static let cborKeyVersions: UInt64 = cborKeyPush + 1

  public static let maximumNameBytes = 256
  public static let maximumURLBytes = 2048
  public static let maximumRedirectURIs = 16
  public static let maximumClientKeys = 8
  public static let maximumVersions = 256
  public static var domainCount: ClosedRange<Int> { 1...ProfileFields.maximumDomains }

  /// The application's bot: an identity hosted by a DC.
  public struct Bot: Hashable, Sendable {
    /// CBOR field keys.
    public static let cborKeyID: UInt64 = 0
    public static let cborKeyDC: UInt64 = 1

    /// The bot's identity ID.
    public var id: Digest
    /// The identity ID of the bot's home DC.
    public var dc: Digest

    public init(id: Digest, dc: Digest) {
      self.id = id
      self.dc = dc
    }
  }

  /// A public key for `private_key_jwt` client assertions (RFC 7523).
  public struct ClientKey: Hashable, Sendable {
    /// CBOR field keys.
    public static let cborKeyKeyID: UInt64 = 0
    public static let cborKeyAlgorithm: UInt64 = 1
    public static let cborKeyRawRepresentation: UInt64 = 2
    public static let maximumKeyIDBytes = 128

    /// A JWS algorithm. Raw values are wire codes, matching Diem's key algorithms.
    public enum Algorithm: UInt64, Hashable, Sendable, CaseIterable {
      /// JWS `EdDSA` with a 32-byte Ed25519 public key.
      case edDSA = 1
      /// JWS `ES256` with a 65-byte SEC1 uncompressed P-256 public key.
      case es256 = 2
    }

    /// The JWS `kid` that selects this key, unique within the profile.
    public var keyID: String
    public var algorithm: Algorithm
    public var rawRepresentation: [UInt8]

    public init(keyID: String, algorithm: Algorithm, rawRepresentation: [UInt8]) {
      self.keyID = keyID
      self.algorithm = algorithm
      self.rawRepresentation = rawRepresentation
    }

    var isValid: Bool {
      guard (1...Self.maximumKeyIDBytes).contains(keyID.utf8.count),
        keyID.utf8.allSatisfy({ (33...126).contains($0) })
      else { return false }
      return switch algorithm {
      case .edDSA: rawRepresentation.count == 32
      case .es256: rawRepresentation.count == 65 && rawRepresentation[0] == 4
      }
    }
  }

  /// OAuth client data for Sign in with Blah.
  public struct OAuth: Hashable, Sendable {
    /// CBOR field keys.
    public static let cborKeyPublicClient: UInt64 = 0
    public static let cborKeyRedirectURIs: UInt64 = 1
    public static let cborKeyClientKeys: UInt64 = 2

    /// Whether the client holds no credentials and must use PKCE.
    public var publicClient: Bool
    /// The exact redirect URIs the client may use.
    public var redirectURIs: [String]
    /// Keys for `private_key_jwt` client authentication.
    public var clientKeys: [ClientKey]

    public init(publicClient: Bool, redirectURIs: [String], clientKeys: [ClientKey] = []) {
      self.publicClient = publicClient
      self.redirectURIs = redirectURIs
      self.clientKeys = clientKeys
    }
  }

  /// The application's push reverse proxies.
  public struct Push: Hashable, Sendable {
    /// CBOR field keys.
    public static let cborKeyCredentialsURL: UInt64 = 0
    public static let cborKeyAPNS: UInt64 = 1
    public static let cborKeyWebPush: UInt64 = 2

    /// Apple Push Notification service proxy endpoints.
    public struct APNS: Hashable, Sendable {
      /// CBOR field keys.
      public static let cborKeyTopic: UInt64 = 0
      public static let cborKeyProductionURL: UInt64 = 1
      public static let cborKeySandboxURL: UInt64 = 2
      public static let maximumTopicBytes = 255

      /// The `apns-topic`: the app's bundle ID.
      public var topic: String
      public var productionURL: String
      public var sandboxURL: String

      public init(topic: String, productionURL: String, sandboxURL: String) {
        self.topic = topic
        self.productionURL = productionURL
        self.sandboxURL = sandboxURL
      }
    }

    /// The Web Push proxy.
    public struct WebPush: Hashable, Sendable {
      /// CBOR field keys.
      public static let cborKeyProxyURL: UInt64 = 0
      public static let cborKeyVAPIDPublicKey: UInt64 = 1

      public var proxyURL: String
      /// The application server's VAPID key: a 65-byte SEC1 uncompressed P-256 key.
      public var vapidPublicKey: [UInt8]

      public init(proxyURL: String, vapidPublicKey: [UInt8]) {
        self.proxyURL = proxyURL
        self.vapidPublicKey = vapidPublicKey
      }
    }

    /// Where a DC obtains its stand-in provider credentials.
    public var credentialsURL: String
    public var apns: APNS?
    public var webPush: WebPush?

    public init(credentialsURL: String, apns: APNS? = nil, webPush: WebPush? = nil) {
      self.credentialsURL = credentialsURL
      self.apns = apns
      self.webPush = webPush
    }
  }

  public struct Content: Hashable, Sendable {
    /// The application's domains. The first names it to DCs and OAuth.
    public var domains: [DomainName]
    /// The display name.
    public var name: String
    /// An HTTPS page where users obtain the application.
    public var downloadURL: String?
    public var bot: Bot?
    public var oauth: OAuth?
    public var push: Push?
    /// Strictly increasing version boundaries; see ``isEnabled(version:)``.
    /// `nil` enables every version and an empty list enables none.
    public var versions: [Int64]?

    public init(
      domains: [DomainName], name: String, downloadURL: String? = nil, bot: Bot? = nil,
      oauth: OAuth? = nil, push: Push? = nil, versions: [Int64]? = nil
    ) {
      self.domains = domains
      self.name = name
      self.downloadURL = downloadURL
      self.bot = bot
      self.oauth = oauth
      self.push = push
      self.versions = versions
    }

    /// Whether `version` is enabled. Each boundary starts a range that runs up to the
    /// next one; ranges alternate enabled and disabled, starting enabled. Versions below
    /// the first boundary are disabled; the last range runs to `Int64.max`.
    public func isEnabled(version: Int64) -> Bool {
      guard let versions else { return true }
      var low = 0
      var high = versions.count
      while low < high {
        let mid = (low + high) / 2
        if versions[mid] <= version { low = mid + 1 } else { high = mid }
      }
      return low % 2 == 1
    }

    init(fields: ProfileFields) throws(BlahError) {
      let e = BlahError.invalidProfile
      let a = fields.application
      typealias P = ApplicationProfile
      guard try HostedRecord.kind(of: fields) == .application,
        (P.cborKeyName...P.cborKeyVersions).allSatisfy({ a[$0] != nil })
      else { throw e }
      func optional<T>(_ value: CBOR, _ read: (CBOR) throws(BlahError) -> T) throws(BlahError) -> T? {
        value == .null ? nil : try read(value)
      }
      func url(_ value: CBOR) throws(BlahError) -> String { try value.text(e) }
      self.init(
        domains: fields.domains,
        name: try a[P.cborKeyName]!.text(e),
        downloadURL: try optional(a[P.cborKeyDownloadURL]!, url),
        bot: try optional(a[P.cborKeyBot]!) { value throws(BlahError) in
          let b = try value.record(e, requiredKeys: Bot.cborKeyID..<(Bot.cborKeyDC + 1))
          return Bot(id: try b[Bot.cborKeyID]!.digest(e), dc: try b[Bot.cborKeyDC]!.digest(e))
        },
        oauth: try optional(a[P.cborKeyOAuth]!) { value throws(BlahError) in
          let o = try value.record(
            e, requiredKeys: OAuth.cborKeyPublicClient..<(OAuth.cborKeyClientKeys + 1))
          guard case .bool(let publicClient) = o[OAuth.cborKeyPublicClient]! else { throw e }
          var redirectURIs: [String] = []
          for uri in try o[OAuth.cborKeyRedirectURIs]!.array(e) { redirectURIs.append(try uri.text(e)) }
          var keys: [ClientKey] = []
          for entry in try o[OAuth.cborKeyClientKeys]!.array(e) {
            let k = try entry.record(
              e, requiredKeys: ClientKey.cborKeyKeyID..<(ClientKey.cborKeyRawRepresentation + 1))
            guard let algorithm = ClientKey.Algorithm(
              rawValue: try k[ClientKey.cborKeyAlgorithm]!.unsigned(e))
            else { throw e }
            keys.append(ClientKey(keyID: try k[ClientKey.cborKeyKeyID]!.text(e), algorithm: algorithm,
              rawRepresentation: try k[ClientKey.cborKeyRawRepresentation]!.bytes(e)))
          }
          return OAuth(publicClient: publicClient, redirectURIs: redirectURIs, clientKeys: keys)
        },
        push: try optional(a[P.cborKeyPush]!) { value throws(BlahError) in
          let p = try value.record(e, requiredKeys: Push.cborKeyCredentialsURL..<(Push.cborKeyWebPush + 1))
          return Push(
            credentialsURL: try url(p[Push.cborKeyCredentialsURL]!),
            apns: try optional(p[Push.cborKeyAPNS]!) { value throws(BlahError) in
              typealias A = Push.APNS
              let r = try value.record(e, requiredKeys: A.cborKeyTopic..<(A.cborKeySandboxURL + 1))
              return A(topic: try r[A.cborKeyTopic]!.text(e),
                productionURL: try url(r[A.cborKeyProductionURL]!),
                sandboxURL: try url(r[A.cborKeySandboxURL]!))
            },
            webPush: try optional(p[Push.cborKeyWebPush]!) { value throws(BlahError) in
              typealias W = Push.WebPush
              let r = try value.record(e, requiredKeys: W.cborKeyProxyURL..<(W.cborKeyVAPIDPublicKey + 1))
              return W(proxyURL: try url(r[W.cborKeyProxyURL]!),
                vapidPublicKey: try r[W.cborKeyVAPIDPublicKey]!.bytes(e, count: 65))
            })
        },
        versions: try optional(a[P.cborKeyVersions]!) { value throws(BlahError) in
          var versions: [Int64] = []
          for entry in try value.array(e) {
            switch entry {
            case .unsigned(let n):
              guard let n = Int64(exactly: n) else { throw e }
              versions.append(n)
            case .negative(let n): versions.append(n)
            default: throw e
            }
          }
          return versions
        })
      try validate()
    }

    var fields: ProfileFields {
      get throws(BlahError) {
        try validate()
        typealias P = ApplicationProfile
        func optional<T>(_ value: T?, _ encode: (T) -> CBOR) -> CBOR { value.map(encode) ?? .null }
        return ProfileFields(domains: domains, application: [
          P.cborKeyKind: .unsigned(ProfileKind.application.rawValue),
          P.cborKeyName: .text(name),
          P.cborKeyDownloadURL: optional(downloadURL, CBOR.text),
          P.cborKeyBot: optional(bot) {
            .record([Bot.cborKeyID: .bytes($0.id.bytes), Bot.cborKeyDC: .bytes($0.dc.bytes)])
          },
          P.cborKeyOAuth: optional(oauth) {
            .record([
              OAuth.cborKeyPublicClient: .bool($0.publicClient),
              OAuth.cborKeyRedirectURIs: .array($0.redirectURIs.map(CBOR.text)),
              OAuth.cborKeyClientKeys: .array($0.clientKeys.map {
                .record([
                  ClientKey.cborKeyKeyID: .text($0.keyID),
                  ClientKey.cborKeyAlgorithm: .unsigned($0.algorithm.rawValue),
                  ClientKey.cborKeyRawRepresentation: .bytes($0.rawRepresentation),
                ])
              }),
            ])
          },
          P.cborKeyPush: optional(push) {
            .record([
              Push.cborKeyCredentialsURL: .text($0.credentialsURL),
              Push.cborKeyAPNS: optional($0.apns) {
                .record([
                  Push.APNS.cborKeyTopic: .text($0.topic),
                  Push.APNS.cborKeyProductionURL: .text($0.productionURL),
                  Push.APNS.cborKeySandboxURL: .text($0.sandboxURL),
                ])
              },
              Push.cborKeyWebPush: optional($0.webPush) {
                .record([
                  Push.WebPush.cborKeyProxyURL: .text($0.proxyURL),
                  Push.WebPush.cborKeyVAPIDPublicKey: .bytes($0.vapidPublicKey),
                ])
              },
            ])
          },
          P.cborKeyVersions: optional(versions) {
            .array($0.map { $0 < 0 ? .negative($0) : .unsigned(UInt64($0)) })
          },
        ])
      }
    }

    private func validate() throws(BlahError) {
      try HostedRecord.validate(domains: domains, count: ApplicationProfile.domainCount)
      guard (1...ApplicationProfile.maximumNameBytes).contains(name.utf8.count),
        downloadURL.map(ApplicationProfile.isHTTPSURL) ?? true
      else { throw .invalidProfile }
      if let oauth {
        let keyIDs = Set(oauth.clientKeys.map { $0.keyID })
        guard (1...ApplicationProfile.maximumRedirectURIs).contains(oauth.redirectURIs.count),
          Set(oauth.redirectURIs).count == oauth.redirectURIs.count,
          oauth.redirectURIs.allSatisfy(ApplicationProfile.isRedirectURI),
          oauth.clientKeys.count <= ApplicationProfile.maximumClientKeys,
          keyIDs.count == oauth.clientKeys.count, oauth.clientKeys.allSatisfy({ $0.isValid })
        else { throw .invalidProfile }
      }
      if let push {
        guard ApplicationProfile.isHTTPSURL(push.credentialsURL) else { throw .invalidProfile }
        if let apns = push.apns {
          guard (1...Push.APNS.maximumTopicBytes).contains(apns.topic.utf8.count),
            apns.topic.utf8.allSatisfy({ (33...126).contains($0) }),
            ApplicationProfile.isHTTPSURL(apns.productionURL),
            ApplicationProfile.isHTTPSURL(apns.sandboxURL)
          else { throw .invalidProfile }
        }
        if let webPush = push.webPush {
          guard ApplicationProfile.isHTTPSURL(webPush.proxyURL),
            webPush.vapidPublicKey.count == 65, webPush.vapidPublicKey[0] == 4
          else { throw .invalidProfile }
        }
      }
      if let versions {
        try ApplicationProfile.validate(versions: versions)
      }
    }
  }

  public let record: ProfileRecord
  public let content: Content

  public init(record: ProfileRecord) throws(BlahError) {
    content = try Content(fields: record.fields)
    self.record = record
  }

  public static func fields(for content: Content) throws(BlahError) -> ProfileFields {
    try content.fields
  }

  /// An application is not hosted by a DC.
  public var home: Home? { nil }
  /// The display name.
  public var name: String { content.name }
  /// The MTProto `api_id` and `api_hash` derived from this identity.
  public var wirePair: ApplicationWirePair { ApplicationWirePair(application: id) }
  /// Whether `version` is enabled; see ``Content/isEnabled(version:)``.
  public func isEnabled(version: Int64) -> Bool { content.isEnabled(version: version) }

  /// Throws ``BlahError/invalidProfile`` unless `versions` is strictly increasing and
  /// has at most ``maximumVersions`` boundaries.
  public static func validate(versions: [Int64]) throws(BlahError) {
    guard versions.count <= maximumVersions,
      zip(versions, versions.dropFirst()).allSatisfy({ $0 < $1 })
    else { throw .invalidProfile }
  }

  /// An absolute `https` URL with a host and no fragment, of printable ASCII.
  static func isHTTPSURL(_ url: String) -> Bool {
    let bytes = Array(url.utf8)
    let prefix = Array("https://".utf8)
    guard bytes.count <= maximumURLBytes, bytes.starts(with: prefix),
      bytes.count > prefix.count, ![47, 63, 35].contains(bytes[prefix.count])
    else { return false }
    return bytes.allSatisfy { (33...126).contains($0) && $0 != 35 && $0 != 92 }
  }

  /// An absolute URI with a scheme and no fragment, of printable ASCII. Native apps may
  /// use private-use schemes (RFC 8252).
  static func isRedirectURI(_ uri: String) -> Bool {
    let bytes = Array(uri.utf8)
    guard bytes.count <= maximumURLBytes, let colon = bytes.firstIndex(of: 58), colon > 0,
      colon + 1 < bytes.count, (97...122).contains(bytes[0]) || (65...90).contains(bytes[0]),
      bytes[..<colon].allSatisfy({
        (97...122).contains($0) || (65...90).contains($0) || (48...57).contains($0)
          || [43, 45, 46].contains($0)
      })
    else { return false }
    return bytes.allSatisfy { (33...126).contains($0) && $0 != 35 && $0 != 92 }
  }
}

/// The MTProto `api_id` and `api_hash` of an application, derived from its identity ID.
///
/// With `d = SHA-256("Blah/app-id:1" ‖ id)`, `apiID` is bit 30 set over the low 30 bits of
/// the big-endian `d[0..<4]`, and `apiHash` is the lowercase hex of `d[4..<20]`. Derived IDs
/// are at least ``firstAPIID``, above every DC-local legacy ID. Neither value is secret.
public struct ApplicationWirePair: Hashable, Sendable {
  /// The derivation's domain-separation prefix.
  public static let context = Array("Blah/app-id:1".utf8)
  /// The smallest derived `api_id`.
  public static let firstAPIID: Int32 = 0x4000_0000

  public let apiID: Int32
  /// 32 lowercase hexadecimal digits.
  public let apiHash: String

  public init(application id: Digest) {
    let d = SHA2.sha256(Self.context + id.bytes)
    let prefix = d[0..<4].reduce(UInt32(0)) { $0 << 8 | UInt32($1) }
    apiID = Int32(bitPattern: UInt32(bitPattern: Self.firstAPIID) | (prefix & 0x3FFF_FFFF))
    let digits = Array("0123456789abcdef".utf8)
    apiHash = String(decoding: d[4..<20].flatMap { [digits[Int($0 >> 4)], digits[Int($0 & 15)]] },
      as: UTF8.self)
  }
}

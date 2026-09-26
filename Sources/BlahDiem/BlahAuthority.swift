@_exported import DiemSwiftCrypto

public enum FederationError: Error, Equatable {
  case invalidDelegation, wrongHome, unknownDC, staleHome, invalidChallenge, challengeLimit
  case challengeExpired, challengeConsumed, sessionAlreadyAuthorized, accountExists, accountMissing
  case admissionDenied, invalidName, authorityUnavailable
  case invalidReference, aliasConflict, deletedReference, allocatorExhausted, pinnedKeyChanged
  case changedMapping
}

/// A domain served by an identity. A flag makes it a public username for a
/// user, bot or channel; a set's sole flagged domain is its short name.
public struct ProfileDomain: Sendable, Equatable {
  public let domain: String
  public let username: Bool

  public init(_ domain: String, username: Bool = false) throws {
    guard DomainName.isValid(domain) else { throw FederationError.invalidName }
    self.domain = domain
    self.username = username
  }
}

/// Application authority carried inside a device-signed Diem profile. Each
/// epoch is one hosting: a newer epoch ends the account an older one named.
public struct HomeDelegation: Sendable, Equatable {
  /// What the identity is. Channels and supergroups are both `channel`; a bot
  /// is a user-numbered account; a sticker or custom-emoji set is its own kind.
  public enum Kind: String, Sendable, CaseIterable { case user, channel, bot, stickerSet }
  public let kind: Kind
  /// The home DC's Diem identity ID. Its discovery domain and endpoints are
  /// obtained from that DC's separately verified profile.
  public let homeIdentityID: [UInt8]?
  public var federationKeyID: [UInt8]? { homeIdentityID }
  public let epoch: UInt64
  public let expiresAt: UInt64
  /// The home's account number, named once that home has allocated it. Only
  /// the home can check it; anywhere else it locates the account.
  public let account: Int64?
  /// The domains that publish this exact profile. Only flagged ones resolve
  /// as public names.
  public let domains: [ProfileDomain]
  public var name: String? { domains.first(where: \.username)?.domain }

  public init(
    kind: Kind = .user, homeIdentityID: [UInt8]?, epoch: UInt64, expiresAt: UInt64,
    account: Int64? = nil, name: String? = nil, domains: [ProfileDomain]? = nil
  ) throws {
    guard epoch > 0, epoch <= UInt64(Int64.max), expiresAt <= UInt64(Int64.max),
      homeIdentityID == nil || homeIdentityID?.count == 32,
      account == nil || homeIdentityID != nil
    else { throw FederationError.invalidDelegation }
    guard name == nil || domains == nil else { throw FederationError.invalidName }
    let claims = try domains ?? name.map { [try ProfileDomain($0, username: true)] } ?? []
    guard claims.count <= 16, Set(claims.map(\.domain)).count == claims.count,
      (kind != .stickerSet || claims.count == 1),
      (kind != .stickerSet || claims.allSatisfy { $0.username }),
      (kind != .bot || claims.filter(\.username).allSatisfy {
        $0.domain.split(separator: ".").first?.hasSuffix("bot") == true
      })
    else { throw FederationError.invalidName }
    if let account {
      guard account > 0, account < kind.localIDKind.upperBound else { throw FederationError.invalidDelegation }
    }
    self.kind = kind
    self.homeIdentityID = homeIdentityID
    self.epoch = epoch
    self.expiresAt = expiresAt
    self.account = account
    self.domains = claims
  }

  /// Accepts a local DC discovery domain for validation. Only the DC identity
  /// is authoritative in the signed resource profile.
  public init(
    kind: Kind = .user, domain: String?, federationKeyID: [UInt8]?, epoch: UInt64, expiresAt: UInt64,
    account: Int64? = nil, name: String? = nil, domains: [ProfileDomain]? = nil
  ) throws {
    guard (domain == nil) == (federationKeyID == nil),
      domain.map(Self.validDomain) ?? true
    else { throw FederationError.invalidDelegation }
    try self.init(kind: kind, homeIdentityID: federationKeyID, epoch: epoch,
      expiresAt: expiresAt, account: account, name: name, domains: domains)
  }

  /// The same hosting, naming the account its home allocated.
  public func naming(account: Int64) throws -> Self {
    try .init(kind: kind, homeIdentityID: homeIdentityID, epoch: epoch,
      expiresAt: expiresAt, account: account, domains: domains)
  }

  /// The same hosting, claiming `name` (or, with `nil`, no name).
  public func claiming(name: String?) throws -> Self {
    var retained = domains.filter { !$0.username }
    if let name { retained.append(try ProfileDomain(name, username: true)) }
    return try .init(kind: kind, homeIdentityID: homeIdentityID, epoch: epoch,
      expiresAt: expiresAt, account: account, domains: retained)
  }

  public func advertising(_ domains: [ProfileDomain]) throws -> Self {
    try .init(kind: kind, homeIdentityID: homeIdentityID, epoch: epoch,
      expiresAt: expiresAt, account: account, domains: domains)
  }

  public func advertises(_ domain: String) -> Bool { domains.contains { $0.domain == domain } }
  public func names(_ domain: String) -> Bool {
    domains.contains { $0.domain == domain && $0.username }
  }

  public var fields: CBOR {
    // The account is appended once known; a signup profile has no number yet.
    var entry: [CBOR] = [
      .unsignedInt(3), .unsignedInt(kind.wireCode),
      homeIdentityID.map { .byteString($0[...]) } ?? .null, .unsignedInt(epoch),
      .unsignedInt(1), .unsignedInt(expiresAt),
    ]
    if let account { entry.append(.unsignedInt(UInt64(account))) }
    // Profile field numbers are fixed by BlahProfileField.
    let pairs = [
      CBORMapPair(key: .unsignedInt(BlahProfileField.home.rawValue), value: .array(entry)),
      CBORMapPair(key: .unsignedInt(BlahProfileField.domains.rawValue), value: .array(domains.map {
        .array([.textString($0.domain), .bool($0.username)])
      })),
    ]
    return .map(pairs)
  }

  public init(profile: SignedProfile, at now: UInt64) throws {
    guard case .map(let pairs) = profile.body.fields, pairs.count == 2,
      let entry = pairs.first(where: { $0.key == .unsignedInt(BlahProfileField.home.rawValue) }),
      case .array(let a) = entry.value, a.count == 6 || a.count == 7, a[0] == .unsignedInt(3),
      case .unsignedInt(let kindCode) = a[1], let kind = Kind(wireCode: kindCode),
      case .unsignedInt(let epoch) = a[3], a[4] == .unsignedInt(1),
      case .unsignedInt(let expiry) = a[5], expiry <= profile.body.validity.expiresAt,
      now < expiry
    else { throw FederationError.invalidDelegation }
    let key: [UInt8]?
    switch a[2] {
    case .null: key = nil
    case .byteString(let k): key = Array(k)
    default: throw FederationError.invalidDelegation
    }
    var account: Int64?
    if a.count == 7 {
      guard case .unsignedInt(let value) = a[6], value <= UInt64(Int64.max) else {
        throw FederationError.invalidDelegation
      }
      account = Int64(value)
    }
    guard let advertised = pairs.first(where: { $0.key == .unsignedInt(BlahProfileField.domains.rawValue) }),
      case .array(let rawDomains) = advertised.value
    else { throw FederationError.invalidDelegation }
    let domains = try rawDomains.map { value -> ProfileDomain in
      guard case .array(let entry) = value, entry.count == 2,
        case .textString(let domain) = entry[0], case .bool(let username) = entry[1]
      else { throw FederationError.invalidDelegation }
      return try ProfileDomain(domain, username: username)
    }
    try self.init(kind: kind, homeIdentityID: key, epoch: epoch, expiresAt: expiry,
      account: account, domains: domains)
  }

  public func requireHome(_ destination: FederationDestination, kind expectedKind: Kind = .user)
    throws
  {
    guard kind == expectedKind, homeIdentityID == destination.keyID
    else {
      throw FederationError.wrongHome
    }
  }

  /// Within one epoch the home stays fixed, and its account number, once named,
  /// can neither change nor disappear.
  public func succeeds(_ previous: Self) throws {
    guard kind == previous.kind, epoch >= previous.epoch,
      epoch > previous.epoch
        || (homeIdentityID == previous.homeIdentityID
          && (previous.account == nil || account == previous.account))
    else { throw FederationError.staleHome }
  }

  static func validDomain(_ value: String) -> Bool { DomainName.isValid(value) }
}

extension HomeDelegation.Kind {
  /// The local number space an account of this kind is allocated from.
  public var localIDKind: LocalIDKind {
    switch self {
    case .user, .bot: .user
    case .channel: .chat
    case .stickerSet: .stickerSet
    }
  }
}

public struct FederationDestination: Sendable, Equatable {
  public let domain: String
  public let keyID: [UInt8]
  public init(domain: String, keyID: [UInt8]) throws {
    guard HomeDelegation.validDomain(domain), keyID.count == 32 else {
      throw FederationError.invalidDelegation
    }
    self.domain = domain
    self.keyID = keyID
  }
}

/// The exact payload a device signs with Diem's `.login` purpose.
public struct DeviceLoginChallenge: Sendable {
  public enum Operation: String, Sendable { case signUp, signIn }
  public let operation: Operation
  public let nonce: [UInt8]
  public let expiresAt: UInt64
  public let identityID: [UInt8]
  public let deviceID: [UInt8]
  public let profileDigest: [UInt8]
  public let destination: FederationDestination
  public let authKeyID: Int64
  public let sessionID: UInt64

  public init(
    operation: Operation, nonce: [UInt8], expiresAt: UInt64, identityID: [UInt8],
    deviceID: [UInt8], profileDigest: [UInt8], destination: FederationDestination,
    authKeyID: Int64, sessionID: UInt64
  ) throws {
    guard [nonce, identityID, deviceID, profileDigest].allSatisfy({ $0.count == 32 }),
      authKeyID != 0, sessionID != 0, expiresAt <= UInt64(Int64.max)
    else { throw FederationError.invalidChallenge }
    self.operation = operation
    self.nonce = nonce
    self.expiresAt = expiresAt
    self.identityID = identityID
    self.deviceID = deviceID
    self.profileDigest = profileDigest
    self.destination = destination
    self.authKeyID = authKeyID
    self.sessionID = sessionID
  }

  public var encoding: [UInt8] {
    CBOR.array([
      .unsignedInt(BlahDiemTag.login.rawValue), .unsignedInt(1), .unsignedInt(operation.wireCode),
      .byteString(nonce[...]), .unsignedInt(expiresAt), .byteString(identityID[...]),
      .byteString(deviceID[...]), .byteString(profileDigest[...]), .textString(destination.domain),
      .byteString(destination.keyID[...]), .unsignedInt(UInt64(bitPattern: authKeyID)),
      .unsignedInt(sessionID),
    ]).encode()
  }
  public static func decode(_ bytes: [UInt8]) throws -> Self {
    let a = try CanonicalCBOR.array(bytes, count: 12)
    guard a[0] == .unsignedInt(BlahDiemTag.login.rawValue), a[1] == .unsignedInt(1),
      case .unsignedInt(let op) = a[2], let operation = Operation(wireCode: op),
      case .byteString(let nonce) = a[3], case .unsignedInt(let expiry) = a[4],
      case .byteString(let identity) = a[5], case .byteString(let device) = a[6],
      case .byteString(let digest) = a[7], case .textString(let domain) = a[8],
      case .byteString(let key) = a[9], case .unsignedInt(let authKey) = a[10],
      case .unsignedInt(let session) = a[11]
    else { throw FederationError.invalidChallenge }
    return try Self(
      operation: operation, nonce: Array(nonce), expiresAt: expiry, identityID: Array(identity),
      deviceID: Array(device), profileDigest: Array(digest),
      destination: .init(domain: domain, keyID: Array(key)), authKeyID: Int64(bitPattern: authKey),
      sessionID: session)
  }
}

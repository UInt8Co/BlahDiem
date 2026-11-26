/// A Diem profile of a Blah identity: named by the domains that serve it, with a profile
/// kind and that kind's fields signed in Blah's application field.
public protocol BlahProfile: DomainNamedProfile {
  /// The account hosting that proofs and client namespaces rely on. A DC is a special
  /// user permanently hosted by itself; its hosting expires with the profile.
  var home: Home? { get }
}

extension BlahProfile {
  /// The application whose field holds the profile kind and that kind's fields.
  public static var application: ApplicationID { .blah }
  /// Blah's field: publishing Blah content replaces it and keeps other applications'.
  public static var applications: Set<ApplicationID> { [.blah] }
}

/// The DC hosting an account, and the account it allocated there.
public struct Home: Hashable, Sendable {
  /// CBOR field keys.
  public static let cborKeyDC: UInt64 = 0
  public static let cborKeyEpoch: UInt64 = 1
  public static let cborKeyExpiresAt: UInt64 = 2
  public static let cborKeyAccount: UInt64 = 3

  /// The home DC's identity ID.
  public var dc: Digest
  /// The hosting's epoch. A later epoch is a new account.
  public var epoch: UInt64
  /// The end of this home delegation, in Unix seconds.
  public var expiresAt: UInt64
  /// The account number the home allocated, once known.
  public var account: Int64?

  public init(dc: Digest, epoch: UInt64, expiresAt: UInt64, account: Int64? = nil) {
    self.dc = dc
    self.epoch = epoch
    self.expiresAt = expiresAt
    self.account = account
  }

  /// Whether the delegation is in force at `time`.
  public func isActive(at time: UInt64) -> Bool { time < expiresAt }
}

/// The content of a user, bot or channel profile.
public struct HostedContent: Hashable, Sendable {
  public var home: Home?
  /// The domains that serve the profile. Every one is a public username candidate.
  public var domains: [DomainName]

  public init(home: Home?, domains: [DomainName] = []) {
    self.home = home
    self.domains = domains
  }

  /// The first domain. Setting this replaces the domain list with that one name.
  public var username: DomainName? {
    get { domains.first }
    set { domains = newValue.map { [$0] } ?? [] }
  }
}

/// A person's profile.
public struct UserProfile: BlahProfile {
  /// CBOR field keys in the map at ``BlahProfile/application`` in the signed profile
  /// content.
  public static let cborKeyKind: UInt64 = 0
  public static let cborKeyHome: UInt64 = cborKeyKind + 1

  public let record: ProfileRecord
  public let content: HostedContent

  public init(record: ProfileRecord) throws(BlahError) {
    content = try HostedRecord.decode(record.fields, kind: .user)
    self.record = record
  }

  public static func fields(for content: HostedContent) throws(BlahError) -> ProfileFields {
    try HostedRecord.encode(content, kind: .user)
  }

  public static func content(_ content: HostedContent, replacingDomains domains: [DomainName])
    throws(BlahError) -> HostedContent
  {
    try HostedRecord.replacing(content, domains: domains, kind: .user)
  }

  public var home: Home? { content.home }
  /// The first domain.
  public var username: DomainName? { content.username }
}

/// A bot's profile.
public struct BotProfile: BlahProfile {
  /// CBOR field keys in the map at ``BlahProfile/application`` in the signed profile
  /// content.
  public static let cborKeyKind: UInt64 = UserProfile.cborKeyKind
  public static let cborKeyHome: UInt64 = UserProfile.cborKeyHome

  public let record: ProfileRecord
  public let content: HostedContent

  public init(record: ProfileRecord) throws(BlahError) {
    content = try HostedRecord.decode(record.fields, kind: .bot)
    self.record = record
  }

  public static func fields(for content: HostedContent) throws(BlahError) -> ProfileFields {
    try HostedRecord.encode(content, kind: .bot)
  }

  public static func content(_ content: HostedContent, replacingDomains domains: [DomainName])
    throws(BlahError) -> HostedContent
  {
    try HostedRecord.replacing(content, domains: domains, kind: .bot)
  }

  public var home: Home? { content.home }
  /// The first domain.
  public var username: DomainName? { content.username }
}

/// A channel's or supergroup's profile.
public struct ChannelProfile: BlahProfile {
  /// CBOR field keys in the map at ``BlahProfile/application`` in the signed profile
  /// content.
  public static let cborKeyKind: UInt64 = UserProfile.cborKeyKind
  public static let cborKeyHome: UInt64 = UserProfile.cborKeyHome

  public let record: ProfileRecord
  public let content: HostedContent

  public init(record: ProfileRecord) throws(BlahError) {
    content = try HostedRecord.decode(record.fields, kind: .channel)
    self.record = record
  }

  public static func fields(for content: HostedContent) throws(BlahError) -> ProfileFields {
    try HostedRecord.encode(content, kind: .channel)
  }

  public static func content(_ content: HostedContent, replacingDomains domains: [DomainName])
    throws(BlahError) -> HostedContent
  {
    try HostedRecord.replacing(content, domains: domains, kind: .channel)
  }

  public var home: Home? { content.home }
  /// The first domain.
  public var username: DomainName? { content.username }
}

/// A sticker or custom-emoji set's profile.
public struct StickerSetProfile: BlahProfile {
  /// CBOR field keys in the map at ``BlahProfile/application`` in the signed profile
  /// content.
  public static let cborKeyKind: UInt64 = UserProfile.cborKeyKind
  public static let cborKeyHome: UInt64 = UserProfile.cborKeyHome

  public struct Content: Hashable, Sendable {
    public var home: Home?
    /// The set's short name: the one domain that serves its profile.
    public var shortName: DomainName

    public init(home: Home?, shortName: DomainName) {
      self.home = home
      self.shortName = shortName
    }
  }

  public static var domainCount: ClosedRange<Int> { 1...1 }

  public let record: ProfileRecord
  public let content: Content

  public init(record: ProfileRecord) throws(BlahError) {
    let hosted = try HostedRecord.decode(record.fields, kind: .stickerSet)
    content = Content(home: hosted.home, shortName: hosted.domains[0])
    self.record = record
  }

  public static func fields(for content: Content) throws(BlahError) -> ProfileFields {
    try HostedRecord.encode(
      HostedContent(home: content.home, domains: [content.shortName]), kind: .stickerSet)
  }

  /// Replaces the short name: `domains` must be exactly one name.
  public static func content(_ content: Content, replacingDomains domains: [DomainName])
    throws(BlahError) -> Content
  {
    guard domains.count == 1 else { throw .invalidName }
    var next = content
    next.shortName = domains[0]
    _ = try fields(for: next)
    return next
  }

  public var home: Home? { content.home }
  /// The set's short name.
  public var shortName: DomainName { content.shortName }
}

/// Any Blah profile, by kind.
public enum AnyBlahProfile: BlahProfile {
  /// The content of any Blah profile, by kind.
  public enum Content: Hashable, Sendable {
    case user(HostedContent)
    case bot(HostedContent)
    case channel(HostedContent)
    case stickerSet(StickerSetProfile.Content)
    case dc(DCProfile.Content)
    case application(ApplicationProfile.Content)

    /// Decodes the content of signed or unsigned profile fields.
    public init(fields: ProfileFields) throws(BlahError) {
      switch try HostedRecord.kind(of: fields) {
      case .user: self = .user(try HostedRecord.decode(fields, kind: .user))
      case .bot: self = .bot(try HostedRecord.decode(fields, kind: .bot))
      case .channel: self = .channel(try HostedRecord.decode(fields, kind: .channel))
      case .stickerSet:
        let hosted = try HostedRecord.decode(fields, kind: .stickerSet)
        self = .stickerSet(.init(home: hosted.home, shortName: hosted.domains[0]))
      case .dc: self = .dc(try DCProfile.Content(fields: fields))
      case .application: self = .application(try ApplicationProfile.Content(fields: fields))
      }
    }
  }

  case user(UserProfile)
  case bot(BotProfile)
  case channel(ChannelProfile)
  case stickerSet(StickerSetProfile)
  case dc(DCProfile)
  case application(ApplicationProfile)

  public init(record: ProfileRecord) throws(BlahError) {
    switch try HostedRecord.kind(of: record.fields) {
    case .user: self = .user(try UserProfile(record: record))
    case .bot: self = .bot(try BotProfile(record: record))
    case .channel: self = .channel(try ChannelProfile(record: record))
    case .stickerSet: self = .stickerSet(try StickerSetProfile(record: record))
    case .dc: self = .dc(try DCProfile(record: record))
    case .application: self = .application(try ApplicationProfile(record: record))
    }
  }

  public static func fields(for content: Content) throws(BlahError) -> ProfileFields {
    switch content {
    case .user(let c): try UserProfile.fields(for: c)
    case .bot(let c): try BotProfile.fields(for: c)
    case .channel(let c): try ChannelProfile.fields(for: c)
    case .stickerSet(let c): try StickerSetProfile.fields(for: c)
    case .dc(let c): try DCProfile.fields(for: c)
    case .application(let c): try ApplicationProfile.fields(for: c)
    }
  }

  /// `content` listing `domains`, under its kind's own naming rules.
  public static func content(_ content: Content, replacingDomains domains: [DomainName])
    throws(BlahError) -> Content
  {
    switch content {
    case .user(let c): .user(try UserProfile.content(c, replacingDomains: domains))
    case .bot(let c): .bot(try BotProfile.content(c, replacingDomains: domains))
    case .channel(let c): .channel(try ChannelProfile.content(c, replacingDomains: domains))
    case .stickerSet(let c):
      .stickerSet(try StickerSetProfile.content(c, replacingDomains: domains))
    case .dc(let c): .dc(try DCProfile.content(c, replacingDomains: domains))
    case .application(let c):
      .application(try ApplicationProfile.content(c, replacingDomains: domains))
    }
  }

  public var record: ProfileRecord {
    switch self {
    case .user(let p): p.record
    case .bot(let p): p.record
    case .channel(let p): p.record
    case .stickerSet(let p): p.record
    case .dc(let p): p.record
    case .application(let p): p.record
    }
  }

  public var content: Content {
    switch self {
    case .user(let p): .user(p.content)
    case .bot(let p): .bot(p.content)
    case .channel(let p): .channel(p.content)
    case .stickerSet(let p): .stickerSet(p.content)
    case .dc(let p): .dc(p.content)
    case .application(let p): .application(p.content)
    }
  }

  public var home: Home? {
    switch self {
    case .user(let p): p.home
    case .bot(let p): p.home
    case .channel(let p): p.home
    case .stickerSet(let p): p.home
    case .dc(let p): p.home
    case .application(let p): p.home
    }
  }
}

/// Blah's application field: a map of a kind and, for hosted kinds, a nullable home record.
enum HostedRecord {
  /// The map at ``ApplicationID/blah``. Keys it does not know are ignored.
  static func blah(_ fields: ProfileFields) throws(BlahError) -> CBOR.Record {
    guard let value = fields.applications[.blah] else { throw .invalidProfile }
    return try value.record(.invalidProfile, requiredKeys: UserProfile.cborKeyKind..<(UserProfile.cborKeyKind + 1))
  }

  /// Profile fields with the Blah map holding `blah`.
  static func fields(domains: [DomainName], blah: [UInt64: CBOR]) -> ProfileFields {
    ProfileFields(domains: domains, applications: [.blah: .record(blah)])
  }

  static func kind(of fields: ProfileFields) throws(BlahError) -> ProfileKind {
    try kind(of: blah(fields))
  }

  static func kind(of blah: CBOR.Record) throws(BlahError) -> ProfileKind {
    guard let kind = ProfileKind(rawValue: try blah[UserProfile.cborKeyKind]!.unsigned(.invalidProfile))
    else { throw .invalidProfile }
    return kind
  }

  static func replacing(_ content: HostedContent, domains: [DomainName], kind: ProfileKind)
    throws(BlahError) -> HostedContent
  {
    var next = content
    next.domains = domains
    try validate(next, kind: kind)
    return next
  }

  static func encode(_ content: HostedContent, kind: ProfileKind) throws(BlahError) -> ProfileFields {
    try validate(content, kind: kind)
    let home: CBOR =
      content.home.map {
        .record([
          Home.cborKeyDC: .bytes($0.dc.bytes), Home.cborKeyEpoch: .unsigned($0.epoch),
          Home.cborKeyExpiresAt: .unsigned($0.expiresAt),
          Home.cborKeyAccount: $0.account.map { .unsigned(UInt64($0)) } ?? .null,
        ])
      } ?? .null
    return fields(domains: content.domains, blah: [
      UserProfile.cborKeyKind: .unsigned(kind.rawValue), UserProfile.cborKeyHome: home,
    ])
  }

  static func decode(_ fields: ProfileFields, kind: ProfileKind) throws(BlahError) -> HostedContent {
    let e = BlahError.invalidProfile
    let map = try blah(fields)
    guard try self.kind(of: map) == kind, let value = map[UserProfile.cborKeyHome] else { throw e }
    var home: Home?
    if value != .null {
      let h = try value.record(e, requiredKeys: Home.cborKeyDC..<(Home.cborKeyAccount + 1))
      home = Home(
        dc: try h[Home.cborKeyDC]!.digest(e), epoch: try h[Home.cborKeyEpoch]!.unsigned(e),
        expiresAt: try h[Home.cborKeyExpiresAt]!.unsigned(e),
        account: h[Home.cborKeyAccount]! == .null
          ? nil : Int64(exactly: try h[Home.cborKeyAccount]!.unsigned(e)) ?? 0)
    }
    let content = HostedContent(home: home, domains: fields.domains)
    try validate(content, kind: kind)
    return content
  }

  static func validate(_ content: HostedContent, kind: ProfileKind) throws(BlahError) {
    if let home = content.home {
      let accountLimit: Int64 = switch kind {
      case .user, .bot, .dc, .application: 9_007_199_254_740_991
      case .channel: 997_852_516_352
      case .stickerSet: .max
      }
      guard (1...UInt64(Int64.max)).contains(home.epoch), home.expiresAt <= UInt64(Int64.max),
        home.account.map({ $0 > 0 && $0 < accountLimit }) ?? true
      else { throw .invalidProfile }
    }
    let domainCount = kind == .stickerSet
      ? StickerSetProfile.domainCount : UserProfile.domainCount
    try validate(domains: content.domains, count: domainCount)
  }

  /// Distinct domains, as many as the kind lists.
  static func validate(domains: [DomainName], count: ClosedRange<Int>) throws(BlahError) {
    guard count.contains(domains.count), Set(domains).count == domains.count else {
      throw .invalidName
    }
  }
}

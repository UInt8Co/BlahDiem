import Foundation

/// A bounded description of the sender's user namespace. The publisher is a
/// location hint, never identity evidence; the fetched Diem profile supplies that.
public struct FederationUserReference: Sendable, Equatable {
  /// A home DC's ordinary public-user attestation, independent of Diem proof.
  /// Receivers may apply it only when the profile delegates to the bound peer.
  public struct Metadata: Sendable, Equatable {
    public let firstName: String
    public let lastName: String?
    public let isPremium: Bool
    public init(firstName: String, lastName: String?, isPremium: Bool) throws {
      guard firstName.utf8.count <= 512, (lastName?.utf8.count ?? 0) <= 512 else {
        throw FederationError.invalidReference
      }
      self.firstName = firstName; self.lastName = lastName; self.isPremium = isPremium
    }
  }
  public let localID: Int64
  public let identity: [UInt8]
  /// The home epoch of the account meant; a later hosting is another account.
  public let epoch: UInt64
  public let publisher: String
  public let metadata: Metadata?
  /// A person or a bot: both are user-numbered accounts named by an identity.
  public let kind: HomeDelegation.Kind
  public let canonical: CanonicalReference

  public init(localID: Int64, identity: [UInt8], epoch: UInt64, publisher: String, metadata: Metadata? = nil,
    kind: HomeDelegation.Kind = .user) throws
  {
    guard localID > 0, localID < LocalIDKind.user.upperBound, HomeDelegation.validDomain(publisher),
      kind == .user || kind == .bot
    else { throw FederationError.invalidReference }
    canonical = try .identity(identity, kind: kind, epoch: epoch)
    self.localID = localID
    self.identity = identity
    self.epoch = epoch
    self.publisher = publisher
    self.metadata = metadata
    self.kind = kind
  }
}

/// Channel references use the canonical binding reserved by their owner. A
/// third DC can name that binding but cannot attest its mutable metadata.
public struct FederationChannelReference: Sendable, Equatable {
  public struct Metadata: Sendable, Equatable {
    public let title: String
    public let kindFlags: Int32
    public init(title: String, kindFlags: Int32) throws {
      guard title.utf8.count <= 1024, (0...255).contains(kindFlags) else {
        throw FederationError.invalidReference
      }
      self.title = title; self.kindFlags = kindFlags
    }
  }
  public let localID: Int64
  public let canonical: CanonicalReference
  public let metadata: Metadata?
  public init(localID: Int64, canonical: CanonicalReference, metadata: Metadata? = nil) throws {
    guard canonical.kind == .chat || canonical.kind == .monoforum,
      canonical.objectOrigin != nil, localID > 0, localID < canonical.kind.upperBound,
      canonical.kind != .monoforum || localID >= LocalIDKind.monoforum.firstID
    else { throw FederationError.invalidReference }
    self.localID = localID; self.canonical = canonical; self.metadata = metadata
  }
}

/// A poll's wire ID has its own local namespace. Its choices remain opaque
/// values scoped to that poll; mutable results travel in the ordinary TL graph.
public struct FederationPollReference: Sendable, Equatable {
  public let localID: Int64
  public let canonical: CanonicalReference
  public init(localID: Int64, canonical: CanonicalReference) throws {
    guard canonical.kind == .poll, canonical.objectOrigin != nil,
      localID > 0, localID < LocalIDKind.poll.upperBound else { throw FederationError.invalidReference }
    self.localID = localID; self.canonical = canonical
  }
}

/// A sticker or custom-emoji set bound by its owner. Any home that names it
/// states its immutable kind and last known header; receivers apply those
/// values to a new pointer, and only the owner can refresh an existing one.
public struct FederationStickerSetReference: Sendable, Equatable {
  public struct Metadata: Sendable, Equatable {
    public let emojis: Bool
    public let title: String
    public let shortName: String
    public let count: Int32
    public let hash: Int32
    public init(emojis: Bool, title: String, shortName: String, count: Int32, hash: Int32) throws {
      guard title.utf8.count <= 1024, (1...DomainName.maximumLength).contains(shortName.utf8.count), count >= 0 else {
        throw FederationError.invalidReference
      }
      self.emojis = emojis; self.title = title; self.shortName = shortName; self.count = count; self.hash = hash
    }
  }
  public let localID: Int64
  public let canonical: CanonicalReference
  public let metadata: Metadata
  public init(localID: Int64, canonical: CanonicalReference, metadata: Metadata) throws {
    guard canonical.kind == .stickerSet, canonical.objectOrigin != nil,
      localID > 0, localID < LocalIDKind.stickerSet.upperBound else { throw FederationError.invalidReference }
    self.localID = localID; self.canonical = canonical; self.metadata = metadata
  }
  var cbor: CBOR {
    .array([.unsignedInt(UInt64(localID)), .byteString(canonical.encoding[...]),
      .unsignedInt(metadata.emojis ? 1 : 0), .textString(metadata.title), .textString(metadata.shortName),
      .unsignedInt(UInt64(metadata.count)), .unsignedInt(UInt64(UInt32(bitPattern: metadata.hash)))])
  }
  static func decode(_ value: CBOR) throws -> Self {
    guard case .array(let row) = value, row.count == 7,
      case .unsignedInt(let id) = row[0], id <= UInt64(Int64.max),
      case .byteString(let canonical) = row[1],
      case .unsignedInt(let emojis) = row[2], emojis <= 1,
      case .textString(let title) = row[3], case .textString(let shortName) = row[4],
      case .unsignedInt(let count) = row[5], count <= UInt64(Int32.max),
      case .unsignedInt(let hash) = row[6], hash <= UInt64(UInt32.max)
    else { throw FederationError.invalidReference }
    return try .init(localID: Int64(id), canonical: .decode(Array(canonical)), metadata: .init(
      emojis: emojis == 1, title: title, shortName: shortName, count: Int32(count),
      hash: Int32(bitPattern: UInt32(hash))))
  }
}

public struct FederationReferences: Sendable, Equatable {
  public let origin: FederationDestination
  public let layer: Int
  public let users: [FederationUserReference]
  public let channels: [FederationChannelReference]
  public let files: [FederationFileReference]
  public let polls: [FederationPollReference]
  public let stickerSets: [FederationStickerSetReference]

  public init(origin: FederationDestination, layer: Int, users: [FederationUserReference],
    channels: [FederationChannelReference] = [], files: [FederationFileReference] = [],
    polls: [FederationPollReference] = [], stickerSets: [FederationStickerSetReference] = []) throws {
    guard layer > 0, layer <= Int(Int32.max),
      (1...512).contains(users.count + channels.count + files.count + polls.count + stickerSets.count),
      Set(users.map(\.localID)).count == users.count,
      Set(users.map(\.canonical)).count == users.count,
      Set(channels.map(\.localID)).count == channels.count,
      Set(channels.map(\.canonical)).count == channels.count,
      Set(files.map(\.localID)).count == files.count, Set(files.map(\.canonical)).count == files.count,
      Set(polls.map(\.localID)).count == polls.count, Set(polls.map(\.canonical)).count == polls.count,
      Set(stickerSets.map(\.localID)).count == stickerSets.count,
      Set(stickerSets.map(\.canonical)).count == stickerSets.count,
      Set(files.map(\.ownerUserID)).isSubset(of: Set(users.map(\.localID))),
      Set(files.compactMap(\.descriptor.stickerSetID)).isSubset(of: Set(stickerSets.map(\.localID)))
    else { throw FederationError.invalidReference }
    self.origin = origin
    self.layer = layer
    self.users = users.sorted { $0.localID < $1.localID }
    self.channels = channels.sorted { $0.localID < $1.localID }
    self.files = files.sorted { $0.localID < $1.localID }
    self.polls = polls.sorted { $0.localID < $1.localID }
    self.stickerSets = stickerSets.sorted { $0.localID < $1.localID }
    guard encoding.count <= CanonicalCBOR.maximumBytes else { throw FederationError.invalidReference }
  }

  public var encoding: [UInt8] {
    let fields: [CBOR] = [
      .unsignedInt(BlahDiemTag.references.rawValue),
      .unsignedInt(1),
      .textString(origin.domain),
      .byteString(origin.keyID[...]), .unsignedInt(UInt64(layer)),
      .array(users.map { user in
        let row: [CBOR] = [
          .unsignedInt(UInt64(user.localID)), .byteString(user.identity[...]), .textString(user.publisher),
          user.metadata.map { .array([.textString($0.firstName), $0.lastName.map(CBOR.textString) ?? .null,
            .bool($0.isPremium)]) } ?? .null, .unsignedInt(user.epoch), .unsignedInt(user.kind.wireCode),
        ]
        return .array(row)
      }),
      .array(channels.map { .array([
        .unsignedInt(UInt64($0.localID)), .byteString($0.canonical.encoding[...]),
        $0.metadata.map { .array([.textString($0.title), .unsignedInt(UInt64($0.kindFlags))]) } ?? .null,
      ]) }),
      .array(files.map(\.cbor)),
      .array(polls.map { .array([.unsignedInt(UInt64($0.localID)), .byteString($0.canonical.encoding[...])]) }),
      .array(stickerSets.map(\.cbor)),
    ]
    return CBOR.array(fields).encode()
  }

  public static func decode(_ bytes: [UInt8]) throws -> Self {
    guard case .array(let a) = try CanonicalCBOR.decode(bytes),
      a.count == 10,
      a[0] == .unsignedInt(BlahDiemTag.references.rawValue), a[1] == .unsignedInt(1),
      case .textString(let domain) = a[2], case .byteString(let key) = a[3],
      case .unsignedInt(let layer) = a[4], layer <= UInt64(Int32.max),
      case .array(let rows) = a[5], rows.count <= 512
    else { throw FederationError.invalidReference }
    var channels: [FederationChannelReference] = []
    do {
      guard case .array(let rows) = a[6], rows.count <= 512 else { throw FederationError.invalidReference }
      channels = try rows.map {
        guard case .array(let row) = $0, row.count == 3,
          case .unsignedInt(let id) = row[0], id <= UInt64(Int64.max),
          case .byteString(let canonical) = row[1]
        else { throw FederationError.invalidReference }
        let metadata: FederationChannelReference.Metadata?
        if row[2] == .null { metadata = nil }
        else {
          guard case .array(let fields) = row[2], fields.count == 2,
            case .textString(let title) = fields[0], case .unsignedInt(let flags) = fields[1], flags <= 255
          else { throw FederationError.invalidReference }
          metadata = try .init(title: title, kindFlags: Int32(flags))
        }
        return try .init(localID: Int64(id), canonical: .decode(Array(canonical)), metadata: metadata)
      }
    }
    var files: [FederationFileReference] = []
    do {
      guard case .array(let rows) = a[7], rows.count <= 512 else { throw FederationError.invalidReference }
      files = try rows.map(FederationFileReference.decode)
    }
    var polls: [FederationPollReference] = []
    do {
      guard case .array(let rows) = a[8], rows.count <= 512 else { throw FederationError.invalidReference }
      polls = try rows.map {
        guard case .array(let row) = $0, row.count == 2,
          case .unsignedInt(let id) = row[0], id <= UInt64(Int64.max),
          case .byteString(let canonical) = row[1] else { throw FederationError.invalidReference }
        return try .init(localID: Int64(id), canonical: .decode(Array(canonical)))
      }
    }
    var stickerSets: [FederationStickerSetReference] = []
    do {
      guard case .array(let rows) = a[9], rows.count <= 512 else { throw FederationError.invalidReference }
      stickerSets = try rows.map(FederationStickerSetReference.decode)
    }
    let result = try Self(origin: .init(domain: domain, keyID: Array(key)), layer: Int(layer),
      users: rows.map {
        guard case .array(let row) = $0, row.count == 6,
          case .unsignedInt(let id) = row[0], id <= UInt64(Int64.max),
          case .byteString(let identity) = row[1], case .textString(let publisher) = row[2],
          case .unsignedInt(let epoch) = row[4],
          case .unsignedInt(let kindCode) = row[5],
          let kind = HomeDelegation.Kind(wireCode: kindCode), kind == .user || kind == .bot
        else { throw FederationError.invalidReference }
        let metadata: FederationUserReference.Metadata?
        if row[3] == .null { metadata = nil }
        else {
          guard case .array(let fields) = row[3], fields.count == 3,
            case .textString(let firstName) = fields[0],
            case .bool(let premium) = fields[2]
          else { throw FederationError.invalidReference }
          let lastName: String?
          if case .textString(let name) = fields[1] { lastName = name }
          else if fields[1] == .null { lastName = nil }
          else { throw FederationError.invalidReference }
          metadata = try .init(firstName: firstName, lastName: lastName, isPremium: premium)
        }
        return try .init(localID: Int64(id), identity: Array(identity), epoch: epoch, publisher: publisher,
          metadata: metadata, kind: kind)
      }, channels: channels, files: files, polls: polls, stickerSets: stickerSets)
    guard result.encoding == bytes else { throw FederationError.invalidReference }
    return result
  }
}

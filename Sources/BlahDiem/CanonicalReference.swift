import Foundation

/// Numeric namespaces exposed to Telegram clients. They are local to one DC;
/// message and topic numbers additionally require a canonical conversation scope.
public enum LocalIDKind: String, Codable, Sendable, CaseIterable {
  // Bots share user numbers; channels, groups and communities share chat numbers.
  case user, chat, monoforum, file, stickerSet, poll, topic, message, dc, authorization

  public var firstID: Int64 {
    switch self {
    case .user: 1_000_000
    case .monoforum: 1_002_147_483_649
    case .dc: 2  // DC1 is always this namespace's own home.
    default: 1
    }
  }
  public var upperBound: Int64 {
    switch self {
    case .chat: 997_852_516_352
    case .monoforum: 3_000_000_000_000
    case .message, .topic, .dc: Int64(Int32.max)
    case .file, .stickerSet, .poll, .authorization: Int64.max
    default: 9_007_199_254_740_991
    }
  }
  public func validate(scope: [UInt8]) throws {
    guard (self == .message || self == .topic || self == .authorization) ? scope.count == 32 : scope.isEmpty else {
      throw FederationError.invalidReference
    }
  }
}

/// Exact canonical bytes are the durable identity. Local access hashes, DC
/// numbers, message-box numbers and caches are deliberately absent.
public struct CanonicalReference: Sendable, Equatable, Hashable {
  public let kind: LocalIDKind
  public let encoding: [UInt8]
  public let scope: [UInt8]

  private init(kind: LocalIDKind, value: CBOR, scope: [UInt8] = []) {
    self.kind = kind
    self.scope = scope
    encoding = value.encode()
  }
  /// One hosting of an identity. A new home epoch is a new account, so its
  /// reference never resolves to the alias an earlier hosting had.
  public static func identity(_ id: [UInt8], kind: HomeDelegation.Kind = .user, epoch: UInt64) throws
    -> Self
  {
    guard id.count == 32, epoch > 0, epoch <= UInt64(Int64.max) else { throw FederationError.invalidReference }
    return Self(
      kind: kind.localIDKind,
      value: .array([
        .unsignedInt(BlahDiemTag.reference.rawValue), .unsignedInt(1), .unsignedInt(BlahReferenceTag.identity.rawValue),
        .unsignedInt(kind.wireCode), .byteString(id[...]), .unsignedInt(epoch),
      ]))
  }
  public static func authority(_ keyID: [UInt8]) throws -> Self {
    guard keyID.count == 32 else { throw FederationError.invalidReference }
    return Self(
      kind: .dc,
      value: .array([
        .unsignedInt(BlahDiemTag.reference.rawValue), .unsignedInt(1), .unsignedInt(BlahReferenceTag.authority.rawValue),
        .byteString(keyID[...]),
      ]))
  }
  public static func object(
    authority: [UInt8], kind: LocalIDKind, originID: Int64, generation: UInt64,
    scope: [UInt8] = []
  ) throws -> Self {
    try kind.validate(scope: scope)
    guard authority.count == 32, originID > 0, originID < kind.upperBound,
      generation > 0, kind != .dc, kind != .message, kind != .authorization,
      kind != .monoforum || originID >= kind.firstID
    else { throw FederationError.invalidReference }
    return Self(
      kind: kind,
      value: .array([
        .unsignedInt(BlahDiemTag.reference.rawValue), .unsignedInt(1), .unsignedInt(BlahReferenceTag.object.rawValue),
        .byteString(authority[...]), .unsignedInt(kind.wireCode), .unsignedInt(UInt64(originID)),
        .unsignedInt(generation), .byteString(scope[...]),
      ]), scope: scope)
  }
  public static func conversation(participants: [[UInt8]]) throws -> Self {
    guard (1...2).contains(participants.count), participants.allSatisfy({ $0.count == 32 }),
      Set(participants).count == participants.count
    else { throw FederationError.invalidReference }
    let sorted = participants.sorted { $0.lexicographicallyPrecedes($1) }
    return Self(
      kind: .chat,
      value: .array([
        .unsignedInt(BlahDiemTag.reference.rawValue), .unsignedInt(1), .unsignedInt(BlahReferenceTag.conversation.rawValue),
        .array(sorted.map { .byteString($0[...]) }),
      ]))
  }
  public static func event(conversation: [UInt8], epoch: UInt64, id: [UInt8]) throws -> Self {
    guard conversation.count == 32, epoch > 0, id.count == 32 else {
      throw FederationError.invalidReference
    }
    return Self(
      kind: .message,
      value: .array([
        .unsignedInt(BlahDiemTag.reference.rawValue), .unsignedInt(1), .unsignedInt(BlahReferenceTag.event.rawValue),
        .byteString(conversation[...]), .unsignedInt(epoch), .byteString(id[...]),
      ]), scope: conversation)
  }
  /// A login incarnation, distinct even when the same device and transport key
  /// sign in again. Its wire hash is only a local, account-scoped lookup handle.
  public static func authorization(
    authority: [UInt8], generation: UInt64, actor: [UInt8], device: [UInt8], incarnation: [UInt8]
  ) throws -> Self {
    guard authority.count == 32, generation > 0, generation <= UInt64(Int64.max),
      actor.count == 32, device.count == 32, incarnation.count == 32 else {
      throw FederationError.invalidReference
    }
    return Self(kind: .authorization, value: .array([
      .unsignedInt(BlahDiemTag.reference.rawValue), .unsignedInt(1), .unsignedInt(BlahReferenceTag.authorization.rawValue),
      .byteString(authority[...]), .unsignedInt(generation), .byteString(actor[...]),
      .byteString(device[...]), .byteString(incarnation[...]),
    ]), scope: SoftwareDeviceCrypto().sha256(actor))
  }
  public var digest: [UInt8] { SoftwareDeviceCrypto().sha256(encoding) }

  /// Only a Diem identity can be resolved through a public profile. Local bots
  /// and other authority-scoped objects deliberately have no identity here.
  public var identityID: [UInt8]? { hosting?.identity }

  /// The identity and the home epoch whose account this reference names.
  public var hosting: (identity: [UInt8], epoch: UInt64)? {
    guard case .array(let a) = try? CanonicalCBOR.decode(encoding), a.count == 6,
      a[2] == .unsignedInt(BlahReferenceTag.identity.rawValue), case .byteString(let id) = a[4], case .unsignedInt(let epoch) = a[5]
    else { return nil }
    return (Array(id), epoch)
  }

  /// Immutable owner coordinates for a DC-allocated object. The origin number
  /// is meaningful only at this authority and generation, never at a receiver.
  public var objectOrigin: (authority: [UInt8], id: Int64, generation: UInt64)? {
    guard case .array(let a) = try? CanonicalCBOR.decode(encoding), a.count == 8,
      a[2] == .unsignedInt(BlahReferenceTag.object.rawValue), case .byteString(let authority) = a[3],
      case .unsignedInt(let id) = a[5], case .unsignedInt(let generation) = a[6]
    else { return nil }
    return (Array(authority), Int64(id), generation)
  }

  public static func decode(_ bytes: [UInt8]) throws -> Self {
    guard case .array(let a) = try CanonicalCBOR.decode(bytes), a.count >= 4,
      a[0] == .unsignedInt(BlahDiemTag.reference.rawValue), a[1] == .unsignedInt(1),
      case .unsignedInt(let tagNumber) = a[2], let tag = BlahReferenceTag(rawValue: tagNumber)
    else { throw FederationError.invalidReference }
    let result: Self
    switch tag {
    case .authorization:
      guard a.count == 8, case .byteString(let authority) = a[3],
        case .unsignedInt(let generation) = a[4], case .byteString(let actor) = a[5],
        case .byteString(let device) = a[6], case .byteString(let incarnation) = a[7]
      else { throw FederationError.invalidReference }
      result = try .authorization(authority: Array(authority), generation: generation,
        actor: Array(actor), device: Array(device), incarnation: Array(incarnation))
    case .identity:
      guard a.count == 6, case .unsignedInt(let name) = a[3],        let kind = HomeDelegation.Kind(wireCode: name), case .byteString(let id) = a[4],
        case .unsignedInt(let epoch) = a[5]
      else { throw FederationError.invalidReference }
      result = try .identity(Array(id), kind: kind, epoch: epoch)
    case .authority:
      guard a.count == 4, case .byteString(let key) = a[3] else {
        throw FederationError.invalidReference
      }
      result = try .authority(Array(key))
    case .object:
      guard a.count == 8, case .byteString(let authority) = a[3],
        case .unsignedInt(let name) = a[4], let kind = LocalIDKind(wireCode: name),
        case .unsignedInt(let id) = a[5], id <= UInt64(Int64.max),
        case .unsignedInt(let generation) = a[6], case .byteString(let scope) = a[7]
      else { throw FederationError.invalidReference }
      result = try .object(
        authority: Array(authority), kind: kind, originID: Int64(id),
        generation: generation, scope: Array(scope))
    case .conversation:
      guard a.count == 4, case .array(let ids) = a[3] else {
        throw FederationError.invalidReference
      }
      result = try .conversation(
        participants: ids.map {
          guard case .byteString(let id) = $0 else { throw FederationError.invalidReference }
          return Array(id)
        })
    case .event:
      guard a.count == 6, case .byteString(let conversation) = a[3],
        case .unsignedInt(let epoch) = a[4], case .byteString(let id) = a[5]
      else { throw FederationError.invalidReference }
      result = try .event(conversation: Array(conversation), epoch: epoch, id: Array(id))
    }
    guard result.encoding == bytes else { throw FederationError.invalidReference }
    return result
  }
}

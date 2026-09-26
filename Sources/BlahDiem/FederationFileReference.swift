import Foundation

/// A durable file binding and its descriptor. File bytes stay with the
/// canonical owner; receiving a descriptor cannot replace local backing bytes.
public struct FederationFileReference: Sendable, Equatable {
  public struct Descriptor: Sendable, Equatable, Codable {
    public let kind: String
    public let mimeType: String
    public let size: Int64
    public let name: String?
    public let fileReference: Data
    public let width: Int32?
    public let height: Int32?
    public let voiceDuration: Int32?
    public let voiceWaveform: Data?
    public let roundVideoDuration: Double?
    public let documentAttributes: Data?
    /// Set membership in the manifest's own sticker-set numbering. It seeds a
    /// receiver's first view of the document; the set's owner stays authoritative.
    public let stickerSetID: Int64?
    public let stickerAlt: String?

    public init(kind: String, mimeType: String, size: Int64, name: String?, fileReference: Data,
      width: Int32?, height: Int32?, voiceDuration: Int32?, voiceWaveform: Data?,
      roundVideoDuration: Double?, documentAttributes: Data?,
      stickerSetID: Int64? = nil, stickerAlt: String? = nil) throws {
      self.kind = kind; self.mimeType = mimeType; self.size = size; self.name = name
      self.fileReference = fileReference; self.width = width; self.height = height
      self.voiceDuration = voiceDuration; self.voiceWaveform = voiceWaveform
      self.roundVideoDuration = roundVideoDuration; self.documentAttributes = documentAttributes
      self.stickerSetID = stickerSetID; self.stickerAlt = stickerAlt
      try validate()
    }
    func validate() throws {
      guard ["photo", "document"].contains(kind), size >= 0, mimeType.utf8.count <= 256,
        (name?.utf8.count ?? 0) <= 4096, fileReference.count <= 1024,
        [width, height, voiceDuration].allSatisfy({ $0.map { $0 >= 0 } ?? true }),
        (voiceWaveform?.count ?? 0) <= 4096, (documentAttributes?.count ?? 0) <= 16384,
        roundVideoDuration.map({ $0.isFinite && $0 >= 0 }) ?? true,
        (stickerSetID == nil) == (stickerAlt == nil), kind == "document" || stickerSetID == nil,
        stickerSetID.map({ $0 > 0 && $0 < LocalIDKind.stickerSet.upperBound }) ?? true,
        stickerAlt.map({ (1...64).contains($0.utf8.count) }) ?? true
      else { throw FederationError.invalidReference }
    }
    var cbor: CBOR {
      func number(_ value: Int32?) -> CBOR {
        value.map { .unsignedInt(UInt64($0)) } ?? .null
      }
      func data(_ value: Data?) -> CBOR { value.map { .byteString(Array($0)[...]) } ?? .null }
      return .array([
        .unsignedInt(kind == "photo" ? 1 : 2), .textString(mimeType), .unsignedInt(UInt64(size)),
        name.map(CBOR.textString) ?? .null, .byteString(Array(fileReference)[...]),
        number(width), number(height), number(voiceDuration), data(voiceWaveform),
        roundVideoDuration.map { .unsignedInt($0.bitPattern) } ?? .null,
        data(documentAttributes), stickerSetID.map { .unsignedInt(UInt64($0)) } ?? .null,
        stickerAlt.map(CBOR.textString) ?? .null,
      ])
    }
    init(cbor value: CBOR) throws {
      guard case .array(let a) = value, a.count == 13,
        case .unsignedInt(let kindCode) = a[0], (1...2).contains(kindCode),
        case .textString(let mimeType) = a[1],
        case .unsignedInt(let size) = a[2], size <= UInt64(Int64.max),
        case .byteString(let fileReference) = a[4]
      else { throw FederationError.invalidReference }
      func text(_ value: CBOR) throws -> String? {
        if value == .null { return nil }
        guard case .textString(let text) = value else { throw FederationError.invalidReference }
        return text
      }
      func number(_ value: CBOR) throws -> Int32? {
        if value == .null { return nil }
        guard case .unsignedInt(let n) = value, n <= UInt64(Int32.max) else {
          throw FederationError.invalidReference
        }
        return Int32(n)
      }
      func data(_ value: CBOR) throws -> Data? {
        if value == .null { return nil }
        guard case .byteString(let bytes) = value else { throw FederationError.invalidReference }
        return Data(bytes)
      }
      func int64(_ value: CBOR) throws -> Int64? {
        if value == .null { return nil }
        guard case .unsignedInt(let n) = value, n <= UInt64(Int64.max) else {
          throw FederationError.invalidReference
        }
        return Int64(n)
      }
      let duration: Double?
      if a[9] == .null { duration = nil }
      else if case .unsignedInt(let bits) = a[9] { duration = Double(bitPattern: bits) }
      else { throw FederationError.invalidReference }
      try self.init(kind: kindCode == 1 ? "photo" : "document", mimeType: mimeType,
        size: Int64(size), name: text(a[3]), fileReference: Data(fileReference),
        width: number(a[5]), height: number(a[6]), voiceDuration: number(a[7]),
        voiceWaveform: data(a[8]), roundVideoDuration: duration,
        documentAttributes: data(a[10]), stickerSetID: int64(a[11]), stickerAlt: text(a[12]))
    }
  }
  public let localID: Int64
  public let canonical: CanonicalReference
  public let ownerUserID: Int64
  public let descriptor: Descriptor
  public init(localID: Int64, canonical: CanonicalReference, ownerUserID: Int64, descriptor: Descriptor) throws {
    guard localID > 0, localID < LocalIDKind.file.upperBound, canonical.kind == .file,
      canonical.objectOrigin != nil, ownerUserID > 0, ownerUserID < LocalIDKind.user.upperBound
    else { throw FederationError.invalidReference }
    try descriptor.validate()
    self.localID = localID; self.canonical = canonical; self.ownerUserID = ownerUserID; self.descriptor = descriptor
  }
  var cbor: CBOR {
    .array([.unsignedInt(UInt64(localID)), .byteString(canonical.encoding[...]),
      .unsignedInt(UInt64(ownerUserID)), descriptor.cbor])
  }
  static func decode(_ value: CBOR) throws -> Self {
    guard case .array(let fields) = value, fields.count == 4,
      case .unsignedInt(let id) = fields[0], id < UInt64(Int64.max),
      case .byteString(let canonical) = fields[1],
      case .unsignedInt(let owner) = fields[2], owner < UInt64(Int64.max)
    else { throw FederationError.invalidReference }
    return try .init(localID: Int64(id), canonical: .decode(Array(canonical)), ownerUserID: Int64(owner),
      descriptor: Descriptor(cbor: fields[3]))
  }
}

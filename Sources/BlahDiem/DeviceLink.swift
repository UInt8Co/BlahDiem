/// The public keys and capabilities of a device asking to join an existing account.
public struct DeviceLinkRequest: Sendable {
  public static let cborKeyTag: UInt64 = 0
  public static let cborKeyVersion: UInt64 = 1
  public static let cborKeyDevice: UInt64 = 2
  public static let cborKeyRecipient: UInt64 = 3
  public static let cborKeyLabel: UInt64 = 4
  public static let cborKeyVerifies: UInt64 = 5
  public static let maximumBytes = 4096

  public let device: DevicePublicKey
  public let recipient: EncryptionPublicKey
  /// Untrusted display text, between 1 and 64 UTF-8 bytes.
  public let label: String
  public let verifies: [PublicKey.Algorithm]
  private var extensions: [UInt64: CBOR] = [:]

  public init(device: DevicePublicKey, recipient: EncryptionPublicKey, label: String,
    verifies: [PublicKey.Algorithm]) throws {
    guard (1...64).contains(label.utf8.count), !verifies.isEmpty,
      Set(verifies).count == verifies.count else { throw BlahError.invalidDeviceLink }
    guard recipient.algorithm == .p256 else { throw DiemError.unsupportedAlgorithm }
    self.device = device; self.recipient = recipient; self.label = label; self.verifies = verifies
    guard encoding.count <= Self.maximumBytes else { throw BlahError.invalidDeviceLink }
  }

  public init(encoding: [UInt8]) throws {
    guard encoding.count <= Self.maximumBytes else { throw BlahError.invalidDeviceLink }
    let fields = try CBOR.record(encoding, tag: .deviceLinkRequest, requiredKeys: 0..<6, error: .invalidDeviceLink)
    try self.init(device: DevicePublicKey(PublicKey(encoding: fields[2]!.bytesValue())),
      recipient: EncryptionPublicKey(encoding: fields[3]!.bytesValue()), label: fields[4]!.textValue(),
      verifies: fields[5]!.arrayValue().map {
        guard let algorithm = PublicKey.Algorithm(rawValue: try $0.unsignedValue()) else {
          throw DiemError.unsupportedAlgorithm
        }
        return algorithm
      })
    extensions = fields.filter { $0.key > Self.cborKeyVerifies }
  }

  public var encoding: [UInt8] {
    CBOR.record([0: .unsigned(BlahTag.deviceLinkRequest.rawValue), 1: .unsigned(1),
      2: .bytes(device.key.encoding), 3: .bytes(recipient.encoding), 4: .text(label),
      5: .array(verifies.map { .unsigned($0.rawValue) })], extensions: extensions).encoded
  }

  /// SHA-256 of the exact canonical request, including unrecognized fields.
  public var digest: Digest { Digest(hashing: encoding) }

  /// Call before certifying the new device with the approving identity and device keys.
  public func requireCompatible(identityKey: IdentityPublicKey, device: DevicePublicKey) throws {
    guard verifies.contains(identityKey.key.algorithm), verifies.contains(device.key.algorithm) else {
      throw DiemError.unsupportedAlgorithm
    }
  }
}

/// The QR-only binding between a request and the response's HPKE context.
public struct DeviceLinkCode: Sendable {
  public static let cborKeyTag: UInt64 = 0
  public static let cborKeyVersion: UInt64 = 1
  public static let cborKeyRequestDigest: UInt64 = 2
  public static let cborKeySecret: UInt64 = 3
  public static let maximumBytes = 4096

  public let requestDigest: Digest
  public let secret: [UInt8]
  private var extensions: [UInt64: CBOR] = [:]

  public init(requestDigest: Digest, secret: [UInt8]) throws {
    guard secret.count == 16 else { throw BlahError.invalidDeviceLink }
    self.requestDigest = requestDigest; self.secret = secret
  }

  public init(request: DeviceLinkRequest, using backend: some CryptoBackend) throws {
    try self.init(requestDigest: request.digest, secret: backend.randomBytes(count: 16))
  }

  public init(encoding: [UInt8]) throws {
    guard encoding.count <= Self.maximumBytes else { throw BlahError.invalidDeviceLink }
    let fields = try CBOR.record(encoding, tag: .deviceLinkCode, requiredKeys: 0..<4, error: .invalidDeviceLink)
    try self.init(requestDigest: Digest(bytes: fields[2]!.bytesValue()), secret: fields[3]!.bytesValue())
    extensions = fields.filter { $0.key > Self.cborKeySecret }
  }

  public var encoding: [UInt8] {
    CBOR.record([0: .unsigned(BlahTag.deviceLinkCode.rawValue), 1: .unsigned(1),
      2: .bytes(requestDigest.bytes), 3: .bytes(secret)], extensions: extensions).encoded
  }

  /// Unpadded base64url, for the `blah` URL parameter. Never send it to the DC.
  public var parameter: String { LinkBase64.encode(encoding) }

  public init(parameter: String) throws {
    try self.init(encoding: LinkBase64.decode(parameter, maximumBytes: Self.maximumBytes))
  }

  /// Check the exact received bytes before decoding or acting on a request.
  public func matches(_ requestBytes: [UInt8]) -> Bool {
    guard requestBytes.count <= DeviceLinkRequest.maximumBytes else { return false }
    let digest = SHA2.sha256(requestBytes)
    var difference: UInt8 = 0
    for index in 0..<32 { difference |= requestDigest.bytes[index] ^ digest[index] }
    return difference == 0
  }
}

/// Canonical HPKE info and associated data for a device-link response.
public struct DeviceLinkContext: Sendable {
  public static let cborKeyTag: UInt64 = 0
  public static let cborKeyVersion: UInt64 = 1
  public static let cborKeyRequestDigest: UInt64 = 2
  public static let cborKeySecret: UInt64 = 3
  public static let maximumBytes = 4096

  public let requestDigest: Digest
  public let secret: [UInt8]
  private var extensions: [UInt64: CBOR] = [:]

  public init(requestDigest: Digest, secret: [UInt8]) throws {
    guard secret.count == 16 else { throw BlahError.invalidDeviceLink }
    self.requestDigest = requestDigest; self.secret = secret
  }

  public init(code: DeviceLinkCode) {
    requestDigest = code.requestDigest; secret = code.secret
  }

  public init(encoding: [UInt8]) throws {
    guard encoding.count <= Self.maximumBytes else { throw BlahError.invalidDeviceLink }
    let fields = try CBOR.record(encoding, tag: .deviceLinkContext, requiredKeys: 0..<4, error: .invalidDeviceLink)
    try self.init(requestDigest: Digest(bytes: fields[2]!.bytesValue()), secret: fields[3]!.bytesValue())
    extensions = fields.filter { $0.key > Self.cborKeySecret }
  }

  public var encoding: [UInt8] {
    CBOR.record([0: .unsigned(BlahTag.deviceLinkContext.rawValue), 1: .unsigned(1),
      2: .bytes(requestDigest.bytes), 3: .bytes(secret)], extensions: extensions).encoded
  }
}

/// The signed, published profile and optional identity custody, visible only to the new device.
public struct DeviceLinkGrant: Sendable {
  public static let cborKeyTag: UInt64 = 0
  public static let cborKeyVersion: UInt64 = 1
  public static let cborKeyProfile: UInt64 = 2
  public static let cborKeyDomain: UInt64 = 3
  public static let cborKeyIdentityKey: UInt64 = 4
  public static let cborKeyMetadata: UInt64 = 5
  public static let maximumBytes = 65_536
  public static let maximumMetadataBytes = 16_384

  /// The exact signed profile bytes published by the approving device.
  public let profile: [UInt8]
  public let domain: DomainName
  public let identityKey: SealedIdentityKey?
  public let metadata: [UInt8]?
  private var extensions: [UInt64: CBOR] = [:]

  public init(profile: [UInt8], domain: DomainName, identityKey: SealedIdentityKey? = nil,
    metadata: [UInt8]? = nil) throws {
    guard metadata == nil || identityKey != nil,
      (metadata?.count ?? 0) <= Self.maximumMetadataBytes else { throw BlahError.invalidDeviceLink }
    _ = try AnyBlahProfile(encoding: profile)
    self.profile = profile; self.domain = domain; self.identityKey = identityKey; self.metadata = metadata
    guard encoding.count <= Self.maximumBytes else { throw BlahError.invalidDeviceLink }
  }

  public init(profile: AnyBlahProfile, domain: DomainName, identityKey: SealedIdentityKey? = nil,
    metadata: [UInt8]? = nil) throws {
    try self.init(profile: profile.encoding, domain: domain, identityKey: identityKey, metadata: metadata)
  }

  public init(encoding: [UInt8]) throws {
    guard encoding.count <= Self.maximumBytes else { throw BlahError.invalidDeviceLink }
    let fields = try CBOR.record(encoding, tag: .deviceLinkGrant, requiredKeys: 0..<4, error: .invalidDeviceLink)
    try self.init(profile: fields[2]!.bytesValue(),
      domain: DomainName(fields[3]!.textValue()),
      identityKey: fields[4].map { try SealedIdentityKey(encoding: $0.bytesValue()) },
      metadata: fields[5].map { try $0.bytesValue() })
    extensions = fields.filter { $0.key > Self.cborKeyMetadata }
  }

  public var encoding: [UInt8] {
    var fields: [UInt64: CBOR] = [0: .unsigned(BlahTag.deviceLinkGrant.rawValue), 1: .unsigned(1),
      2: .bytes(profile), 3: .text(domain.name)]
    if let identityKey { fields[4] = .bytes(identityKey.encoding) }
    if let metadata { fields[5] = .bytes(metadata) }
    return CBOR.record(fields, extensions: extensions).encoded
  }

  /// Requires current published authority for this device at an allocated user account.
  public func verify(for request: DeviceLinkRequest, expectedDC: Digest? = nil, at time: UInt64? = nil,
    using backend: some CryptoBackend) async throws {
    let time = time ?? backend.now
    let profile = try AnyBlahProfile(encoding: profile)
    try await profile.verify(using: backend, at: time)
    guard case .user = profile else { throw BlahError.invalidProfile }
    guard let home = profile.home, home.account != nil, home.isActive(at: time),
      expectedDC == nil || home.dc == expectedDC else { throw BlahError.wrongHome }
    guard profile.domains.contains(domain) else { throw BlahError.invalidName }
    guard profile.devices.contains(where: {
      $0.device == request.device && $0.generation == profile.generation && $0.validity.contains(time)
    }) else { throw DiemError.deviceNotListed }
    try request.requireCompatible(identityKey: profile.identityKey, device: profile.record.signer)
    if let identityKey {
      guard identityKey.identityKey == profile.identityKey,
        identityKey.recipient == request.recipient else { throw DiemError.identityMismatch }
    }
  }
}

/// A bounded Diem HPKE box: canonical CBOR `{0: encapsulatedKey, 1: ciphertext}`.
public enum DeviceLinkResponse {
  public static let cborKeyEncapsulatedKey: UInt64 = 0
  public static let cborKeyCiphertext: UInt64 = 1
  public static let maximumBytes = 65_536

  /// A grant whose profile and optional identity custody have both been verified.
  public struct Opened: Sendable {
    public let grant: DeviceLinkGrant
    public let profile: AnyBlahProfile
    public let identityKey: IdentityPrivateKey?
  }

  public static func seal(_ grant: DeviceLinkGrant, for request: DeviceLinkRequest,
    code: DeviceLinkCode, using backend: some CryptoBackend) async throws -> [UInt8] {
    guard code.matches(request.encoding) else { throw BlahError.invalidDeviceLink }
    try await grant.verify(for: request, using: backend)
    let box = try await backend.seal(grant.encoding, to: request.recipient,
      context: DeviceLinkContext(code: code).encoding)
    let bytes = CBOR.record([cborKeyEncapsulatedKey: .bytes(box.encapsulatedKey),
      cborKeyCiphertext: .bytes(box.ciphertext)]).encoded
    guard bytes.count <= maximumBytes else { throw BlahError.invalidDeviceLink }
    return bytes
  }

  public static func open(_ bytes: [UInt8], recipientKey: EncryptionPrivateKey,
    request: DeviceLinkRequest, code: DeviceLinkCode, expectedDC: Digest? = nil,
    at time: UInt64? = nil, using backend: some CryptoBackend) async throws -> Opened {
    guard bytes.count <= maximumBytes, code.matches(request.encoding) else { throw BlahError.invalidDeviceLink }
    guard recipientKey.publicKey == request.recipient else { throw DiemError.identityMismatch }
    let fields = try CBOR(decoding: bytes).recordValue(requiredKeys: 0..<2)
    let box = try SealedBox(encapsulatedKey: fields[cborKeyEncapsulatedKey]!.bytesValue(count: 65),
      ciphertext: fields[cborKeyCiphertext]!.bytesValue())
    guard box.encapsulatedKey.first == 4, box.ciphertext.count >= 16 else { throw BlahError.invalidDeviceLink }
    var plaintext = try await recipientKey.open(box, context: DeviceLinkContext(code: code).encoding)
    defer { plaintext = [UInt8](repeating: 0, count: plaintext.count) }
    let grant = try DeviceLinkGrant(encoding: plaintext)
    try await grant.verify(for: request, expectedDC: expectedDC, at: time, using: backend)
    let profile = try AnyBlahProfile(encoding: grant.profile)
    let key = try await grant.identityKey?.open(with: recipientKey, using: backend)
    guard key == nil || key?.publicKey == profile.identityKey else { throw DiemError.identityMismatch }
    return Opened(grant: grant, profile: profile, identityKey: key)
  }
}

private enum LinkBase64 {
  static let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".utf8)

  static func encode(_ bytes: [UInt8]) -> String {
    var result: [UInt8] = []
    var accumulator: UInt32 = 0
    var bits = 0
    for byte in bytes {
      accumulator = (accumulator << 8) | UInt32(byte); bits += 8
      while bits >= 6 { bits -= 6; result.append(alphabet[Int((accumulator >> bits) & 63)]) }
    }
    if bits > 0 { result.append(alphabet[Int((accumulator << (6 - bits)) & 63)]) }
    return String(decoding: result, as: UTF8.self)
  }

  static func decode(_ text: String, maximumBytes: Int) throws -> [UInt8] {
    guard text.utf8.count <= (maximumBytes * 4 + 2) / 3, text.utf8.count % 4 != 1 else {
      throw BlahError.invalidDeviceLink
    }
    var result: [UInt8] = []
    var accumulator: UInt32 = 0
    var bits = 0
    for byte in text.utf8 {
      guard let value = alphabet.firstIndex(of: byte) else { throw BlahError.invalidDeviceLink }
      accumulator = (accumulator << 6) | UInt32(value); bits += 6
      if bits >= 8 { bits -= 8; result.append(UInt8(truncatingIfNeeded: accumulator >> bits)) }
    }
    guard accumulator & ((1 << bits) - 1) == 0 else { throw BlahError.invalidDeviceLink }
    return result
  }
}

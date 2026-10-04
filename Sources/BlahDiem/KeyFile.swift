/// Exportable signing material. The public key carries its algorithm and purpose.
public struct KeyFilePrivateKey: Sendable {
  public static let cborKeyTag: UInt64 = 0
  public static let cborKeyVersion: UInt64 = 1
  public static let cborKeyPublicKey: UInt64 = 2
  public static let cborKeySecret: UInt64 = 3

  public let publicKey: PublicKey
  public let secret: [UInt8]

  public init(publicKey: PublicKey, secret: [UInt8]) throws {
    guard !secret.isEmpty, secret.count <= 8192 else { throw DiemError.invalidKey }
    self.publicKey = publicKey
    self.secret = secret
  }

  public init(encoding: [UInt8]) throws {
    let fields = try CBOR.record(encoding, tag: .privateKey, requiredKeys: 0..<4, error: .invalidProfile)
    try self.init(publicKey: PublicKey(encoding: fields[2]!.bytesValue()), secret: fields[3]!.bytesValue())
  }

  public var encoding: [UInt8] {
    CBOR.record([0: .unsigned(BlahTag.privateKey.rawValue), 1: .unsigned(1),
      2: .bytes(publicKey.encoding), 3: .bytes(secret)]).encoded
  }
}

/// A recovery key, a listed device key, or both, together with their signed profile.
/// Metadata is an encrypted application-owned CBOR map, never identity authority.
public struct KeyFileContents: Sendable {
  public static let cborKeyTag: UInt64 = 0
  public static let cborKeyVersion: UInt64 = 1
  public static let cborKeyProfile: UInt64 = 2
  public static let cborKeyKeys: UInt64 = 3
  public static let cborKeyMetadata: UInt64 = 4

  public let profile: Profile
  public let keys: [KeyFilePrivateKey]
  public let metadata: CBOR

  public init(profile: Profile, keys: [KeyFilePrivateKey], metadata: CBOR = .map([:])) throws {
    guard (1...2).contains(keys.count), case .map = metadata,
      Set(keys.map { $0.publicKey.purpose }).count == keys.count else { throw DiemError.invalidKey }
    for key in keys {
      switch key.publicKey.purpose {
      case .identity:
        guard key.publicKey == profile.identityKey.key else { throw DiemError.identityMismatch }
      case .device:
        guard profile.devices.contains(where: { $0.device.key == key.publicKey }) else {
          throw DiemError.deviceNotListed
        }
      }
    }
    self.profile = profile
    self.keys = keys
    self.metadata = metadata
    _ = try metadata.recordValue(requiredKeys: 0..<0)
    guard encoding.count <= 200_000 else { throw DiemError.invalidEncoding }
  }

  public init(encoding: [UInt8]) throws {
    let fields = try CBOR.record(encoding, tag: .keyFileContents, requiredKeys: 0..<5, error: .invalidProfile)
    try self.init(profile: Profile(encoding: fields[2]!.bytesValue()),
      keys: fields[3]!.arrayValue().map { try KeyFilePrivateKey(encoding: $0.bytesValue()) },
      metadata: fields[4]!)
  }

  public var encoding: [UInt8] {
    CBOR.record([0: .unsigned(BlahTag.keyFileContents.rawValue), 1: .unsigned(1),
      2: .bytes(profile.encoding), 3: .array(keys.map { .bytes($0.encoding) }), 4: metadata]).encoded
  }

  /// Checks signatures and private/public correspondence. Expired profiles remain recoverable;
  /// applications still require current published authority before login.
  public func validate(using backend: some CryptoBackend) async throws {
    _ = try AnyBlahProfile(profile)
    try await profile.verify(using: backend, at: profile.validity.notBefore)
    for key in keys {
      let restored = try await backend.makePrivateKey(key.publicKey.algorithm,
        for: key.publicKey.purpose, restoring: key.secret)
      guard restored.publicKey == key.publicKey else { throw DiemError.identityMismatch }
    }
  }
}

/// Password-protected HPKE custody, shared by native clients, browsers and DC setup.
/// Version one uses PBKDF2-HMAC-SHA256 (600,000 rounds), RFC 9180 P-256 DeriveKeyPair,
/// and Diem's P-256/HKDF-SHA256/AES-256-GCM base-mode suite.
public struct KeyFile: Sendable {
  public static let cborKeyTag: UInt64 = 0
  public static let cborKeyVersion: UInt64 = 1
  public static let cborKeyIdentityID: UInt64 = 2
  public static let cborKeySalt: UInt64 = 3
  public static let cborKeyKDF: UInt64 = 4
  public static let cborKeyIterations: UInt64 = 5
  public static let cborKeyRecipient: UInt64 = 6
  public static let cborKeyEncapsulatedKey: UInt64 = 7
  public static let cborKeyCiphertext: UInt64 = 8
  public static let iterations: UInt32 = 600_000
  public static let maximumBytes = CBOR.maximumBytes

  public let identityID: Digest
  public let salt: [UInt8]
  public let recipient: EncryptionPublicKey
  public let box: SealedBox
  private let fields: [UInt64: CBOR]

  public init(encoding: [UInt8]) throws {
    let fields = try CBOR.record(encoding, tag: .keyFile, requiredKeys: 0..<9, error: .invalidProfile)
    guard fields[4] == .unsigned(1), fields[5] == .unsigned(UInt64(Self.iterations)) else {
      throw DiemError.invalidEncoding
    }
    identityID = try Digest(bytes: fields[2]!.bytesValue(count: 32))
    salt = try fields[3]!.bytesValue(count: 16)
    recipient = try EncryptionPublicKey(encoding: fields[6]!.bytesValue())
    guard recipient.algorithm == .p256 else { throw DiemError.unsupportedAlgorithm }
    let encapsulated = try fields[7]!.bytesValue(count: 65)
    let ciphertext = try fields[8]!.bytesValue()
    guard encapsulated.first == 4, (16...200_016).contains(ciphertext.count) else {
      throw DiemError.invalidEncoding
    }
    box = SealedBox(encapsulatedKey: encapsulated, ciphertext: ciphertext)
    self.fields = fields
  }

  public var encoding: [UInt8] { CBOR.record(fields).encoded }

  private var context: [UInt8] {
    CBOR.record(fields.filter { $0.key != Self.cborKeyEncapsulatedKey && $0.key != Self.cborKeyCiphertext }).encoded
  }

  public static func seal(_ contents: KeyFileContents, salt: [UInt8],
    to recipient: EncryptionPublicKey, using backend: some CryptoBackend) async throws -> Self {
    guard salt.count == 16, recipient.algorithm == .p256 else { throw DiemError.invalidKey }
    try await contents.validate(using: backend)
    var fields: [UInt64: CBOR] = [0: .unsigned(BlahTag.keyFile.rawValue), 1: .unsigned(1),
      2: .bytes(contents.profile.id.bytes), 3: .bytes(salt), 4: .unsigned(1),
      5: .unsigned(UInt64(iterations)), 6: .bytes(recipient.encoding)]
    let box = try await backend.seal(contents.encoding, to: recipient, context: CBOR.record(fields).encoded)
    fields[7] = .bytes(box.encapsulatedKey)
    fields[8] = .bytes(box.ciphertext)
    return try Self(encoding: CBOR.record(fields).encoded)
  }

  public func open(with key: EncryptionPrivateKey, using backend: some CryptoBackend) async throws -> KeyFileContents {
    guard key.publicKey == recipient else { throw DiemError.decryptionFailed }
    var plaintext = try await key.open(box, context: context)
    defer { plaintext = [UInt8](repeating: 0, count: plaintext.count) }
    let contents = try KeyFileContents(encoding: plaintext)
    guard contents.profile.id == identityID else { throw DiemError.identityMismatch }
    try await contents.validate(using: backend)
    return contents
  }

  /// The platform supplies PBKDF2; the format owns password encoding, parameters and
  /// deterministic RFC 9180 recipient derivation. Passwords are used as exact UTF-8.
  public static func passwordRecipient(_ password: String, salt: [UInt8], using backend: some CryptoBackend,
    pbkdf2: @Sendable ([UInt8], [UInt8], UInt32) async throws -> [UInt8]) async throws -> EncryptionPrivateKey {
    guard !password.isEmpty, salt.count == 16 else { throw DiemError.invalidKey }
    var material = try await pbkdf2(Array(password.utf8), salt, iterations)
    defer { material = [UInt8](repeating: 0, count: material.count) }
    guard material.count == 32 else { throw DiemError.invalidKey }
    var raw = try deriveP256PrivateKey(material)
    defer { raw = [UInt8](repeating: 0, count: raw.count) }
    return try await backend.makeEncryptionKey(.p256, restoring: raw)
  }

  // RFC 9180 §7.1.3. Kept in the format owner so native password adapters only
  // provide PBKDF2. Web/recovery-key.js implements the same derivation for WebCrypto.
  static func deriveP256PrivateKey(_ material: [UInt8]) throws -> [UInt8] {
    let suite = Array("HPKE-v1KEM".utf8) + [0, 16]
    let prk = hmac([], suite + Array("dkp_prk".utf8) + material)
    let order: [UInt8] = [255,255,255,255,0,0,0,0,255,255,255,255,255,255,255,255,
      188,230,250,173,167,23,158,132,243,185,202,194,252,99,37,81]
    for counter in UInt16(0)...255 {
      let candidate = hmac(prk, [0, 32] + suite + Array("candidate".utf8) + [UInt8(counter), 1])
      if candidate.contains(where: { $0 != 0 }), candidate.lexicographicallyPrecedes(order) { return candidate }
    }
    throw DiemError.invalidKey
  }

  private static func hmac(_ key: [UInt8], _ message: [UInt8]) -> [UInt8] {
    let shortened = key.count > 64 ? SHA2.sha256(key) : key
    let padded = shortened + [UInt8](repeating: 0, count: 64 - shortened.count)
    return SHA2.sha256(padded.map { $0 ^ 0x5c } + SHA2.sha256(padded.map { $0 ^ 0x36 } + message))
  }
}

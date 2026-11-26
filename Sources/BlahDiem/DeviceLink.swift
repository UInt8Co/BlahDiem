// Device linking is Diem's (`DeviceLinkRequest`, `DeviceLinkCode`, `DeviceLinkContext`,
// `DeviceLinkGrant`, `DeviceLinkResponse`). Blah adds its acceptance rules and metadata.

extension DeviceLinkGrant {
  /// The largest Blah metadata.
  public static let maximumMetadataBytes = 16_384

  /// A grant carrying Blah's opaque `metadata`, which requires seed transfer.
  public init(profile: [UInt8], domain: DomainName, seed: SealedIdentitySeed? = nil,
    metadata: [UInt8]?) throws
  {
    try self.init(profile: profile, domain: domain, seed: seed,
      applications: metadata.map { [.blah: .bytes($0)] } ?? [:])
    try requireBlahFields()
  }

  /// A grant of `profile`'s exact encoding, carrying Blah's opaque `metadata`.
  public init(profile: AnyBlahProfile, domain: DomainName, seed: SealedIdentitySeed? = nil,
    metadata: [UInt8]?) throws
  {
    try self.init(profile: profile.encoding, domain: domain, seed: seed, metadata: metadata)
  }

  /// Blah's opaque metadata: the bytes at ``ApplicationID/blah``.
  public var metadata: [UInt8]? {
    guard case .bytes(let bytes)? = applications[.blah] else { return nil }
    return bytes
  }

  /// Throws ``BlahError/invalidDeviceLink`` unless Blah's field, if any, is at most
  /// ``maximumMetadataBytes`` bytes and comes with a sealed seed.
  public func requireBlahFields() throws(BlahError) {
    guard let field = applications[.blah] else { return }
    guard seed != nil, case .bytes(let bytes) = field, bytes.count <= Self.maximumMetadataBytes
    else { throw .invalidDeviceLink }
  }

  /// The grant's profile, verified as by Diem's `verify(as:for:at:using:)` and accepted by
  /// ``acceptLink(of:at:expectedDC:)``.
  @discardableResult
  public func verify(for request: DeviceLinkRequest, expectedDC: Digest?, at time: UInt64? = nil,
    using backend: some CryptoBackend) async throws -> AnyBlahProfile
  {
    let time = time ?? backend.now
    let profile = try await verify(as: AnyBlahProfile.self, for: request, at: time, using: backend)
    try acceptLink(of: profile, at: time, expectedDC: expectedDC)
    return profile
  }
}

extension DeviceLinkResponse {
  /// Seals `grant` for `request` after Diem's checks and Blah's acceptance rules, with the
  /// profile verified now at any DC.
  public static func seal(_ grant: DeviceLinkGrant, for request: DeviceLinkRequest,
    code: DeviceLinkCode, using backend: some CryptoBackend) async throws -> [UInt8]
  {
    let time = backend.now
    return try await seal(grant, as: AnyBlahProfile.self, for: request, code: code,
      using: backend) { profile, grant in
      try grant.acceptLink(of: profile, at: time, expectedDC: nil)
    }
  }

  /// Opens a response as Diem's `open(_:as:…)` does, accepting only a grant Blah accepts
  /// (see ``DeviceLinkGrant/requireBlahFields()``) of a user whose home at `expectedDC` is
  /// active at `time` with an allocated account. Blah's checks run before the sealed seed
  /// is opened. A missing `expectedDC` is ``BlahError/wrongHome``: a response cannot
  /// establish which DC the client intended to connect to.
  public static func open(_ bytes: [UInt8], recipientKey: EncryptionPrivateKey,
    request: DeviceLinkRequest, code: DeviceLinkCode, expectedDC: Digest?,
    at time: UInt64? = nil, using backend: some CryptoBackend) async throws
    -> Opened<AnyBlahProfile>
  {
    guard let expectedDC else { throw BlahError.wrongHome }
    let time = time ?? backend.now
    return try await open(bytes, as: AnyBlahProfile.self, recipientKey: recipientKey,
      request: request, code: code, at: time, using: backend) { profile, grant in
      try grant.acceptLink(of: profile, at: time, expectedDC: expectedDC)
    }
  }
}

extension DeviceLinkGrant {
  /// Blah's device-link acceptance, Diem's `accept` check: Blah's field rules, then a user
  /// profile whose home is active at `time` with an allocated account, at `expectedDC`
  /// when given.
  public func acceptLink(of profile: AnyBlahProfile, at time: UInt64, expectedDC: Digest?)
    throws(BlahError)
  {
    try requireBlahFields()
    guard case .user = profile else { throw .invalidProfile }
    guard let home = profile.home, home.account != nil, home.isActive(at: time),
      expectedDC == nil || home.dc == expectedDC
    else { throw .wrongHome }
  }
}

import BlahDiem
import Testing

/// Blah records keep fixed numeric tags and integer field keys.
@Suite struct WireContractTests {
  let backend = TestBackend()

  @Test func dcProfilesHaveAFixedUserHostingForProofsAndNamespaces() async throws {
    let domain = try DomainName("one.example")
    let data = DCProfile.Content(domains: [domain],
      endpoints: [.init(host: "one.example", port: 443, tls: true)],
      bidcomEndpoints: [], transportPublicKey: "rsa", namespaceGeneration: 12)
    let identity = try await BasicIdentity<DCProfile>(data, using: backend)
    let destination = DCAddress(domain: domain, id: identity.id)
    let home = try #require(identity.profile.home)
    #expect(home.dc == identity.id && home.account == 777000 && home.epoch == 1)
    #expect(home.expiresAt == identity.profile.validity.expiresAt)
    #expect(try AnyBlahProfile(record: identity.profile.record).home == home)
    let namespace = try ClientNamespace(profile: identity.profile, dc: destination, generation: 12)
    try namespace.require(identity.profile)
    #expect(throws: BlahError.wrongHome) {
      try ClientNamespace(profile: identity.profile, dc: Fixture.dc, generation: 12)
    }
    let challenge = try LoginChallenge(operation: .signIn, nonce: Fixture.nonce,
      expiresAt: backend.now + 60, identityID: identity.id,
      deviceID: identity.deviceKey.publicKey.id, profileDigest: identity.profile.digest,
      dc: destination, authKeyID: 42, sessionID: 73)
    let proof = try await identity.prove(challenge)
    try await proof.verify(against: identity.profile, using: backend)
  }

  @Test func challengeTagsAndPositionsAreExact() throws {
    let login = try LoginChallenge(
      operation: .signIn, nonce: Fixture.nonce, expiresAt: 5, identityID: Fixture.dcID,
      deviceID: Fixture.dcID, profileDigest: Fixture.dcID, dc: Fixture.dc, authKeyID: -1,
      sessionID: 73)
    let fields = try CBOR(decoding: login.encoding).recordValue(requiredKeys: 0..<12)
    #expect(fields[0] == .unsigned(3) && fields[1] == .unsigned(1) && fields[2] == .unsigned(2))
    #expect(fields[8] == .text("one.example") && fields[10] == .unsigned(.max))
    #expect(try LoginChallenge(encoding: login.encoding) == login)
    var renamed = fields
    renamed[0] = .text("Blah/login")
    #expect(throws: BlahError.invalidChallenge) {
      try LoginChallenge(encoding: CBOR.map(Dictionary(uniqueKeysWithValues: renamed.map { (.unsigned($0.key), $0.value) })).encoded)
    }
    var uppercase = fields
    uppercase[8] = .text("One.example")
    #expect(throws: BlahError.invalidChallenge) { try LoginChallenge(encoding: CBOR.record(uppercase).encoded) }

    let invocation = try InvocationChallenge(
      domain: DomainName("alice.one.example"), nonce: Fixture.nonce, expiresAt: 5, dc: Fixture.dcID,
      transportKeyID: 42, sessionID: 73)
    let statement = InvocationStatement(challenge: invocation, payload: [1])
    let s = try CBOR(decoding: statement.encoding).recordValue(requiredKeys: 0..<5)
    #expect(s[0] == .unsigned(5) && s[2] == .bytes(invocation.encoding) && s[3] == .unsigned(1))
    #expect(try CBOR(decoding: invocation.encoding).recordValue(requiredKeys: 0..<8)[0] == .unsigned(4))
  }

  @Test func profileFieldsAndNamespaceLayoutsAreExact() async throws {
    let user = HostedContent(home: Fixture.home(account: 1_000_001), domains: [try DomainName("a.example")])
    #expect(
      try CBOR(decoding: UserProfile.fields(for: user).encoding) == .map([
        .unsigned(9): .array([.text("a.example")]),
        .unsigned(16): .unsigned(1),
        .unsigned(17): .map([.unsigned(0): .bytes(Fixture.dcID.bytes), .unsigned(1): .unsigned(1), .unsigned(2): .unsigned(TestBackend.start + 3600), .unsigned(3): .unsigned(1_000_001)]),
      ]))

    let identity = try await BasicIdentity<UserProfile>(user, using: backend)
    let namespace = try ClientNamespace(profile: identity.profile, dc: Fixture.dc, generation: 11)
    let fields = try CBOR(decoding: namespace.encoding).recordValue(requiredKeys: 0..<7)
    #expect(fields[0] == .unsigned(10) && fields[5] == .unsigned(11) && fields[6] == .unsigned(1))
    #expect(namespace.identifier.count == 64)
    try namespace.require(identity.profile)

    let other = DCAddress(domain: try DomainName("two.example"), id: Digest(hashing: [8]))
    #expect(throws: BlahError.wrongHome) {
      try ClientNamespace(profile: identity.profile, dc: other, generation: 11)
    }
    let stranger = try await BasicIdentity<UserProfile>(user, using: backend)
    #expect(throws: BlahError.wrongNamespace) { try namespace.require(stranger.profile) }
  }
}

@Suite struct RecordExtensionTests {
  @Test func challengeExtensionsSurviveDeviceSigning() async throws {
    let backend = TestBackend()
    let identity = try await BasicIdentity<UserProfile>(HostedContent(home: Fixture.home()), using: backend)
    let challenge = try LoginChallenge(operation: .signIn, nonce: Fixture.nonce,
      expiresAt: backend.now + 60, identityID: identity.id,
      deviceID: identity.deviceKey.publicKey.id, profileDigest: identity.profile.digest,
      dc: Fixture.dc, authKeyID: 42, sessionID: 73)
    var fields = try CBOR(decoding: challenge.encoding).recordValue(requiredKeys: 0..<12)
    fields[100] = .text("future")
    let encoding = CBOR.record(fields).encoded
    let decoded = try LoginChallenge(encoding: encoding)
    #expect(decoded.encoding == encoding)
    let proof = try await identity.prove(decoded)
    #expect(proof.data == encoding)
    try await proof.verify(against: identity.profile, using: backend)
    fields.removeValue(forKey: 3)
    #expect(throws: BlahError.invalidChallenge) { try LoginChallenge(encoding: CBOR.record(fields).encoded) }
  }

  @Test func profilesAcceptUnknownFields() async throws {
    let backend = TestBackend()
    let content = HostedContent(home: Fixture.home(), domains: [try DomainName("any.example")])
    var fields = try UserProfile.fields(for: content)
    var home = try fields.application[17]!.recordValue(requiredKeys: 0..<4)
    home[100] = .bool(true)
    fields.application[17] = .record(home)
    fields.application[100] = .null
    let raw = try await BasicIdentity<ProfileRecord>(fields, using: backend)
    let profile = try UserProfile(encoding: raw.profile.encoding)
    #expect(profile.content == content)
    // Renewal re-signs the fields it does not interpret.
    var identity = try await BasicIdentity<UserProfile>(profile: profile,
      deviceKey: raw.deviceKey, identityKey: raw.identityKey, using: backend)
    #expect(try await identity.renew().record.fields.application[100] == .null)
  }
}

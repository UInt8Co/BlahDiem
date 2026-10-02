import BlahDiem
import Testing

/// Blah records keep fixed numeric tags and integer field keys.
@Suite struct WireContractTests {
  let backend = TestBackend()

  @Test func dcProfilesHaveAFixedUserHostingForProofsAndNamespaces() async throws {
    let data = DCProfile(domains: ["one.example"],
      endpoints: [.init(host: "one.example", port: 443, tls: true)],
      bidcomEndpoints: [], transportPublicKey: "rsa", namespaceGeneration: 12)
    let identity = try await Identity(data, using: backend)
    let destination = try DCAddress(domain: "one.example", id: identity.id)
    let home = try #require(try identity.profile.blahHome)
    #expect(home.dc == identity.id && home.account == 777000 && home.epoch == 1)
    #expect(home.expiresAt == identity.profile.validity.expiresAt)
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

    let invocation = try InvocationChallenge(
      domain: "alice.one.example", nonce: Fixture.nonce, expiresAt: 5, dc: Fixture.dcID,
      transportKeyID: 42, sessionID: 73)
    let statement = InvocationStatement(challenge: invocation, payload: [1])
    let s = try CBOR(decoding: statement.encoding).recordValue(requiredKeys: 0..<5)
    #expect(s[0] == .unsigned(5) && s[2] == .bytes(invocation.encoding) && s[3] == .unsigned(1))
    #expect(try CBOR(decoding: invocation.encoding).recordValue(requiredKeys: 0..<8)[0] == .unsigned(4))
  }

  @Test func profileDataAndNamespaceLayoutsAreExact() async throws {
    let user = UserProfile(home: Fixture.home(account: 1_000_001), domains: [try ProfileDomain("a.example")])
    #expect(
      try CBOR(decoding: user.encoded()) == .map([
        .unsigned(0): .unsigned(13), .unsigned(1): .unsigned(1), .unsigned(2): .unsigned(1),
        .unsigned(3): .map([.unsigned(0): .bytes(Fixture.dcID.bytes), .unsigned(1): .unsigned(1), .unsigned(2): .unsigned(TestBackend.start + 3600), .unsigned(3): .unsigned(1_000_001)]),
        .unsigned(4): .array([.map([.unsigned(0): .text("a.example")])]),
      ]))

    let identity = try await Identity(user, using: backend)
    let namespace = try ClientNamespace(profile: identity.profile, dc: Fixture.dc, generation: 11)
    let fields = try CBOR(decoding: namespace.encoding).recordValue(requiredKeys: 0..<7)
    #expect(fields[0] == .unsigned(10) && fields[5] == .unsigned(11) && fields[6] == .unsigned(1))
    #expect(namespace.identifier.count == 64)
    try namespace.require(identity.profile)

    let other = try DCAddress(domain: "two.example", id: Digest(hashing: [8]))
    #expect(throws: BlahError.wrongHome) {
      try ClientNamespace(profile: identity.profile, dc: other, generation: 11)
    }
    let stranger = try await Identity(user, using: backend)
    #expect(throws: BlahError.wrongNamespace) { try namespace.require(stranger.profile) }
  }
}

@Suite struct RecordExtensionTests {
  @Test func challengeExtensionsSurviveDeviceSigning() async throws {
    let backend = TestBackend()
    let identity = try await Identity(UserProfile(home: Fixture.home()), using: backend)
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
    #expect(proof.proof.data == encoding)
    try await proof.verify(against: identity.profile, using: backend)
    fields.removeValue(forKey: 3)
    #expect(throws: BlahError.invalidChallenge) { try LoginChallenge(encoding: CBOR.record(fields).encoded) }
  }

  @Test func nestedProfileObjectsAcceptUnknownFields() throws {
    let profile = UserProfile(home: Fixture.home(), domains: [try ProfileDomain("any.example")])
    var fields = try CBOR(decoding: profile.encoded()).recordValue(requiredKeys: 0..<5)
    var home = try fields[3]!.recordValue(requiredKeys: 0..<4)
    home[100] = .bool(true)
    fields[3] = .record(home)
    fields[4] = .array([.record([0: .text("any.example"), 100: .unsigned(7)])])
    fields[100] = .null
    #expect(try UserProfile(data: CBOR.record(fields).encoded) == profile)
  }
}

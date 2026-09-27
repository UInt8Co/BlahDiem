import BlahDiem
import Testing

/// Blah records keep fixed numeric tags and field positions.
@Suite struct WireContractTests {
  let backend = TestBackend()

  @Test func challengeTagsAndPositionsAreExact() throws {
    let login = try LoginChallenge(
      operation: .signIn, nonce: Fixture.nonce, expiresAt: 5, identityID: Fixture.dcID,
      deviceID: Fixture.dcID, profileDigest: Fixture.dcID, dc: Fixture.dc, authKeyID: -1,
      sessionID: 73)
    let fields = try CBOR(decoding: login.encoding).arrayValue(count: 12)
    #expect(fields[0] == .unsigned(3) && fields[1] == .unsigned(1) && fields[2] == .unsigned(2))
    #expect(fields[8] == .text("one.example") && fields[10] == .unsigned(.max))
    #expect(try LoginChallenge(encoding: login.encoding) == login)
    var renamed = fields
    renamed[0] = .text("Blah/login")
    #expect(throws: BlahError.invalidChallenge) {
      try LoginChallenge(encoding: CBOR.array(renamed).encoded)
    }

    let invocation = try InvocationChallenge(
      domain: "alice.one.example", nonce: Fixture.nonce, expiresAt: 5, dc: Fixture.dcID,
      transportKeyID: 42, sessionID: 73)
    let statement = InvocationStatement(challenge: invocation, payload: [1])
    let s = try CBOR(decoding: statement.encoding).arrayValue(count: 5)
    #expect(s[0] == .unsigned(5) && s[2] == .bytes(invocation.encoding) && s[3] == .unsigned(1))
    #expect(try CBOR(decoding: invocation.encoding).arrayValue(count: 8)[0] == .unsigned(4))
  }

  @Test func profileDataAndNamespaceLayoutsAreExact() async throws {
    let user = UserProfile(home: Fixture.home(account: 1_000_001), domains: [try ProfileDomain("a.example", isUsername: true)])
    #expect(
      try CBOR(decoding: user.encoded()) == .array([
        .unsigned(13), .unsigned(1), .unsigned(1),
        .array([.bytes(Fixture.dcID.bytes), .unsigned(1), .unsigned(TestBackend.start + 3600), .unsigned(1_000_001)]),
        .array([.array([.text("a.example"), .bool(true)])]),
      ]))

    let identity = try await Identity(user, using: backend)
    let namespace = try ClientNamespace(profile: identity.profile, dc: Fixture.dc, generation: 11)
    let fields = try CBOR(decoding: namespace.encoding).arrayValue(count: 7)
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

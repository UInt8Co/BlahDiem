import BlahDiem
import Testing

/// Blah profiles: homes, served domains and public names.
@Suite struct NameClaimTests {
  let backend = TestBackend()

  @Test func aUserProfileKeepsItsNameAcrossRenumbering() async throws {
    var user = HostedContent(home: Fixture.home(), domains: [try DomainName("id.one.example")])
    user.username = try DomainName("alice.one.example")
    var identity = try await BasicIdentity<UserProfile>(user, using: backend)
    var parsed = try UserProfile(encoding: identity.profile.encoding)
    #expect(parsed.content == user && parsed.username?.name == "alice.one.example")
    #expect(parsed.domains == user.domains && parsed.serves("alice.one.example"))

    var next = parsed.content
    next.home?.account = 1_000_001
    parsed = try await identity.update(next)
    #expect(parsed.home?.account == 1_000_001 && parsed.username?.name == "alice.one.example")

    next.username = nil
    #expect(try await identity.update(next).domains == [])
  }

  @Test func profileDomainsAreDistinctAndKindsLimitTheirCount() async throws {
    let one = try DomainName("helper.one.example")
    var identity = try await BasicIdentity<BotProfile>(
      HostedContent(home: Fixture.home(account: 1_000_002), domains: [one]), using: backend)
    #expect(try BotProfile(encoding: identity.profile.encoding) == identity.profile)
    await #expect(throws: BlahError.invalidName) {
      try await identity.update(HostedContent(home: nil, domains: [one, one]))
    }
    let many = try (0...ProfileFields.maximumDomains).map { try DomainName("d\($0).example") }
    await #expect(throws: BlahError.invalidName) {
      try await identity.update(HostedContent(home: nil, domains: many))
    }
  }

  @Test func accountNumbersComeFromEachKindsOwnSpace() async throws {
    let numbered = HostedContent(home: Fixture.home(account: 997_852_516_352))
    #expect(throws: BlahError.invalidProfile) { try ChannelProfile.fields(for: numbered) }
    let user = try await BasicIdentity<UserProfile>(numbered, using: backend)
    #expect(user.profile.home?.account == 997_852_516_352)
    #expect(throws: BlahError.invalidProfile) {
      try UserProfile.fields(for: HostedContent(home: Home(dc: Fixture.dcID, epoch: 0, expiresAt: 1)))
    }
  }

  @Test func aStickerSetHasExactlyOneShortName() async throws {
    let content = StickerSetProfile.Content(
      home: Fixture.home(account: 5), shortName: try DomainName("cats.one.example"))
    let set = try await BasicIdentity<StickerSetProfile>(content, using: backend)
    #expect(try StickerSetProfile(encoding: set.profile.encoding).content == content)
    #expect(set.profile.domains == [content.shortName])
    // Another kind's profile, even with one name, is not a sticker set.
    let user = try await BasicIdentity<UserProfile>(
      HostedContent(home: nil, domains: [try DomainName("a.example")]), using: backend)
    #expect(throws: BlahError.invalidProfile) { try StickerSetProfile(record: user.profile.record) }
    // A sticker-set kind with two names is malformed.
    var fields = try StickerSetProfile.fields(for: content)
    fields.domains.append(try DomainName("b.example"))
    var raw = try await BasicIdentity<ProfileRecord>(fields, using: backend)
    #expect(throws: BlahError.invalidName) { try StickerSetProfile(record: raw.profile) }
    fields.domains = []
    let unnamed = try await raw.update(fields)
    #expect(throws: BlahError.invalidName) { try StickerSetProfile(record: unnamed) }
  }

  @Test func eachKindDecodesOnlyAsItself() async throws {
    let channel = try await BasicIdentity<ChannelProfile>(
      HostedContent(home: Fixture.home()), using: backend)
    guard case .channel(let decoded) = try AnyBlahProfile(encoding: channel.profile.encoding) else {
      Issue.record("Expected a channel profile")
      return
    }
    #expect(decoded.home == Fixture.home())
    #expect(throws: BlahError.invalidProfile) { try UserProfile(record: channel.profile.record) }
    let plain = try await BasicIdentity<ProfileRecord>(ProfileFields(), using: backend)
    #expect(throws: BlahError.invalidProfile) { try AnyBlahProfile(record: plain.profile) }
  }

  @Test func aDCProfileCarriesItsEndpoints() async throws {
    let dc = DCProfile.Content(
      domains: [try DomainName("one.example")],
      endpoints: [.init(host: "mtproto.one.example", port: 443, tls: true)],
      bidcomEndpoints: [.init(host: "peer.one.example", port: 8443, tls: true)],
      transportPublicKey: "-----BEGIN RSA PUBLIC KEY-----", namespaceGeneration: 11)
    var identity = try await BasicIdentity<DCProfile>(dc, using: backend)
    #expect(try DCProfile(encoding: identity.profile.encoding).content == dc)
    #expect(try AnyBlahProfile(encoding: identity.profile.encoding).content == .dc(dc))
    var unreachable = dc
    unreachable.bidcomEndpoints = []
    #expect(try await identity.update(unreachable).bidcomEndpoints.isEmpty)
    unreachable = dc
    unreachable.endpoints[0].host = "user@host"
    #expect(throws: BlahError.invalidProfile) { try DCProfile.fields(for: unreachable) }
    unreachable = dc
    unreachable.domains = []
    #expect(throws: BlahError.invalidName) { try DCProfile.fields(for: unreachable) }
  }

  @Test func websocketEndpointsHaveExplicitTransportAndSignedPaths() async throws {
    let endpoint = DCProfile.Endpoint(host: "ws.example", port: 443, tls: true,
      transport: .webSocket, path: "/apiws?route=dc1")
    let dc = DCProfile.Content(domains: [try DomainName("dc.example")], endpoints: [endpoint],
      bidcomEndpoints: [], transportPublicKey: "rsa", namespaceGeneration: 1)
    let identity = try await BasicIdentity<DCProfile>(dc, using: backend)
    try await identity.profile.verify(using: backend)
    #expect(try DCProfile(encoding: identity.profile.encoding).content == dc)
    for path: String? in [nil, "", "apiws", "//other.example/", "/x#fragment", "/x\n", "/a\\b",
      "/" + String(repeating: "x", count: 2048)] {
      var invalid = dc
      invalid.endpoints[0].path = path
      #expect(throws: BlahError.invalidProfile) { try DCProfile.fields(for: invalid) }
    }
    var invalid = dc
    invalid.bidcomEndpoints = [endpoint]
    #expect(throws: BlahError.invalidProfile) { try DCProfile.fields(for: invalid) }
    invalid = dc
    invalid.endpoints[0].transport = .tcp
    #expect(throws: BlahError.invalidProfile) { try DCProfile.fields(for: invalid) }
    invalid = dc
    invalid.endpoints.append(endpoint)
    #expect(throws: BlahError.invalidProfile) { try DCProfile.fields(for: invalid) }
  }
}

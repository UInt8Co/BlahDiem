import BlahDiem
import Testing

/// Blah profiles: homes, served domains and public names.
@Suite struct NameClaimTests {
  let backend = TestBackend()

  @Test func aUserProfileKeepsItsNameAcrossRenumbering() async throws {
    var user = UserProfile(home: Fixture.home(), domains: [try ProfileDomain("id.one.example")])
    user.username = "alice.one.example"
    var identity = try await Identity(user, using: backend)
    var parsed = try UserProfile(identity.profile)
    #expect(parsed == user && parsed.username == "alice.one.example")

    parsed.home?.account = 1_000_001
    let numbered = try UserProfile(try await identity.update(parsed))
    #expect(numbered.home?.account == 1_000_001 && numbered.username == "alice.one.example")

    parsed.username = nil
    #expect(try UserProfile(try await identity.update(parsed)).domains.map(\.name) == ["id.one.example"])
  }

  @Test func namesAreDomainsAndABotsFirstLabelEndsInBot() throws {
    for name in ["alice", "Alice.example", "ali_ce.example", "-a.example", "a-.example", "a..example", "a.example.",
      "álîce.example", "alice.例え", "alice.💬", "a.\u{212A}", String(repeating: "a", count: 64) + ".example"] {
      #expect(throws: BlahError.invalidName) { try ProfileDomain(name) }
      var user = UserProfile(home: nil)
      user.username = name
      #expect(throws: BlahError.invalidName) { try user.encoded() }
    }
    var bot = BotProfile(home: Fixture.home(account: 1_000_002))
    bot.username = "helper.one.example"
    #expect(throws: BlahError.invalidName) { try bot.encoded() }
    bot.username = "helperbot.one.example"
    #expect(try BotProfile(data: bot.encoded()) == bot)
    #expect(DomainName.normalized("Alice.Example") == "alice.example")
  }

  @Test func accountNumbersComeFromEachKindsOwnSpace() throws {
    let channel = ChannelProfile(home: Fixture.home(account: 997_852_516_352))
    #expect(throws: BlahError.invalidProfile) { try channel.encoded() }
    let user = UserProfile(home: Fixture.home(account: 997_852_516_352))
    #expect(try UserProfile(data: user.encoded()) == user)
    #expect(throws: BlahError.invalidProfile) {
      try UserProfile(home: Home(dc: Fixture.dcID, epoch: 0, expiresAt: 1)).encoded()
    }
  }

  @Test func aStickerSetHasExactlyOneShortName() throws {
    let set = StickerSetProfile(home: Fixture.home(account: 5), shortName: "cats.one.example")
    #expect(try StickerSetProfile(data: set.encoded()) == set)
    let twoNames = try UserProfile(
      home: nil, domains: [ProfileDomain("a.example", isUsername: true), ProfileDomain("b.example")]
    ).encoded()
    #expect(throws: BlahError.invalidProfile) { try StickerSetProfile(data: twoNames) }
  }

  @Test func eachKindDecodesOnlyAsItself() async throws {
    let channel = try await Identity(ChannelProfile(home: Fixture.home()), using: backend)
    guard case .channel(let decoded) = try AnyBlahProfile(channel.profile) else {
      Issue.record("Expected a channel profile")
      return
    }
    #expect(decoded.home == Fixture.home())
    #expect(throws: BlahError.invalidProfile) { try UserProfile(channel.profile) }
    #expect(throws: BlahError.invalidProfile) { try UserProfile(data: [0x80]) }
  }

  @Test func aDCProfileCarriesItsEndpoints() async throws {
    let dc = DCProfile(
      domains: ["one.example"], endpoints: [.init(host: "mtproto.one.example", port: 443, tls: true)],
      bidcomEndpoints: [.init(host: "peer.one.example", port: 8443, tls: true)],
      transportPublicKey: "-----BEGIN RSA PUBLIC KEY-----", namespaceGeneration: 11)
    let identity = try await Identity(dc, using: backend)
    #expect(try DCProfile(identity.profile) == dc)
    #expect(try AnyBlahProfile(identity.profile).home == nil)
    var unreachable = dc
    unreachable.bidcomEndpoints = []
    #expect(try DCProfile(data: unreachable.encoded()).bidcomEndpoints.isEmpty)
    unreachable = dc
    unreachable.endpoints[0].host = "user@host"
    #expect(throws: BlahError.invalidProfile) { try unreachable.encoded() }
  }

  @Test func websocketEndpointsHaveExplicitTransportAndSignedPaths() async throws {
    let endpoint = DCProfile.Endpoint(host: "ws.example", port: 443, tls: true,
      transport: .webSocket, path: "/apiws?route=dc1")
    let dc = DCProfile(domains: ["dc.example"], endpoints: [endpoint],
      bidcomEndpoints: [], transportPublicKey: "rsa", namespaceGeneration: 1)
    let identity = try await Identity(dc, using: backend)
    try await identity.profile.verify(using: backend)
    #expect(try DCProfile(identity.profile) == dc)
    for path: String? in [nil, "", "apiws", "//other.example/", "/x#fragment", "/x\n", "/a\\b",
      "/" + String(repeating: "x", count: 2048)] {
      var invalid = dc
      invalid.endpoints[0].path = path
      #expect(throws: BlahError.invalidProfile) { try invalid.encoded() }
    }
    var invalid = dc
    invalid.bidcomEndpoints = [endpoint]
    #expect(throws: BlahError.invalidProfile) { try invalid.encoded() }
    invalid = dc
    invalid.endpoints[0].transport = .tcp
    #expect(throws: BlahError.invalidProfile) { try invalid.encoded() }
    invalid = dc
    invalid.endpoints.append(endpoint)
    #expect(throws: BlahError.invalidProfile) { try invalid.encoded() }
  }
}

import BlahDiem
import Testing

/// Application profiles: client data, version ranges and the derived MTProto wire pair.
@Suite struct ApplicationProfileTests {
  let backend = TestBackend()

  static let full = ApplicationProfile.Content(
    domains: [try! DomainName("app.example"), try! DomainName("alias.example")],
    name: "Example Messenger",
    downloadURL: "https://app.example/download",
    bot: .init(id: Digest(hashing: [1]), dc: Fixture.dcID),
    oauth: .init(publicClient: false,
      redirectURIs: ["https://app.example/callback", "com.example.app:/oauth", "http://127.0.0.1/cb"],
      clientKeys: [
        .init(keyID: "ed-1", algorithm: .edDSA, rawRepresentation: [UInt8](repeating: 3, count: 32)),
        .init(keyID: "p256-1", algorithm: .es256, rawRepresentation: [4] + [UInt8](repeating: 5, count: 64)),
      ]),
    push: .init(credentialsURL: "https://push.app.example/credentials",
      apns: .init(topic: "com.example.app", productionURL: "https://push.app.example/apns",
        sandboxURL: "https://push.app.example/apns-sandbox"),
      webPush: .init(proxyURL: "https://push.app.example/web",
        vapidPublicKey: [4] + [UInt8](repeating: 6, count: 64))),
    versions: [-5, 0, 100, 200, 300])

  @Test func roundTripsEveryFieldAndDecodesAsAnyKind() async throws {
    let minimal = ApplicationProfile.Content(domains: [try DomainName("min.example")], name: "M")
    for content in [Self.full, minimal] {
      var identity = try await BasicIdentity<ApplicationProfile>(content, using: backend)
      let decoded = try ApplicationProfile(encoding: identity.profile.encoding)
      #expect(decoded.content == content && decoded.home == nil && decoded.name == content.name)
      let any = try await AnyBlahProfile(verifying: identity.profile.encoding, using: backend)
      #expect(any.content == .application(content) && any.home == nil)
      #expect(try AnyBlahProfile.fields(for: .application(content)) == ApplicationProfile.fields(for: content))
      #expect(identity.profile.record.fields.blah[ApplicationProfile.cborKeyKind] == .unsigned(6))
      var next = content
      next.versions = []
      #expect(try await identity.update(next).content.versions == [])
    }
    let user = try await BasicIdentity<UserProfile>(HostedContent(home: nil), using: backend)
    #expect(throws: BlahError.invalidProfile) { try ApplicationProfile(record: user.profile.record) }
    let app = try await BasicIdentity<ApplicationProfile>(Self.full, using: backend)
    #expect(throws: BlahError.invalidProfile) { try BotProfile(record: app.profile.record) }
  }

  @Test func replacingDomainsKeepsTheApplication() throws {
    let content: AnyBlahProfile.Content = .application(Self.full)
    let replacement = try DomainName("new.example")
    var expected = Self.full
    expected.domains = [replacement]
    #expect(try content.replacingDomains([replacement]) == .application(expected))
    #expect(throws: BlahError.invalidName) { try content.replacingDomains([]) }
  }

  @Test func rejectsInvalidFields() throws {
    var invalid: [ApplicationProfile.Content] = []
    func with(_ change: (inout ApplicationProfile.Content) -> Void) {
      var content = Self.full
      change(&content)
      invalid.append(content)
    }
    with { $0.name = "" }
    with { $0.name = String(repeating: "x", count: 257) }
    for url in ["http://app.example/", "https://", "https:///path", "https://a.example/#x",
      "https://a .example/", "ftp://a.example/", "https://a.example/\\"] {
      with { $0.downloadURL = url }
      with { $0.push?.credentialsURL = url }
      with { $0.push?.apns?.productionURL = url }
      with { $0.push?.apns?.sandboxURL = url }
      with { $0.push?.webPush?.proxyURL = url }
    }
    for uri in ["", "/relative", "1app:/x", "https://a.example/#frag", "app: x", "noscheme"] {
      with { $0.oauth?.redirectURIs = [uri] }
    }
    with { $0.oauth?.redirectURIs = [] }
    with { $0.oauth?.redirectURIs = ["https://a.example/", "https://a.example/"] }
    with { $0.oauth?.clientKeys[1].keyID = "ed-1" }
    with { $0.oauth?.clientKeys[0].keyID = "" }
    with { $0.oauth?.clientKeys[0].rawRepresentation = [UInt8](repeating: 3, count: 33) }
    with { $0.oauth?.clientKeys[1].rawRepresentation[0] = 2 }
    with { $0.oauth?.clientKeys[1].algorithm = .edDSA }
    with { $0.push?.apns?.topic = "" }
    with { $0.push?.webPush?.vapidPublicKey = [4] + [UInt8](repeating: 6, count: 32) }
    with { $0.versions = [1, 1] }
    with { $0.versions = [2, 1] }
    with { $0.versions = (0...Int64(ApplicationProfile.maximumVersions)).map { $0 } }
    for content in invalid {
      #expect(throws: BlahError.invalidProfile) { try ApplicationProfile.fields(for: content) }
    }
    var unnamed = Self.full
    unnamed.domains = []
    #expect(throws: BlahError.invalidName) { try ApplicationProfile.fields(for: unnamed) }
  }

  @Test func rejectsMalformedSignedFields() async throws {
    let fields = try ApplicationProfile.fields(for: Self.full)
    var cases: [ProfileFields] = []
    for key in ApplicationProfile.cborKeyName...ApplicationProfile.cborKeyVersions {
      var missing = fields
      missing.blah[key] = nil
      cases.append(missing)
    }
    var overflow = fields
    overflow.blah[ApplicationProfile.cborKeyVersions] = .array([.unsigned(UInt64(Int64.max) + 1)])
    cases.append(overflow)
    var unordered = fields
    unordered.blah[ApplicationProfile.cborKeyVersions] = .array([.unsigned(2), .negative(-1)])
    cases.append(unordered)
    var algorithm = fields
    algorithm.blah[ApplicationProfile.cborKeyOAuth] = .record([
      0: .bool(true), 1: .array([.text("https://a.example/")]),
      2: .array([.record([0: .text("k"), 1: .unsigned(5), 2: .bytes([UInt8](repeating: 0, count: 32))])]),
    ])
    cases.append(algorithm)
    for invalid in cases {
      let identity = try await BasicIdentity<ProfileRecord>(invalid, using: backend)
      #expect(throws: BlahError.invalidProfile) { try ApplicationProfile(record: identity.profile) }
      #expect(throws: BlahError.invalidProfile) { try AnyBlahProfile(record: identity.profile) }
    }
    // Unknown keys are accepted.
    var extended = fields
    extended.blah[ApplicationProfile.cborKeyVersions + 1] = .text("future")
    let identity = try await BasicIdentity<ProfileRecord>(extended, using: backend)
    #expect(try ApplicationProfile(record: identity.profile).content == Self.full)
  }

  @Test func versionRangesAlternateFromEnabled() throws {
    func app(_ versions: [Int64]?) -> ApplicationProfile.Content {
      .init(domains: [try! DomainName("v.example")], name: "V", versions: versions)
    }
    for version: Int64 in [.min, -1, 0, 1, .max] {
      #expect(app(nil).isEnabled(version: version))
      #expect(!app([]).isEnabled(version: version))
      #expect(app([.min]).isEnabled(version: version))
    }
    let ranges = app([10, 20, 30])
    let expected: [(Int64, Bool)] = [
      (.min, false), (0, false), (9, false), (10, true), (19, true), (20, false), (29, false),
      (30, true), (.max, true),
    ]
    for (version, enabled) in expected {
      #expect(ranges.isEnabled(version: version) == enabled, "version \(version)")
    }
    #expect(!app([0, .max]).isEnabled(version: .max) && app([0, .max]).isEnabled(version: .max - 1))
    #expect(!Self.full.isEnabled(version: -6) && Self.full.isEnabled(version: -5))
    #expect(!Self.full.isEnabled(version: 0) && Self.full.isEnabled(version: 150))
    #expect(!Self.full.isEnabled(version: 250) && Self.full.isEnabled(version: 300))
    try ApplicationProfile.validate(versions: [.min, -1, 0, .max])
    #expect(throws: BlahError.invalidProfile) { try ApplicationProfile.validate(versions: [0, -1]) }
  }

  @Test func wirePairVectors() async throws {
    let vectors: [([UInt8], Int32, String)] = [
      (Array(0..<32), 1_705_667_788, "b99b5108426a9bfdbcf8dda934047b31"),
      ([UInt8](repeating: 0, count: 32), 1_937_526_107, "a63ac8864bd11244cce21727a68eade1"),
      ([UInt8](repeating: 0xff, count: 32), 1_957_165_822, "86fa24c1b11713250836e330034bbd13"),
      (Fixture.dcID.bytes, 1_644_300_822, "225a712e43a8be5a3b0ac15c68dab47e"),
    ]
    for (bytes, apiID, apiHash) in vectors {
      let pair = ApplicationWirePair(application: try Digest(bytes: bytes))
      #expect(pair.apiID == apiID && pair.apiHash == apiHash)
      #expect(pair.apiID >= ApplicationWirePair.firstAPIID)
    }
    let identity = try await BasicIdentity<ApplicationProfile>(Self.full, using: backend)
    #expect(identity.profile.wirePair == ApplicationWirePair(application: identity.id))
  }
}

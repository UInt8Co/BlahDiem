import BlahDiem
import Testing

@Suite struct ProfileHostingTests {
  let backend = TestBackend()

  @Test func apexPolicyAndTargetsAreReexported() async throws {
    let domain = try DomainName("id.example")
    let policy = try HostingPolicy(json: HostingTestHost.json(["domain": domain.name, "apex": true]).body,
      domain: domain)
    #expect(policy.apex && !policy.servesChildNames)
    #expect(policy.names == nil)
    #expect(policy.requiredBits(for: "alice") == nil)
    #expect(policy.requiredBits(for: "@") == nil)
    #expect(throws: ProfileHostingError.invalidResponse) {
      try HostingPolicy(json: HostingTestHost.json(["domain": domain.name, "apex": true,
        "labelPattern": "[a-z]+"]).body, domain: domain)
    }
    let child = try HostingPolicy(json: HostingTestHost.json(HostingTestHost.policy()).body, domain: domain)
    #expect(!child.apex && child.names?.baseBits == 4)

    let transport = ApexTransport()
    let host = ProfileHostingClient(domain: domain, http: transport)
    let identity = try await BasicIdentity<AnyBlahProfile>(.user(.init(home: Fixture.home(), domains: [domain])), using: backend)
    let publication = HostingPublication(profile: identity.profile, via: HostingTarget.apex)
    #expect(publication.via == .apex)
    let plan = try await host.plan(labels: ["@"], identity: identity.id)
    #expect(plan.names.map(\.status) == [.needsProof(requiredBits: 4)])
    #expect(await transport.requests.last?.url == "https://id.example/.well-known/diem/hosting/names/@")
    try await host.publish(publication, solver: PortableProofOfWorkSolver())
    #expect(try await host.profile(at: .apex) == identity.profile.encoding)
    let mixed = try await identity.updating(identity.profile.content.replacingDomains([domain, DomainName("alice.id.example")]))
    try await host.publish(mixed)
    try await host.publish(mixed, via: .apex, proofs: ["@": [2], "alice": [1]], solver: PortableProofOfWorkSolver())
    let requests = await transport.requests
    #expect(requests.map(\.url) == [
      "https://id.example/.well-known/diem/hosting/names/@",
      "https://id.example/.well-known/diem/profile.cbor",
      "https://id.example/.well-known/diem/profile.cbor",
      "https://id.example/.well-known/diem/profile.cbor",
      "https://alice.id.example/.well-known/diem/profile.cbor",
      "https://id.example/.well-known/diem/profile.cbor",
    ])
    #expect(requests[1].headers["Diem-Hosting-Proof"] == nil)
    #expect(requests[2].headers["Diem-Hosting-Proof"]?.hasPrefix("@=") == true)
    #expect(requests.last?.headers["Diem-Hosting-Proof"] == "@=Ag, alice=AQ")
    #expect(try await host.plan(labels: ["@"], identity: identity.id).names[0].status == .held)
  }

  @Test func claimAndReleasePreserveHostedKinds() async throws {
    let home = Fixture.home(account: 123)
    let original = try DomainName("original.example")
    for content: AnyBlahProfile.Content in [
      .user(.init(home: home, domains: [original])),
      .bot(.init(home: home, domains: [original])),
      .channel(.init(home: home, domains: [original]))
    ] {
      let transport = HostingTestHost()
      let host = ProfileHostingClient(domain: try DomainName("id.example"), http: transport)
      var identity = try await BasicIdentity<AnyBlahProfile>(content, using: backend)
      let claim = try await identity.claiming(labels: ["alice"], at: host,
        solver: PortableProofOfWorkSolver(), transform: { try $0.replacingDomains($1) })
      #expect(identity.profile.domains == [original])
      #expect(claim.profile.domains.map(\.name) == ["original.example", "alice.id.example"])
      #expect(claim.profile.home == home)
      try await claim.profile.verify(using: backend)
      try await host.publish(claim, solver: PortableProofOfWorkSolver())
      try await host.publish(claim, solver: PortableProofOfWorkSolver())
      #expect(try await host.plan(labels: ["alice"], identity: identity.id).names[0].status == .held)
      identity = try await BasicIdentity(profile: claim.profile, deviceKey: identity.deviceKey,
        identityKey: identity.identityKey, using: backend)
      let release = try await identity.releasing(labels: ["alice"], at: host,
        transform: { try $0.replacingDomains($1) })
      #expect(release.profile.content == content)
      #expect(release.via == .name("alice"))
      try await host.publish(release, solver: PortableProofOfWorkSolver())
      #expect(await transport.claims.isEmpty)
    }
  }

  @Test func stickerSetRequiresReplacementAndDCKeepsDiscoveryFields() async throws {
    let original = try DomainName("alice.id.example")
    let replacement = try DomainName("bob.id.example")
    let sticker: AnyBlahProfile.Content = .stickerSet(.init(home: Fixture.home(), shortName: original))
    #expect(throws: BlahError.invalidName) { try sticker.replacingDomains([]) }
    #expect(throws: BlahError.invalidName) { try sticker.replacingDomains([original, replacement]) }
    #expect(try sticker.replacingDomains([replacement]) == .stickerSet(.init(home: Fixture.home(), shortName: replacement)))
    let dc = DCProfile.Content(domains: [original],
      endpoints: [.init(host: "ws.example", port: 443, tls: true, transport: .webSocket, path: "/apiws")],
      bidcomEndpoints: [.init(host: "peer.example", port: 443, tls: true)],
      transportPublicKey: "rsa", namespaceGeneration: 42)
    let content: AnyBlahProfile.Content = .dc(dc)
    #expect(throws: BlahError.invalidName) { try content.replacingDomains([]) }
    #expect(throws: BlahError.invalidName) { try content.replacingDomains([original, original]) }
    var expected = dc
    expected.domains = [replacement]
    #expect(try content.replacingDomains([replacement]) == .dc(expected))

    for value in [sticker, content] {
      let host = ProfileHostingClient(domain: try DomainName("id.example"), http: HostingTestHost())
      let identity = try await BasicIdentity<AnyBlahProfile>(value, using: backend)
      await #expect(throws: BlahError.invalidName) {
        try await identity.releasing(labels: ["alice"], at: host, transform: { try $0.replacingDomains($1) })
      }
      if case .stickerSet = value {
        await #expect(throws: BlahError.invalidName) {
          try await identity.claiming(labels: ["bob"], at: host, solver: PortableProofOfWorkSolver(),
            transform: { try $0.replacingDomains($1) })
        }
      } else {
        let claim = try await identity.claiming(labels: ["bob"], at: host, solver: PortableProofOfWorkSolver(),
          transform: { try $0.replacingDomains($1) })
        expected.domains = [original, replacement]
        #expect(claim.profile.content == .dc(expected))
        #expect(claim.profile.home?.dc == identity.id)
        #expect(claim.profile.home?.account == DCProfile.accountID)
        try await host.publish(claim, solver: PortableProofOfWorkSolver())
      }
    }
  }
}

private actor ApexTransport: HostingHTTPClient {
  var requests: [HostingHTTPRequest] = []
  var encoding: [UInt8] = []

  func send(_ request: HostingHTTPRequest) async throws -> HostingHTTPResponse {
    requests.append(request)
    if request.url.hasSuffix("/names/@") {
      return HostingTestHost.json(["label": "@", "status": encoding.isEmpty ? "available" : "claimed", "requiredBits": 4])
    }
    if request.method == .get { return .init(status: 200, body: encoding) }
    if encoding.isEmpty && request.headers["Diem-Hosting-Proof"] == nil {
      return HostingTestHost.json(["type": "urn:diem:profile-hosting:proof-required",
        "title": "Proof", "detail": "Proof", "status": 403,
        "labels": [["label": "@", "reason": "proof-required", "requiredBits": 4]]], status: 403)
    }
    encoding = request.body ?? []
    let profile = try ProfileRecord(encoding: encoding)
    return HostingTestHost.json(["identity": HostingTestHost.base64(profile.id.bytes),
      "revision": profile.revision, "domains": profile.domains.map(\.name)])
  }
}

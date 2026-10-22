import BlahDiem
import Testing

@Suite struct ProfileHostingTests {
  let backend = TestBackend()

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
      #expect(release.via == "alice")
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

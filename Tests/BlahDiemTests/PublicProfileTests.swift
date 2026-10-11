import BlahDiem
import Testing

@Suite struct PublicProfileTests {
  let backend = TestBackend()

  @Test func verifiesEveryBlahKindAndItsPublicFacts() async throws {
    let domains = try [DomainName("second.example"), DomainName("first.example")]
    let home = Home(dc: Fixture.dcID, epoch: 9_007_199_254_740_993,
      expiresAt: backend.now + 3600, account: 42)
    let hosted = HostedContent(home: home, domains: domains)
    let contents: [AnyBlahProfile.Content] = [
      .user(hosted), .channel(hosted), .bot(hosted),
      .stickerSet(.init(home: home, shortName: domains[0])),
      .dc(.init(domains: domains, endpoints: [.init(host: "dc.example", port: 443, tls: true)],
        bidcomEndpoints: [], transportPublicKey: "rsa")),
      .user(.init(home: nil)), .channel(.init(home: Fixture.home())),
    ]
    for content in contents {
      var identity = try await BasicIdentity<AnyBlahProfile>(content, using: backend)
      let original = try await identity.update(content)
      let verified = try await AnyBlahProfile(verifying: original.encoding, using: backend)
      #expect(verified == original)
      #expect(verified.id == identity.id && verified.revision == 2 && verified.generation == 1)
      #expect(verified.domains == original.domains && verified.home == original.home)
      if case .dc = verified {
        #expect(verified.home?.dc == verified.id)
        #expect(verified.home?.account == 777000 && verified.home?.epoch == 1)
      }
    }
  }

  @Test func verifiesAfterProfileAndCertificatesExpire() async throws {
    let identity = try await BasicIdentity<UserProfile>(HostedContent(home: Fixture.home()),
      profileLifetime: 60, deviceLifetime: 60, using: backend)
    backend.advance(by: 120)
    await #expect(throws: DiemError.expired) { try await identity.profile.verify(using: backend) }
    let profile = try await AnyBlahProfile(verifying: identity.profile.encoding, using: backend)
    #expect(!profile.validity.contains(backend.now))
    #expect(!profile.validity.contains(TestBackend.start - 1))
    #expect(profile.validity.contains(TestBackend.start))
    #expect(profile.validity.contains(TestBackend.start + 59))
    #expect(!profile.validity.contains(TestBackend.start + 60))
  }

  @Test func rejectsContentAndCertificateSignatureTampering() async throws {
    let identity = try await BasicIdentity<UserProfile>(HostedContent(home: Fixture.home()), using: backend)
    let original = try CBOR(decoding: identity.profile.encoding).recordValue(requiredKeys: 0..<5)
    for certificate in [false, true] {
      var envelope = original
      if certificate {
        var certificates = try envelope[3]!.arrayValue()
        var bytes = try certificates[0].bytesValue()
        bytes[bytes.count - 1] ^= 1
        certificates[0] = .bytes(bytes)
        envelope[3] = .array(certificates)
      } else {
        var bytes = try envelope[4]!.bytesValue()
        bytes[bytes.count - 1] ^= 1
        envelope[4] = .bytes(bytes)
      }
      await #expect(throws: DiemError.invalidSignature) {
        try await AnyBlahProfile(verifying: CBOR.record(envelope).encoded, using: backend)
      }
    }
  }

  @Test func rejectsSignedInvalidBlahFields() async throws {
    let home = Fixture.home(account: 997_852_516_352)
    var fields = try UserProfile.fields(for: HostedContent(home: home))
    // The same account number is valid for a user but outside the channel range.
    fields.application[UserProfile.cborKeyKind] = .unsigned(2)
    let identity = try await BasicIdentity<ProfileRecord>(fields, using: backend)
    try await identity.profile.verify(using: backend)
    await #expect(throws: BlahError.invalidProfile) {
      try await AnyBlahProfile(verifying: identity.profile.encoding, using: backend)
    }
  }

  @Test func rejectsSignedInvalidRevisionAndValidity() async throws {
    let identity = try await BasicIdentity<UserProfile>(HostedContent(home: Fixture.home()), using: backend)
    let device = try await backend.makePrivateKey(identity.deviceKey.publicKey.key.algorithm,
      for: .device, restoring: #require(identity.deviceKey.rawRepresentation))
    let signed = identity.profile.record.signedContent
    let original = try CBOR(decoding: signed.message).recordValue(requiredKeys: 0..<10)
    let mutations: [(UInt64, CBOR)] = [
      (ProfileRecord.cborKeyContentRevision, .unsigned(0)),
      (ProfileRecord.cborKeyContentRevision, .unsigned(2)), // Missing previous digest.
      (ProfileRecord.cborKeyContentGeneration, .unsigned(2)), // Certificates are generation 1.
      (ProfileRecord.cborKeyContentExpiresAt, .unsigned(identity.profile.devices[0].validity.expiresAt + 1)),
    ]
    for (key, value) in mutations {
      var content = original
      content[key] = value
      let changed = try await SignedMessage(signing: CBOR.record(content).encoded, with: device)
      var envelope = try CBOR(decoding: identity.profile.encoding).recordValue(requiredKeys: 0..<5)
      envelope[4] = .bytes(changed.encoding)
      await #expect(throws: (any Error).self) {
        try await AnyBlahProfile(verifying: CBOR.record(envelope).encoded, using: backend)
      }
    }
  }
}

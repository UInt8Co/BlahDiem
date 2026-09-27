import BlahDiem
import Testing

/// Blah proofs: a device signs a DC's statement for the identity it acts for.
@Suite struct IdentityInvocationProofTests {
  let backend = TestBackend()

  func identity(home: Home? = Fixture.home()) async throws -> Identity {
    try await Identity(
      UserProfile(home: home, domains: [try ProfileDomain("alice.one.example")]), using: backend)
  }

  @Test func blahIdentitiesUsePostQuantumKeysForSeparatePurposes() async throws {
    let alice = try await identity()
    let identityKey = alice.profile.identityKey.key, deviceKey = alice.deviceKey.publicKey.key
    #expect(identityKey.purpose == .identity && identityKey.algorithm == .mlDSA65)
    #expect(deviceKey.purpose == .device && deviceKey.algorithm == .mlDSA65)
    let consent = try await alice.prove(OAuthConsentChallenge.sample(expiresAt: backend.now + 60))
    #expect(consent.proof.deviceID == alice.deviceKey.publicKey.id)
  }

  @Test func invocationProofBindsTheChallengeAndExactQuery() async throws {
    let alice = try await identity()
    let challenge = try InvocationChallenge(
      domain: "alice.one.example", nonce: Fixture.nonce, expiresAt: backend.now + 120,
      dc: Fixture.dcID, transportKeyID: 42, sessionID: 73)
    let query: [UInt8] = [1, 2, 3, 4, 5]
    let proof = try await alice.prove(InvocationStatement(challenge: challenge, payload: query))

    let received = try BlahProof<InvocationStatement>(encoding: proof.encoding)
    try await received.verify(against: alice.profile, using: backend)
    #expect(received.statement.challenge == challenge)
    #expect(received.statement.matches(query) && !received.statement.matches([1, 2, 3, 4, 6]))

    let elsewhere = try InvocationChallenge(
      domain: "bob.one.example", nonce: Fixture.nonce, expiresAt: backend.now + 120,
      dc: Fixture.dcID, transportKeyID: 42, sessionID: 73)
    await #expect(throws: BlahError.invalidChallenge) {
      try await alice.prove(InvocationStatement(challenge: elsewhere, payload: query))
    }
  }

  @Test func loginProofNamesThisDeviceProfileAndHome() async throws {
    let alice = try await identity()
    func challenge(dc: DCAddress = Fixture.dc, expiresAt: UInt64? = nil, digest: Digest? = nil)
      throws -> LoginChallenge
    {
      try LoginChallenge(
        operation: .signUp, nonce: Fixture.nonce, expiresAt: expiresAt ?? backend.now + 120,
        identityID: alice.id, deviceID: alice.deviceKey.publicKey.id,
        profileDigest: digest ?? alice.profile.digest, dc: dc, authKeyID: 42, sessionID: 73)
    }
    let proof = try await alice.prove(challenge())
    try await BlahProof<LoginChallenge>(encoding: proof.encoding)
      .verify(against: alice.profile, using: backend)
    // A login proof is not an OAuth consent.
    #expect(throws: BlahError.invalidChallenge) {
      try BlahProof<OAuthConsentChallenge>(encoding: proof.encoding)
    }

    let otherDC = try DCAddress(domain: "two.example", id: Digest(hashing: [8]))
    await #expect(throws: BlahError.wrongHome) { try await alice.prove(challenge(dc: otherDC)) }
    await #expect(throws: BlahError.invalidChallenge) {
      try await alice.prove(challenge(digest: Digest(hashing: [])))
    }
    await #expect(throws: BlahError.challengeExpired) {
      try await alice.prove(challenge(expiresAt: backend.now + 121))
    }
    await #expect(throws: BlahError.challengeExpired) {
      try await alice.prove(challenge(expiresAt: backend.now))
    }
    let unhosted = try await identity(home: nil)
    await #expect(throws: BlahError.wrongHome) {
      try await unhosted.prove(OAuthConsentChallenge.sample(expiresAt: backend.now + 60))
    }
  }

  @Test func approvalsRoundTripAndBindTheirHome() async throws {
    let alice = try await identity()
    let consent = try OAuthConsentChallenge.sample(expiresAt: backend.now + 60)
    #expect(try OAuthConsentChallenge(encoding: consent.encoding) == consent)
    try await alice.prove(consent).verify(against: alice.profile, using: backend)

    let link = try AccountLinkChallenge(
      dc: Fixture.dc, nonce: Fixture.nonce, expiresAt: backend.now + 60, operation: .confirm,
      identityID: alice.id, requestID: Fixture.nonce, externalID: "12345", label: "Work")
    #expect(try AccountLinkChallenge(encoding: link.encoding) == link)
    try await alice.prove(link).verify(against: alice.profile, using: backend)
    #expect(throws: BlahError.invalidChallenge) {
      try AccountLinkChallenge(
        dc: Fixture.dc, nonce: Fixture.nonce, expiresAt: 1, operation: .read, externalID: "1")
    }
    #expect(throws: BlahError.invalidChallenge) {
      try AccountLinkChallenge(
        dc: Fixture.dc, nonce: Fixture.nonce, expiresAt: 1, operation: .unlink, externalID: "01")
    }

    let admin = try DCAdminChallenge(
      dc: Fixture.dc, nonce: Fixture.nonce, expiresAt: backend.now + 60, operation: .replace,
      revision: 3, document: [1])
    #expect(try DCAdminChallenge(encoding: admin.encoding) == admin)
    try await alice.prove(admin).verify(against: alice.profile, using: backend)
    #expect(throws: BlahError.invalidChallenge) {
      try DCAdminChallenge(dc: Fixture.dc, nonce: Fixture.nonce, expiresAt: 1, operation: .replace)
    }
  }

  @Test func aRemovedDevicesProofFailsAgainstTheNewProfile() async throws {
    var alice = try await identity()
    let phoneKey = try await DevicePrivateKey.generate(using: backend)
    let phone = try await Identity(
      profile: try await alice.add(phoneKey.publicKey), deviceKey: phoneKey, using: backend)
    let proof = try await phone.prove(OAuthConsentChallenge.sample(expiresAt: backend.now + 60))
    try await proof.verify(against: phone.profile, using: backend)
    let current = try await alice.remove(phoneKey.publicKey.id)
    await #expect(throws: DiemError.deviceNotListed) {
      try await proof.verify(against: current, using: backend)
    }
  }
}

extension OAuthConsentChallenge {
  static func sample(expiresAt: UInt64) throws -> Self {
    try Self(
      dc: Fixture.dc, nonce: Fixture.nonce, expiresAt: expiresAt, appID: 17, appName: "Notes",
      appVersion: 2, redirectURI: "https://notes.example/callback", scopes: ["openid", "profile"],
      codeChallenge: String(repeating: "a", count: 43), state: "s", oidcNonce: "n")
  }
}

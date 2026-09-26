import BlahDiem
import Testing

@Suite struct IdentityInvocationProofTests {
  @Test func signedStatementBindsChallengeAndExactQuery() throws {
    let crypto = SoftwareDeviceCrypto()
    let device = try DeviceSigner(
      signingKey: SoftwareSigningKey(algorithm: .p256Signing),
      wrappingKey: SoftwareWrappingKey(algorithm: .p256Agreement))
    let home = try HomeDelegation(
      homeIdentityID: Array(repeating: 7, count: 32), epoch: 1,
      expiresAt: 1_800_003_600, domains: [ProfileDomain("person.example")])
    let profile = try IdentityController.create(on: device, fields: home.fields, at: 1_800_000_000).profile
    let challenge = try IdentityInvocationChallenge(
      domain: "person.example", nonce: Array(repeating: 9, count: 32),
      expiresAt: 1_800_000_120, destinationID: Array(repeating: 7, count: 32),
      transportKeyID: 42, sessionID: 73)
    let query: [UInt8] = [1, 2, 3, 4, 5]
    let statement = IdentityInvocationStatement(challenge: challenge.encoding, wrappedPayload: query)
    let proof = try device.sign(
      statement.encoding, purpose: .action, profile: profile, at: 1_800_000_000,
      using: crypto)
    try proof.verify(purpose: .action, profile: profile, at: 1_800_000_000, using: crypto)
    let decoded = try IdentityInvocationStatement.decode(proof.payload)
    #expect(try IdentityInvocationChallenge.decode(decoded.challenge) == challenge)
    #expect(decoded.matches(query))
    #expect(!decoded.matches([1, 2, 3, 4, 6]))
    #expect(decoded.encoding == statement.encoding)
  }
}

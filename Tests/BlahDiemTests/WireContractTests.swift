import BlahDiem
import Foundation
import Testing

@Suite struct WireContractTests {
  private let now: UInt64 = 1_800_000_000
  private let key = [UInt8](repeating: 7, count: 32)

  @Test func numericTagsAndProfileFieldsAreExact() throws {
    let destination = try FederationDestination(domain: "one.example", keyID: key)
    let home = try HomeDelegation(homeIdentityID: key, epoch: 1, expiresAt: now + 3600,
      domains: [ProfileDomain("id.one.example")])
    guard case .map(let fields) = home.fields else { Issue.record("home fields are not a map"); return }
    #expect(fields.map(\.key) == [.unsignedInt(0), .unsignedInt(1)])
    let challenge = try DeviceLoginChallenge(operation: .signUp, nonce: key, expiresAt: now + 120,
      identityID: key, deviceID: key, profileDigest: key, destination: destination,
      authKeyID: 42, sessionID: 73)
    let encoded = challenge.encoding
    let values = try CanonicalCBOR.array(encoded, count: 12)
    #expect(values[0] == .unsignedInt(BlahDiemTag.login.rawValue))
    #expect(values[2] == .unsignedInt(1))
    #expect(try DeviceLoginChallenge.decode(encoded).encoding == encoded)
    #expect(throws: (any Error).self) {
      try DeviceLoginChallenge.decode(CBOR.array([.textString("Blah/login")] + Array(values.dropFirst())).encode())
    }
    let reference = try CanonicalReference.identity(key, epoch: 1)
    #expect(try CanonicalReference.decode(reference.encoding) == reference)
    let ref = try CanonicalCBOR.array(reference.encoding, count: 6)
    #expect(ref[0] == .unsignedInt(BlahDiemTag.reference.rawValue))
    #expect(ref[2] == .unsignedInt(1))
  }

  @Test func namespaceAndDelegationShareTheSameProfileContract() throws {
    let federation = try FederationIdentity(domain: "one.example", privateKey: key)
    let device = try DeviceSigner(signingKey: SoftwareSigningKey(algorithm: .ed25519),
      wrappingKey: SoftwareWrappingKey(algorithm: .x25519))
    let home = try HomeDelegation(homeIdentityID: federation.destination.keyID, epoch: 1,
      expiresAt: now + 3600)
    let profile = try IdentityController.create(on: device, fields: home.fields, at: now).profile
    #expect(try HomeDelegation(profile: profile, at: now) == home)
    let namespace = try BlahClientNamespace(profile: profile,
      bootstrap: .init(domain: federation.destination.domain,
        publicKey: Data(federation.signingKey.publicKey.encoding), namespaceVersion: "11"), at: now)
    let fields = try CanonicalCBOR.array(namespace.encoding, count: 7)
    #expect(fields[0] == .unsignedInt(BlahDiemTag.clientNamespace.rawValue))
    #expect(namespace.identifier.count == 64)
  }
}

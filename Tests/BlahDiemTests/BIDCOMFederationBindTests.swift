import BlahDiem
import Foundation
import Testing


@Suite struct FederationBindTests {
  static let a = try! FederationIdentity(
    domain: "a.example", privateKey: Array(repeating: 1, count: 32))
  static let b = try! FederationIdentity(
    domain: "b.example", privateKey: Array(repeating: 2, count: 32))

  @Test func bothSignaturesBindEveryIdentityAndTheLiveSession() throws {
    let a = Self.a
    let b = Self.b
    let binding = try BIDCOMFederationBind(
      source: a.destination, destination: b.destination,
      authKeyID: -42, sessionID: -73, nonce: Array(repeating: 3, count: 32))
    let proof = try binding.signed(by: a)
    #expect(try BIDCOMFederationBind.read(proof) == binding)
    try binding.verify(
      proof, sourceKey: a.device.signingKey.publicKey, destination: b.destination,
      authKeyID: -42, sessionID: -73)
    let accepted = try binding.accepted(by: b)
    let acceptance = BIDCOMFederationAcceptance(bind: binding)
    #expect(try BIDCOMFederationAcceptance.decode(acceptance.encoding) == acceptance)
    try binding.verifyAcceptance(accepted, destinationKey: b.device.signingKey.publicKey)
    for (key, destination, auth, session) in [
      (b.device.signingKey.publicKey, b.destination, Int64(-42), Int64(-73)),
      (a.device.signingKey.publicKey, a.destination, -42, -73),
      (a.device.signingKey.publicKey, b.destination, -43, -73),
      (a.device.signingKey.publicKey, b.destination, -42, -74),
    ] {
      #expect(throws: (any Error).self) {
        try binding.verify(
          proof, sourceKey: key, destination: destination, authKeyID: auth, sessionID: session)
      }
    }
    let next = try BIDCOMFederationBind(
      source: a.destination, destination: b.destination,
      authKeyID: -42, sessionID: -73, nonce: Array(repeating: 4, count: 32))
    #expect(throws: (any Error).self) {
      try next.verifyAcceptance(accepted, destinationKey: b.device.signingKey.publicKey)
    }
    #expect(throws: (any Error).self) {
      try binding.verifyAcceptance(proof, destinationKey: b.device.signingKey.publicKey)
    }
    #expect(throws: (any Error).self) {
      try binding.verifyAcceptance(accepted, destinationKey: a.device.signingKey.publicKey)
    }
    #expect(throws: (any Error).self) { try binding.signed(by: b) }
    #expect(throws: (any Error).self) { try binding.accepted(by: a) }
    var forged = proof
    forged[forged.count - 1] ^= 1
    #expect(throws: (any Error).self) {
      try binding.verify(
        forged, sourceKey: a.device.signingKey.publicKey, destination: b.destination,
        authKeyID: -42, sessionID: -73)
    }
    var forgedAcceptance = accepted
    forgedAcceptance[forgedAcceptance.count - 1] ^= 1
    #expect(throws: (any Error).self) {
      try binding.verifyAcceptance(forgedAcceptance, destinationKey: b.device.signingKey.publicKey)
    }
  }

  @Test func malformedNoncanonicalAndUnboundedTranscriptsFailClosed() throws {
    let binding = try BIDCOMFederationBind(
      source: Self.a.destination, destination: Self.b.destination,
      authKeyID: 42, sessionID: 73, nonce: Array(repeating: 3, count: 32))
    let proof = try binding.signed(by: Self.a)
    for malformed in [
      Data(), proof + Data([0]), Data([0x98, 2]) + proof.dropFirst(),
      Data(repeating: 0, count: 4097),
    ] {
      #expect(throws: (any Error).self) { try BIDCOMFederationBind.read(malformed) }
    }
    for (target, auth, session, nonce) in [
      (Self.a.destination, Int64(42), Int64(73), 32),
      (Self.b.destination, 0, 73, 32), (Self.b.destination, 42, 0, 32),
      (Self.b.destination, 42, 73, 31),
    ] {
      #expect(throws: (any Error).self) {
        try BIDCOMFederationBind(
          source: Self.a.destination, destination: target,
          authKeyID: auth, sessionID: session, nonce: Array(repeating: 3, count: nonce))
      }
    }
  }
}

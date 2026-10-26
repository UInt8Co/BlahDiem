import BlahDiem
import Testing

@Suite struct LinkEncodingVectorTests {
  private func hex(_ text: String) -> [UInt8] {
    let characters = Array(text)
    return stride(from: 0, to: characters.count, by: 2).map {
      UInt8(String(characters[$0...($0 + 1)]), radix: 16)!
    }
  }

  @Test func fixedRequestCodeAndContext() throws {
    let request = try DeviceLinkRequest(
      device: DevicePublicKey(PublicKey(purpose: .device, algorithm: .ed25519,
        rawRepresentation: Array(0..<32))),
      recipient: EncryptionPublicKey(algorithm: .p256, rawRepresentation: hex(
        "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")),
      label: "Desktop", verifies: [.ed25519, .p256])
    let encoded = hex("a600110101025834a500684469656d2f6b6579010302020301045820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f035855a500684469656d2f6b6579010302030304045841046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f504674465736b746f7005820102")
    #expect(request.encoding == encoded)
    #expect(try DeviceLinkRequest(encoding: encoded).encoding == encoded)
    #expect(request.digest.bytes == hex("cf94945a4a5fdc94b7740d5e021ece9ffaf96df295fe8b9b5742f791d84d1cb1"))
    let code = try DeviceLinkCode(requestDigest: request.digest, secret: Array(0..<16))
    #expect(code.encoding == hex("a400120101025820cf94945a4a5fdc94b7740d5e021ece9ffaf96df295fe8b9b5742f791d84d1cb10350000102030405060708090a0b0c0d0e0f"))
    #expect(code.parameter == "pAASAQECWCDPlJRaSl_clLd0DV4CHs6f-vlt8pX-i5tXQveR2E0csQNQAAECAwQFBgcICQoLDA0ODw")
    #expect(try DeviceLinkCode(parameter: code.parameter).matches(encoded))
    #expect(DeviceLinkContext(code: code).encoding == hex("a400140101025820cf94945a4a5fdc94b7740d5e021ece9ffaf96df295fe8b9b5742f791d84d1cb10350000102030405060708090a0b0c0d0e0f"))
  }

  @Test func digestIncludesExtensionsAndBase64IsCanonical() async throws {
    let backend = TestBackend()
    let request = try await DeviceLinkRequest(device: DevicePrivateKey.generate(.ed25519, using: backend).publicKey,
      recipient: backend.makeEncryptionKey(.p256).publicKey, label: "桌面", verifies: [.ed25519])
    var fields = try CBOR(decoding: request.encoding).recordValue(requiredKeys: 0..<6)
    fields[100] = .text("future")
    let extended = CBOR.record(fields).encoded
    let decoded = try DeviceLinkRequest(encoding: extended)
    #expect(decoded.encoding == extended)
    let code = try DeviceLinkCode(request: decoded, using: backend)
    #expect(code.matches(extended))
    #expect(!code.matches(request.encoding))
    #expect(throws: (any Error).self) { try DeviceLinkCode(parameter: code.parameter + "=") }
    #expect(throws: (any Error).self) { try DeviceLinkCode(parameter: "A") }
    // A 58-byte code has four unused low bits in its last base64url character.
    let canonical = try DeviceLinkCode(requestDigest: request.digest, secret: Array(repeating: 0, count: 16))
    #expect(throws: (any Error).self) {
      try DeviceLinkCode(parameter: String(canonical.parameter.dropLast()) + "B")
    }
  }

  @Test func openingRequiresAnExpectedDCAndActiveHome() async throws {
    let backend = TestBackend()
    let recipient = try await backend.makeEncryptionKey(.p256)
    let device = try await DevicePrivateKey.generate(.ed25519, using: backend)
    let request = try DeviceLinkRequest(device: device.publicKey, recipient: recipient.publicKey,
      label: "Desktop", verifies: [.ed25519])
    let code = try DeviceLinkCode(request: request, using: backend)
    let domain = try DomainName("link.example")
    var identity = try await BasicIdentity<UserProfile>(
      HostedContent(home: Fixture.home(account: 42), domains: [domain]),
      identityKey: .generate(.ed25519, using: backend), deviceKey: .generate(.ed25519, using: backend), using: backend)
    try await identity.add(device.publicKey)
    let grant = try DeviceLinkGrant(profile: identity.profile.encoding, domain: domain)
    let response = try await DeviceLinkResponse.seal(grant, for: request, code: code, using: backend)
    await #expect(throws: BlahError.wrongHome) {
      try await DeviceLinkResponse.open(response, recipientKey: recipient, request: request,
        code: code, expectedDC: nil, using: backend)
    }
    // The profile remains valid beyond this independently expiring home delegation.
    await #expect(throws: BlahError.wrongHome) {
      try await DeviceLinkResponse.open(response, recipientKey: recipient, request: request,
        code: code, expectedDC: Fixture.dcID, at: backend.now + 3600, using: backend)
    }
  }
}

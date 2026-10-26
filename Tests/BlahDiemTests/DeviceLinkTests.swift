import BlahDiem
import Foundation
import Testing

/// Contract tests use public records and independently assembled hostile plaintexts.
@Suite struct DeviceLinkTests {
  let backend = TestBackend()
  let domain = try! DomainName("link.example")
  let secret = [UInt8](0..<16)

  func identity(home: Home? = Fixture.home(account: 42), kind: Bool = true)
    async throws -> BasicIdentity<AnyBlahProfile>
  {
    let content = HostedContent(home: home, domains: [domain])
    return try await BasicIdentity(kind ? .user(content) : .bot(content),
      identityKey: .generate(.ed25519, using: backend),
      deviceKey: .generate(.ed25519, using: backend), using: backend)
  }

  func request(label: String = "Desktop", verifies: [PublicKey.Algorithm] = [.ed25519])
    async throws -> (DeviceLinkRequest, EncryptionPrivateKey)
  {
    let recipient = try await backend.makeEncryptionKey(.p256)
    return (try await DeviceLinkRequest(device: DevicePrivateKey.generate(.ed25519, using: backend).publicKey,
      recipient: recipient.publicKey, label: label, verifies: verifies), recipient)
  }

  func code(_ request: DeviceLinkRequest) throws -> DeviceLinkCode {
    try DeviceLinkCode(requestDigest: request.digest, secret: secret)
  }

  func fields(_ bytes: [UInt8]) throws -> [UInt64: CBOR] {
    try CBOR(decoding: bytes).recordValue(requiredKeys: 0..<0)
  }

  func replacing(_ bytes: [UInt8], _ key: UInt64, _ value: CBOR?) throws -> [UInt8] {
    var record = try fields(bytes)
    record[key] = value
    return CBOR.record(record).encoded
  }

  func context(_ code: DeviceLinkCode) -> [UInt8] {
    CBOR.record([0: .unsigned(20), 1: .unsigned(1),
      2: .bytes(code.requestDigest.bytes), 3: .bytes(code.secret)]).encoded
  }

  func plaintext(_ profile: AnyBlahProfile, domain: DomainName? = nil,
    identityKey: SealedIdentityKey? = nil, metadata: [UInt8]? = nil) -> [UInt8]
  {
    var fields: [UInt64: CBOR] = [0: .unsigned(19), 1: .unsigned(1),
      2: .bytes(profile.encoding), 3: .text((domain ?? self.domain).name)]
    if let identityKey { fields[4] = .bytes(identityKey.encoding) }
    if let metadata { fields[5] = .bytes(metadata) }
    return CBOR.record(fields).encoded
  }

  // Bypasses the friendly grant/seal constructors: open must defend itself.
  func rawResponse(_ plaintext: [UInt8], request: DeviceLinkRequest, code: DeviceLinkCode,
    recipient: EncryptionPublicKey? = nil) async throws -> [UInt8]
  {
    let box = try await backend.seal(plaintext, to: recipient ?? request.recipient, context: context(code))
    return CBOR.record([0: .bytes(box.encapsulatedKey), 1: .bytes(box.ciphertext)]).encoded
  }

  @Test func roundTripsAndCanonicalRecords() async throws {
    let (request, _) = try await request()
    let code = try code(request)
    #expect(try DeviceLinkRequest(encoding: request.encoding).encoding == request.encoding)
    #expect(request.digest == Digest(hashing: request.encoding))
    #expect(try DeviceLinkCode(encoding: code.encoding).encoding == code.encoding)
    #expect(try fields(request.encoding) == [0: .unsigned(17), 1: .unsigned(1),
      2: .bytes(request.device.key.encoding), 3: .bytes(request.recipient.encoding),
      4: .text("Desktop"), 5: .array([.unsigned(1)])])
    #expect(try fields(code.encoding) == [0: .unsigned(18), 1: .unsigned(1),
      2: .bytes(request.digest.bytes), 3: .bytes(secret)])
    #expect(try DeviceLinkContext(encoding: context(code)).encoding == context(code))
    for bytes in [request.encoding, code.encoding, context(code)] {
      #expect(try CBOR(decoding: bytes).encoded == bytes)
    }
  }

  @Test func fixedCanonicalEncodingVectors() async throws {
    func hex(_ text: String) -> [UInt8] {
      stride(from: 0, to: text.count, by: 2).map { offset in
        let start = text.index(text.startIndex, offsetBy: offset)
        return UInt8(text[start..<text.index(start, offsetBy: 2)], radix: 16)!
      }
    }
    // Ed25519 seed 07 x 32, P-256 scalar 1; encoded independently with the JS fixture codec.
    let expectedRequest = hex("a600110101025834a500684469656d2f6b6579010302020301045820ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c035855a500684469656d2f6b6579010302030304045841046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5046f496e7465726f70206465736b746f70058101")
    let expectedCode = hex("a40012010102582082c5e613265e617fd26eeff6b2e66860459770a60b6b6614a15aefb66a65a5b50350000102030405060708090a0b0c0d0e0f")
    let expectedContext = hex("a40014010102582082c5e613265e617fd26eeff6b2e66860459770a60b6b6614a15aefb66a65a5b50350000102030405060708090a0b0c0d0e0f")
    let device = try DevicePrivateKey(await backend.makePrivateKey(.ed25519, for: .device,
      restoring: Array(repeating: 7, count: 32)))
    let recipient = try await backend.makeEncryptionKey(.p256, restoring: Array(repeating: 0, count: 31) + [1])
    let request = try DeviceLinkRequest(device: device.publicKey, recipient: recipient.publicKey,
      label: "Interop desktop", verifies: [.ed25519])
    let code = try code(request)
    #expect(request.encoding == expectedRequest)
    #expect(code.encoding == expectedCode)
    #expect(DeviceLinkContext(code: code).encoding == expectedContext)
    #expect(try DeviceLinkRequest(encoding: expectedRequest).encoding == expectedRequest)
    #expect(try DeviceLinkCode(encoding: expectedCode).encoding == expectedCode)
    #expect(try DeviceLinkContext(encoding: expectedContext).encoding == expectedContext)
  }

  @Test func labelBoundsCountUTF8Bytes() async throws {
    for label in ["a", String(repeating: "a", count: 64), String(repeating: "é", count: 32)] {
      let (request, _) = try await request(label: label)
      #expect(try DeviceLinkRequest(encoding: request.encoding).label == label)
    }
    let (valid, _) = try await request()
    for label in ["", String(repeating: "a", count: 65), String(repeating: "é", count: 33)] {
      await #expect(throws: (any Error).self) { try await request(label: label) }
      #expect(throws: (any Error).self) {
        try DeviceLinkRequest(encoding: replacing(valid.encoding, 4, .text(label)))
      }
    }
  }

  @Test func algorithmAndRequestBounds() async throws {
    let (valid, _) = try await request()
    for algorithms: [PublicKey.Algorithm] in [[], [.ed25519, .ed25519]] {
      await #expect(throws: (any Error).self) { try await request(verifies: algorithms) }
      #expect(throws: (any Error).self) {
        try DeviceLinkRequest(encoding: replacing(valid.encoding, 5,
          .array(algorithms.map { .unsigned($0.rawValue) })))
      }
    }
    // Unknown fields count towards the encoded limit, even though their meaning is ignored.
    let overhead = try replacing(valid.encoding, 99, .bytes(Array(repeating: 0, count: 4000))).count - 4000
    let exact = try replacing(valid.encoding, 99, .bytes(Array(repeating: 0, count: 4096 - overhead)))
    #expect(exact.count == 4096)
    _ = try DeviceLinkRequest(encoding: exact)
    let oversized = try replacing(valid.encoding, 99, .bytes(Array(repeating: 0, count: 4097 - overhead)))
    #expect(oversized.count == 4097)
    #expect(throws: (any Error).self) { try DeviceLinkRequest(encoding: oversized) }
  }

  @Test func unknownKeysAndRequiredHeaders() async throws {
    let (request, _) = try await request()
    let code = try code(request)
    let alice = try await identity()
    let encodings = [request.encoding, code.encoding, context(code), plaintext(alice.profile)]
    let decoders: [([UInt8]) throws -> Void] = [
      { _ = try DeviceLinkRequest(encoding: $0) }, { _ = try DeviceLinkCode(encoding: $0) },
      { _ = try DeviceLinkContext(encoding: $0) }, { _ = try DeviceLinkGrant(encoding: $0) },
    ]
    for (bytes, decode) in zip(encodings, decoders) {
      try decode(replacing(bytes, 99, .text("future")))
      for (key, value): (UInt64, CBOR?) in [(0, .unsigned(255)), (1, .unsigned(2)), (0, nil), (1, nil), (2, nil), (3, nil)] {
        #expect(throws: (any Error).self) { try decode(replacing(bytes, key, value)) }
      }
    }
  }

  @Test func codeTextIsStrictBase64URLAndMatchesEveryDigestByte() async throws {
    let (request, _) = try await request()
    let code = try code(request)
    let expected = Data(code.encoding).base64EncodedString()
      .replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
      .replacingOccurrences(of: "=", with: "")
    #expect(code.parameter == expected)
    #expect(try DeviceLinkCode(parameter: expected).encoding == code.encoding)
    #expect(code.matches(request.encoding))
    for index in 0..<32 {
      var digest = request.digest.bytes
      digest[index] ^= 1
      #expect(try !DeviceLinkCode(requestDigest: Digest(bytes: digest), secret: secret).matches(request.encoding))
    }
    for malformed in ["", "=", "A", expected + "=", " " + expected, expected + "\n", "+" + expected, "/" + expected, "💥", String(repeating: "a", count: 4097)] {
      #expect(throws: (any Error).self) { try DeviceLinkCode(parameter: malformed) }
    }
    let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
    let last = alphabet.firstIndex(of: expected.last!)!
    let nonzeroPadBits = String(expected.dropLast()) + String(alphabet[last ^ 1])
    #expect(throws: (any Error).self) { try DeviceLinkCode(parameter: nonzeroPadBits) }
    #expect(throws: (any Error).self) { try DeviceLinkCode(encoding: code.encoding + [0]) }
    for count in [0, 15, 17] {
      #expect(throws: (any Error).self) { try DeviceLinkCode(requestDigest: request.digest, secret: Array(repeating: 0, count: count)) }
      #expect(throws: (any Error).self) { try DeviceLinkCode(encoding: replacing(code.encoding, 3, .bytes(Array(repeating: 0, count: count)))) }
    }
    for count in [0, 31, 33] {
      #expect(throws: (any Error).self) { try DeviceLinkCode(encoding: replacing(code.encoding, 2, .bytes(Array(repeating: 0, count: count)))) }
    }
    let (swapped, _) = try await self.request(label: "Attacker")
    #expect(!code.matches(swapped.encoding))
    #expect(!code.matches(try replacing(request.encoding, 99, .unsigned(1))))
  }

  @Test func grantMetadataAndContextDecodingBounds() async throws {
    let (request, _) = try await request()
    let code = try code(request)
    let alice = try await identity()
    let key = try await #require(alice.identityKey).sealed(to: request.recipient, using: backend)
    for count in [0, 16384] {
      let metadata = Array(repeating: UInt8(42), count: count)
      let decoded = try DeviceLinkGrant(encoding: plaintext(alice.profile, identityKey: key, metadata: metadata))
      #expect(decoded.metadata == metadata)
    }
    #expect(throws: (any Error).self) {
      try DeviceLinkGrant(encoding: plaintext(alice.profile, identityKey: key, metadata: Array(repeating: 42, count: 16385)))
    }
    for metadata: [UInt8] in [[], [1]] {
      #expect(throws: (any Error).self) { try DeviceLinkGrant(encoding: plaintext(alice.profile, metadata: metadata)) }
      #expect(throws: (any Error).self) { try DeviceLinkGrant(profile: alice.profile, domain: domain, metadata: metadata) }
    }
    for count in [0, 15, 17] {
      #expect(throws: (any Error).self) {
        try DeviceLinkContext(encoding: replacing(context(code), 3, .bytes(Array(repeating: 0, count: count))))
      }
    }
    for count in [0, 31, 33] {
      #expect(throws: (any Error).self) {
        try DeviceLinkContext(encoding: replacing(context(code), 2, .bytes(Array(repeating: 0, count: count))))
      }
    }
  }

  @Test func requestValidatesKeyPurposesAndAlgorithms() async throws {
    let (request, _) = try await request()
    let algorithms: [PublicKey.Algorithm] = [.mlDSA65, .ed25519, .p256]
    let varied = try DeviceLinkRequest(device: request.device, recipient: request.recipient,
      label: request.label, verifies: algorithms)
    #expect(Set(try DeviceLinkRequest(encoding: varied.encoding).verifies) == Set(algorithms))
    let identity = try await IdentityPrivateKey.generate(.ed25519, using: backend)
    #expect(throws: (any Error).self) {
      try DeviceLinkRequest(encoding: replacing(request.encoding, 2, .bytes(identity.publicKey.key.encoding)))
    }
    for field: UInt64 in [2, 3, 4, 5] {
      for invalid: CBOR? in [nil, .unsigned(0), .text("wrong type")] {
        if field == 4 && invalid == .text("wrong type") { continue }
        #expect(throws: (any Error).self) { try DeviceLinkRequest(encoding: replacing(request.encoding, field, invalid)) }
      }
    }
    #expect(throws: (any Error).self) {
      try DeviceLinkRequest(encoding: replacing(request.encoding, 5, .array([.unsigned(999)])))
    }
    let x25519 = try await backend.makeEncryptionKey(.x25519)
    #expect(throws: (any Error).self) {
      try DeviceLinkRequest(device: request.device, recipient: x25519.publicKey, label: request.label, verifies: [.ed25519])
    }
    #expect(throws: (any Error).self) {
      try DeviceLinkRequest(encoding: replacing(request.encoding, 3, .bytes(x25519.publicKey.encoding)))
    }
  }

  @Test func correctGrantsOpenAndPreserveExactPublishedProfile() async throws {
    let (request, recipient) = try await request()
    let code = try code(request)
    var alice = try await identity()
    try await alice.add(request.device)
    for transfer in [false, true] {
      let sealed = try await transfer ? #require(alice.identityKey).sealed(to: request.recipient, using: backend) : nil
      let metadata: [UInt8]? = transfer ? [0, 255, 1, 128] : nil
      let grant = try DeviceLinkGrant(encoding: plaintext(alice.profile, identityKey: sealed, metadata: metadata))
      #expect(grant.encoding == plaintext(alice.profile, identityKey: sealed, metadata: metadata))
      let response = try await DeviceLinkResponse.seal(grant, for: request, code: code, using: backend)
      let opened = try await DeviceLinkResponse.open(response, recipientKey: recipient, request: request,
        code: code, expectedDC: Fixture.dcID, at: backend.now, using: backend)
      #expect(opened.grant.profile == alice.profile.encoding)
      #expect(opened.grant.metadata == metadata)
      #expect(opened.identityKey?.publicKey == (transfer ? alice.profile.identityKey : nil))
      // Independent context construction must also produce an interoperable response.
      let raw = try await rawResponse(grant.encoding, request: request, code: code)
      _ = try await DeviceLinkResponse.open(raw, recipientKey: recipient, request: request,
        code: code, expectedDC: Fixture.dcID, at: backend.now, using: backend)
    }
  }

  @Test func rejectsWrongSecretsDigestsRecipientsAndTampering() async throws {
    let (request, recipient) = try await request()
    let code = try code(request)
    var alice = try await identity()
    try await alice.add(request.device)
    let grant = plaintext(alice.profile)
    let response = try await rawResponse(grant, request: request, code: code)
    var tampered = response
    tampered[tampered.count - 1] ^= 1
    let other = try await backend.makeEncryptionKey(.p256)
    let wrongSecret = try DeviceLinkCode(requestDigest: request.digest, secret: Array(repeating: 99, count: 16))
    let wrongDigest = try DeviceLinkCode(requestDigest: Digest(hashing: [1]), secret: secret)
    for candidate in [wrongSecret, wrongDigest] {
      await #expect(throws: (any Error).self) {
        try await DeviceLinkResponse.open(response, recipientKey: recipient, request: request,
          code: candidate, expectedDC: Fixture.dcID, at: backend.now, using: backend)
      }
    }
    // Even a valid ciphertext under the caller's wrong digest cannot authorize the request.
    let wrongBinding = try await rawResponse(grant, request: request, code: wrongDigest)
    for bytes in [tampered, try await rawResponse(grant, request: request, code: code, recipient: other.publicKey), wrongBinding] {
      await #expect(throws: (any Error).self) {
        try await DeviceLinkResponse.open(bytes, recipientKey: recipient, request: request,
          code: bytes == wrongBinding ? wrongDigest : code, expectedDC: Fixture.dcID, at: backend.now, using: backend)
      }
    }
    await #expect(throws: (any Error).self) {
      try await DeviceLinkResponse.open(response, recipientKey: other, request: request,
        code: code, expectedDC: Fixture.dcID, at: backend.now, using: backend)
    }
  }

  @Test func rejectsUnauthorizingProfilesAndCustody() async throws {
    let (request, recipient) = try await request()
    let code = try code(request)
    var alice = try await identity()
    let beforeAdding = alice.profile
    try await alice.add(request.device)
    let certified = alice.profile
    let removed = try await alice.remove(request.device.id)
    #expect(removed.generation > certified.generation)
    var unallocated = try await identity(home: Fixture.home())
    try await unallocated.add(request.device)
    var homeless = try await identity(home: nil)
    try await homeless.add(request.device)
    var bot = try await identity(kind: false)
    try await bot.add(request.device)
    // A relay cannot resurrect an old certificate by appending it to the new generation.
    var oldCertificateEnvelope = try fields(removed.encoding)
    let stale = try #require(certified.devices.first { $0.device == request.device })
    oldCertificateEnvelope[3] = .array(removed.devices.map { .bytes($0.encoding) } + [.bytes(stale.encoding)])
    let staleCertificateGrant = try replacing(plaintext(removed), 2, .bytes(CBOR.record(oldCertificateEnvelope).encoded))
    let otherIdentity = try await identity()
    let foreignKey = try await #require(otherIdentity.identityKey).sealed(to: request.recipient, using: backend)
    let validKey = try await #require(alice.identityKey).sealed(to: request.recipient, using: backend)
    var shortLived = try await BasicIdentity<AnyBlahProfile>(
      .user(HostedContent(home: Fixture.home(account: 42), domains: [domain])),
      identityKey: #require(alice.identityKey), deviceKey: alice.deviceKey,
      profileLifetime: 60, using: backend)
    try await shortLived.add(request.device)
    #expect(shortLived.profile.validity.expiresAt < shortLived.profile.home!.expiresAt)
    #expect(shortLived.profile.validity.expiresAt < shortLived.profile.devices[0].validity.expiresAt)
    var corruptedProfile = certified.encoding
    corruptedProfile[corruptedProfile.count - 1] ^= 1
    let tamperedProfileGrant = try replacing(plaintext(certified), 2, .bytes(corruptedProfile))
    var corruptedKey = validKey.encoding
    corruptedKey[corruptedKey.count - 1] ^= 1
    let tamperedIdentityGrant = try replacing(plaintext(certified), 4, .bytes(corruptedKey))
    let wrongRecipient = try await backend.makeEncryptionKey(.p256)
    let wrongRecipientIdentity = try await #require(alice.identityKey).sealed(to: wrongRecipient.publicKey, using: backend)
    let cases: [(String, [UInt8], Digest, UInt64)] = [
      ("before adding", plaintext(beforeAdding), Fixture.dcID, backend.now),
      ("removed device", plaintext(removed), Fixture.dcID, backend.now),
      ("old certificate in new generation", staleCertificateGrant, Fixture.dcID, backend.now),
      ("unlisted domain", plaintext(certified, domain: try DomainName("evil.example")), Fixture.dcID, backend.now),
      ("wrong DC", plaintext(certified), Digest(hashing: [55]), backend.now),
      ("unallocated account", plaintext(unallocated.profile), Fixture.dcID, backend.now),
      ("no home", plaintext(homeless.profile), Fixture.dcID, backend.now),
      ("bot profile", plaintext(bot.profile), Fixture.dcID, backend.now),
      ("expired profile with live home and certificates", plaintext(shortLived.profile), Fixture.dcID, shortLived.profile.validity.expiresAt),
      ("not yet valid", plaintext(certified), Fixture.dcID, certified.validity.notBefore - 1),
      ("wrong identity key", plaintext(certified, identityKey: foreignKey), Fixture.dcID, backend.now),
      ("tampered profile signature", tamperedProfileGrant, Fixture.dcID, backend.now),
      ("tampered inner identity ciphertext", tamperedIdentityGrant, Fixture.dcID, backend.now),
      ("identity key sealed to other recipient", plaintext(certified, identityKey: wrongRecipientIdentity), Fixture.dcID, backend.now),
      ("metadata without identity", plaintext(certified, metadata: [1]), Fixture.dcID, backend.now),
      ("another identity profile", plaintext(otherIdentity.profile, identityKey: foreignKey), Fixture.dcID, backend.now),
    ]
    for (name, plain, dc, now) in cases {
      let response = try await rawResponse(plain, request: request, code: code)
      await #expect(throws: (any Error).self, Comment(rawValue: name)) {
        try await DeviceLinkResponse.open(response, recipientKey: recipient, request: request,
          code: code, expectedDC: dc, at: now, using: backend)
      }
    }
  }

  @Test func exactResponseSizeBoundaryAndSealRequestBinding() async throws {
    let (request, recipient) = try await request()
    let code = try code(request)
    var alice = try await identity()
    try await alice.add(request.device)
    let plain = plaintext(alice.profile)
    let sample = try replacing(plain, 99, .bytes(Array(repeating: 0, count: 60000)))
    let overhead = try await rawResponse(sample, request: request, code: code).count - 60000
    for size in [65536, 65537] {
      let padded = try replacing(plain, 99, .bytes(Array(repeating: 0, count: size - overhead)))
      let response = try await rawResponse(padded, request: request, code: code)
      #expect(response.count == size)
      let grant = try DeviceLinkGrant(encoding: padded)
      if size == 65536 {
        _ = try await DeviceLinkResponse.open(response, recipientKey: recipient, request: request,
          code: code, expectedDC: Fixture.dcID, at: backend.now, using: backend)
        #expect(try await DeviceLinkResponse.seal(grant, for: request, code: code, using: backend).count == size)
      } else {
        await #expect(throws: (any Error).self) {
          try await DeviceLinkResponse.open(response, recipientKey: recipient, request: request,
            code: code, expectedDC: Fixture.dcID, at: backend.now, using: backend)
        }
        await #expect(throws: (any Error).self) {
          try await DeviceLinkResponse.seal(grant, for: request, code: code, using: backend)
        }
      }
    }
    let grant = try DeviceLinkGrant(encoding: plain)
    let wrongDigest = try DeviceLinkCode(requestDigest: Digest(hashing: [42]), secret: secret)
    await #expect(throws: (any Error).self) {
      try await DeviceLinkResponse.seal(grant, for: request, code: wrongDigest, using: backend)
    }
  }

  @Test func approverChecksBothSigningAlgorithmsBeforeCertifying() async throws {
    let (request, _) = try await request()
    let edIdentity = try await IdentityPrivateKey.generate(.ed25519, using: backend)
    let p256Identity = try await IdentityPrivateKey.generate(.p256, using: backend)
    let edDevice = try await DevicePrivateKey.generate(.ed25519, using: backend)
    let p256Device = try await DevicePrivateKey.generate(.p256, using: backend)
    try request.requireCompatible(identityKey: edIdentity.publicKey, device: edDevice.publicKey)
    #expect(throws: (any Error).self) {
      try request.requireCompatible(identityKey: p256Identity.publicKey, device: edDevice.publicKey)
    }
    #expect(throws: (any Error).self) {
      try request.requireCompatible(identityKey: edIdentity.publicKey, device: p256Device.publicKey)
    }
  }

  @Test func metadataAndResponseBoundsApplyToDecoding() async throws {
    let (request, recipient) = try await request()
    let code = try code(request)
    var alice = try await identity()
    try await alice.add(request.device)
    let sealed = try await #require(alice.identityKey).sealed(to: request.recipient, using: backend)
    for count in [0, 16384] {
      let plain = plaintext(alice.profile, identityKey: sealed, metadata: Array(repeating: 42, count: count))
      _ = try DeviceLinkGrant(encoding: plain)
      let response = try await rawResponse(plain, request: request, code: code)
      let opened = try await DeviceLinkResponse.open(response, recipientKey: recipient, request: request,
        code: code, expectedDC: Fixture.dcID, at: backend.now, using: backend)
      #expect(opened.grant.metadata?.count == count)
    }
    let over = plaintext(alice.profile, identityKey: sealed, metadata: Array(repeating: 42, count: 16385))
    #expect(throws: (any Error).self) { try DeviceLinkGrant(encoding: over) }
    for plain in [over, plaintext(alice.profile, metadata: [])] {
      let response = try await rawResponse(plain, request: request, code: code)
      await #expect(throws: (any Error).self) {
        try await DeviceLinkResponse.open(response, recipientKey: recipient, request: request,
          code: code, expectedDC: Fixture.dcID, at: backend.now, using: backend)
      }
    }
    let large = try replacing(plaintext(alice.profile), 99, .bytes(Array(repeating: 0, count: 65536)))
    let response = try await rawResponse(large, request: request, code: code)
    #expect(response.count > 65536)
    await #expect(throws: (any Error).self) {
      try await DeviceLinkResponse.open(response, recipientKey: recipient, request: request,
        code: code, expectedDC: Fixture.dcID, at: backend.now, using: backend)
    }
  }
}

extension DeviceLinkTests {
  struct InteropVector: Codable {
    let request: [UInt8]
    let parameter: String
    let code: [UInt8]
    let context: [UInt8]
    let response: [UInt8]
    let deviceOnlyResponse: [UInt8]
    let profile: [UInt8]
    let dc: [UInt8]
    let now: UInt64
    let domain: String
    let recipientSecret: [UInt8]
    let deviceSecret: [UInt8]
    let identitySecret: [UInt8]
    let signerSecret: [UInt8]
    let metadata: [UInt8]
  }

  static var vectorDirectory: URL {
    URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
      .deletingLastPathComponent().appendingPathComponent("Web/tests")
  }

  /// Run explicitly to refresh fixtures; normal test runs only read the checked-in vectors.
  @Test func nativeBrowserFixtures() async throws {
    let nativeURL = Self.vectorDirectory.appendingPathComponent("device-link-native.json")
    if ProcessInfo.processInfo.environment["BLAH_DEVICE_LINK_GENERATE"] == "1" {
      let recipientSecret = Array(repeating: UInt8(0), count: 31) + [1]
      let deviceSecret = Array(repeating: UInt8(7), count: 32)
      let identitySecret = Array(repeating: UInt8(8), count: 32)
      let signerSecret = Array(repeating: UInt8(9), count: 32)
      let recipient = try await backend.makeEncryptionKey(.p256, restoring: recipientSecret)
      let device = try DevicePrivateKey(await backend.makePrivateKey(.ed25519, for: .device, restoring: deviceSecret))
      let root = try IdentityPrivateKey(await backend.makePrivateKey(.ed25519, for: .identity, restoring: identitySecret))
      let signer = try DevicePrivateKey(await backend.makePrivateKey(.ed25519, for: .device, restoring: signerSecret))
      var alice = try await BasicIdentity<AnyBlahProfile>(
        .user(HostedContent(home: Fixture.home(account: 42), domains: [domain])),
        identityKey: root, deviceKey: signer, using: backend)
      let request = try DeviceLinkRequest(device: device.publicKey, recipient: recipient.publicKey,
        label: "Interop desktop", verifies: [.ed25519])
      let code = try code(request)
      try await alice.add(device.publicKey)
      let metadata: [UInt8] = [0xa1, 0x18, 0x63, 0x43, 0, 255, 128] // Opaque future application metadata.
      let sealed = try await root.sealed(to: request.recipient, using: backend)
      let grant = try DeviceLinkGrant(encoding: plaintext(alice.profile, identityKey: sealed, metadata: metadata))
      let deviceOnly = try DeviceLinkGrant(encoding: plaintext(alice.profile))
      let vector = try await InteropVector(request: request.encoding, parameter: code.parameter,
        code: code.encoding, context: context(code),
        response: DeviceLinkResponse.seal(grant, for: request, code: code, using: backend),
        deviceOnlyResponse: DeviceLinkResponse.seal(deviceOnly, for: request, code: code, using: backend),
        profile: alice.profile.encoding, dc: Fixture.dcID.bytes, now: backend.now, domain: domain.name,
        recipientSecret: recipientSecret, deviceSecret: deviceSecret, identitySecret: identitySecret,
        signerSecret: signerSecret, metadata: metadata)
      let encoder = JSONEncoder()
      encoder.outputFormatting = [.sortedKeys]
      try encoder.encode(vector).write(to: nativeURL)
    }
    let vector = try JSONDecoder().decode(InteropVector.self, from: Data(contentsOf: nativeURL))
    let request = try DeviceLinkRequest(encoding: vector.request)
    let code = try DeviceLinkCode(parameter: vector.parameter)
    let recipient = try await backend.makeEncryptionKey(.p256, restoring: vector.recipientSecret)
    #expect(code.encoding == vector.code)
    #expect(context(code) == vector.context)
    #expect(request.encoding == vector.request)
    let opened = try await DeviceLinkResponse.open(vector.response, recipientKey: recipient,
      request: request, code: code, expectedDC: Digest(bytes: vector.dc), at: vector.now, using: backend)
    #expect(opened.grant.profile == vector.profile)
    #expect(opened.grant.metadata == vector.metadata)
    #expect(opened.identityKey?.rawRepresentation == vector.identitySecret)
    struct BrowserVector: Codable { let engine: String; let realm: String; let response: [UInt8]; let deviceOnlyResponse: [UInt8] }
    struct BrowserVectors: Codable { let vectors: [BrowserVector] }
    let browserURL = Self.vectorDirectory.appendingPathComponent("device-link-browser.json")
    if ProcessInfo.processInfo.environment["BLAH_DEVICE_LINK_GENERATE"] == "1" &&
      !FileManager.default.fileExists(atPath: browserURL.path) { return }
    let browsers = try JSONDecoder().decode(BrowserVectors.self, from: Data(contentsOf: browserURL))
    #expect(!browsers.vectors.isEmpty)
    for browser in browsers.vectors {
      for (response, transfers) in [(browser.response, true), (browser.deviceOnlyResponse, false)] {
        let opened = try await DeviceLinkResponse.open(response, recipientKey: recipient,
          request: request, code: code, expectedDC: Digest(bytes: vector.dc), at: vector.now, using: backend)
        #expect(opened.grant.profile == vector.profile, "\(browser.engine) \(browser.realm)")
        #expect(opened.grant.metadata == (transfers ? vector.metadata : nil))
        #expect(opened.identityKey?.rawRepresentation == (transfers ? vector.identitySecret : nil))
      }
    }
  }
}

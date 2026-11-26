import BlahDiem
import DiemTesting
import Foundation
import Testing

/// Blah's acceptance rules and metadata on Diem's device linking. Diem's own tests cover
/// the records, their bounds and the HPKE binding.
@Suite struct DeviceLinkTests {
  let backend = TestBackend()
  let domain = try! DomainName("link.example")
  let secret = [UInt8](0..<16)
  let seed = try! IdentitySeed(entropy: Array(repeating: 8, count: 32))

  func identity(home: Home? = Fixture.home(account: 42), user: Bool = true)
    async throws -> BasicIdentity<AnyBlahProfile>
  {
    let content = HostedContent(home: home, domains: [domain])
    return try await BasicIdentity(user ? .user(content) : .bot(content),
      identityKey: seed.identityKey(.ed25519, using: backend),
      deviceKey: .generate(.ed25519, using: backend), using: backend)
  }

  func request() async throws -> (DeviceLinkRequest, EncryptionPrivateKey, DeviceLinkCode) {
    let recipient = try await backend.makeEncryptionKey(.p256)
    let request = try await DeviceLinkRequest(
      device: DevicePrivateKey.generate(.ed25519, using: backend).publicKey,
      recipient: recipient.publicKey, label: "Desktop", verifies: [.ed25519])
    return (request, recipient, try DeviceLinkCode(requestDigest: request.digest, secret: secret))
  }

  /// A grant record assembled without Blah's checks: `open` must defend itself.
  func plaintext(_ profile: AnyBlahProfile, seed: SealedIdentitySeed? = nil, blah: CBOR? = nil)
    -> [UInt8]
  {
    var fields: [UInt64: CBOR] = [0: .text("Diem/device-link-grant"), 1: .unsigned(1),
      2: .bytes(profile.encoding), 3: .text(domain.name)]
    if let seed { fields[4] = .bytes(seed.encoding) }
    return CBOR.record(fields, applications: blah.map { [.blah: $0] } ?? [:]).encoded
  }

  func rawResponse(_ plaintext: [UInt8], request: DeviceLinkRequest, code: DeviceLinkCode)
    async throws -> [UInt8]
  {
    let box = try await backend.seal(plaintext, to: request.recipient,
      context: DeviceLinkContext(code: code).encoding)
    return CBOR.record([0: .bytes(box.encapsulatedKey), 1: .bytes(box.ciphertext)]).encoded
  }

  @Test func metadataTravelsAtBlahsKeyOnlyWithSeedTransfer() async throws {
    let (request, recipient, code) = try await request()
    var alice = try await identity()
    try await alice.add(request.device)
    let sealed = try await seed.sealed(to: request.recipient, identity: alice.profile.identityKey,
      using: backend)
    for transfer in [false, true] {
      let metadata: [UInt8]? = transfer ? [0, 255, 1, 128] : nil
      let grant = try DeviceLinkGrant(profile: alice.profile, domain: domain,
        seed: transfer ? sealed : nil, metadata: metadata)
      #expect(grant.encoding == plaintext(alice.profile, seed: transfer ? sealed : nil,
        blah: metadata.map(CBOR.bytes)))
      let response = try await DeviceLinkResponse.seal(grant, for: request, code: code, using: backend)
      let opened = try await DeviceLinkResponse.open(response, recipientKey: recipient,
        request: request, code: code, expectedDC: Fixture.dcID, using: backend)
      #expect(opened.grant.profile == alice.profile.encoding && opened.profile == alice.profile)
      #expect(opened.grant.metadata == metadata)
      #expect(opened.seed?.entropy == (transfer ? seed.entropy : nil))
    }
    _ = try DeviceLinkGrant(profile: alice.profile, domain: domain, seed: sealed,
      metadata: Array(repeating: 42, count: DeviceLinkGrant.maximumMetadataBytes))
    for (seed, metadata): (SealedIdentitySeed?, [UInt8]) in [(nil, [1]), (sealed, Array(repeating: 42, count: 16_385))] {
      #expect(throws: BlahError.invalidDeviceLink) {
        try DeviceLinkGrant(profile: alice.profile, domain: domain, seed: seed, metadata: metadata)
      }
    }
    for (seed, blah): (SealedIdentitySeed?, CBOR) in [(nil, .bytes([1])), (sealed, .text("x"))] {
      let response = try await rawResponse(plaintext(alice.profile, seed: seed, blah: blah),
        request: request, code: code)
      await #expect(throws: BlahError.invalidDeviceLink) {
        try await DeviceLinkResponse.open(response, recipientKey: recipient, request: request,
          code: code, expectedDC: Fixture.dcID, using: backend)
      }
    }
  }

  @Test func opensOnlyAnAllocatedUserHomedAtTheExpectedDC() async throws {
    let (request, recipient, code) = try await request()
    var alice = try await identity()
    try await alice.add(request.device)
    var unallocated = try await identity(home: Fixture.home())
    try await unallocated.add(request.device)
    var homeless = try await identity(home: nil)
    try await homeless.add(request.device)
    var bot = try await identity(user: false)
    try await bot.add(request.device)
    let cases: [(String, AnyBlahProfile, Digest?, UInt64, BlahError)] = [
      ("no expected DC", alice.profile, nil, backend.now, .wrongHome),
      ("wrong DC", alice.profile, Digest(hashing: [55]), backend.now, .wrongHome),
      // The profile remains valid beyond this independently expiring home delegation.
      ("expired home", alice.profile, Fixture.dcID, Fixture.home().expiresAt, .wrongHome),
      ("unallocated account", unallocated.profile, Fixture.dcID, backend.now, .wrongHome),
      ("no home", homeless.profile, Fixture.dcID, backend.now, .wrongHome),
      ("bot profile", bot.profile, Fixture.dcID, backend.now, .invalidProfile),
    ]
    for (name, profile, dc, time, error) in cases {
      let response = try await rawResponse(plaintext(profile), request: request, code: code)
      await #expect(throws: error, Comment(rawValue: name)) {
        try await DeviceLinkResponse.open(response, recipientKey: recipient, request: request,
          code: code, expectedDC: dc, at: time, using: backend)
      }
    }
    // The approver refuses to seal what the new device would refuse to open.
    let grant = try DeviceLinkGrant(profile: bot.profile, domain: domain)
    await #expect(throws: BlahError.invalidProfile) {
      try await DeviceLinkResponse.seal(grant, for: request, code: code, using: backend)
    }
    #expect(try await DeviceLinkGrant(profile: alice.profile, domain: domain)
      .verify(for: request, expectedDC: Fixture.dcID, using: backend) == alice.profile)
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
    let entropy: [UInt8]
    let signerSecret: [UInt8]
    let metadata: [UInt8]
  }

  static var vectorDirectory: URL {
    URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
      .deletingLastPathComponent().appendingPathComponent("Web/tests")
  }

  /// Native responses the web runtime opens, and its browsers' responses opened natively.
  /// Set `BLAH_DEVICE_LINK_GENERATE=1` to rewrite the native fixture; the web tests
  /// rewrite the browser fixture, which this test checks whenever it exists.
  @Test func nativeBrowserFixtures() async throws {
    let nativeURL = Self.vectorDirectory.appendingPathComponent("device-link-native.json")
    if ProcessInfo.processInfo.environment["BLAH_DEVICE_LINK_GENERATE"] == "1" {
      let recipientSecret = Array(repeating: UInt8(0), count: 31) + [1]
      let deviceSecret = Array(repeating: UInt8(7), count: 32)
      let entropy = Array(repeating: UInt8(8), count: 32)
      let signerSecret = Array(repeating: UInt8(9), count: 32)
      let recipient = try await backend.makeEncryptionKey(.p256, restoring: recipientSecret)
      let device = try DevicePrivateKey(await backend.makePrivateKey(.p256, for: .device, restoring: deviceSecret))
      let seed = try IdentitySeed(entropy: entropy)
      let root = try await seed.identityKey(.ed25519, using: backend)
      let signer = try DevicePrivateKey(await backend.makePrivateKey(.p256, for: .device, restoring: signerSecret))
      var alice = try await BasicIdentity<AnyBlahProfile>(
        .user(HostedContent(home: Fixture.home(account: 42), domains: [domain])),
        identityKey: root, deviceKey: signer, using: backend)
      let request = try DeviceLinkRequest(device: device.publicKey, recipient: recipient.publicKey,
        label: "Interop desktop", verifies: [.ed25519, .p256])
      let code = try DeviceLinkCode(requestDigest: request.digest, secret: secret)
      try await alice.add(device.publicKey)
      let metadata: [UInt8] = [0xa1, 0x18, 0x63, 0x43, 0, 255, 128] // Opaque future application metadata.
      let sealed = try await seed.sealed(to: request.recipient, identity: root.publicKey, using: backend)
      let grant = try DeviceLinkGrant(profile: alice.profile, domain: domain, seed: sealed,
        metadata: metadata)
      let deviceOnly = try DeviceLinkGrant(profile: alice.profile, domain: domain)
      let vector = try await InteropVector(request: request.encoding, parameter: code.parameter,
        code: code.encoding, context: DeviceLinkContext(code: code).encoding,
        response: DeviceLinkResponse.seal(grant, for: request, code: code, using: backend),
        deviceOnlyResponse: DeviceLinkResponse.seal(deviceOnly, for: request, code: code, using: backend),
        profile: alice.profile.encoding, dc: Fixture.dcID.bytes, now: backend.now, domain: domain.name,
        recipientSecret: recipientSecret, deviceSecret: deviceSecret, entropy: entropy,
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
    #expect(DeviceLinkContext(code: code).encoding == vector.context)
    #expect(request.encoding == vector.request)
    let opened = try await DeviceLinkResponse.open(vector.response, recipientKey: recipient,
      request: request, code: code, expectedDC: Digest(bytes: vector.dc), at: vector.now, using: backend)
    #expect(opened.grant.profile == vector.profile)
    #expect(opened.grant.metadata == vector.metadata)
    #expect(opened.seed?.entropy == vector.entropy)
    struct BrowserVector: Codable { let engine: String; let realm: String; let response: [UInt8]; let deviceOnlyResponse: [UInt8] }
    struct BrowserVectors: Codable { let vectors: [BrowserVector] }
    let browserURL = Self.vectorDirectory.appendingPathComponent("device-link-browser.json")
    guard FileManager.default.fileExists(atPath: browserURL.path) else { return }
    let browsers = try JSONDecoder().decode(BrowserVectors.self, from: Data(contentsOf: browserURL))
    #expect(!browsers.vectors.isEmpty)
    for browser in browsers.vectors {
      for (response, transfers) in [(browser.response, true), (browser.deviceOnlyResponse, false)] {
        let opened = try await DeviceLinkResponse.open(response, recipientKey: recipient,
          request: request, code: code, expectedDC: Digest(bytes: vector.dc), at: vector.now, using: backend)
        #expect(opened.grant.profile == vector.profile, "\(browser.engine) \(browser.realm)")
        #expect(opened.grant.metadata == (transfers ? vector.metadata : nil))
        #expect(opened.seed?.entropy == (transfers ? vector.entropy : nil))
      }
    }
  }
}

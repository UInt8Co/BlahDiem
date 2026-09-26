import BlahDiem
import Crypto
import DiemSwiftCrypto
import Testing

private let now: UInt64 = 1_800_000_000
private let crypto = SoftwareDeviceCrypto()
private func fields(_ name: String) -> CBOR {
  .map([CBORMapPair(key: .unsignedInt(0), value: .textString(name))])
}
private struct Fixture {
  let device: DeviceSigner
  let created: IdentityController.Creation
  init(signing: KeyAlgorithm = .ed25519, wrapping: KeyAlgorithm = .x25519) throws {
    device = try crypto.makeDevice(signing: signing, wrapping: wrapping)
    created = try IdentityController.create(on: device, fields: fields("Alice"), at: now)
  }
  func profile(
    revision: UInt64 = 2, name: String = "Bob", signer: DeviceSigner? = nil,
    list: SignedDeviceList? = nil
  ) throws -> SignedProfile {
    try (signer ?? device).signProfile(
      identityKey: created.profile.identityKey,
      deviceList: list ?? created.profile.deviceList, revision: revision,
      previousDigest: revision == 1 ? [] : created.profile.digest(using: crypto),
      validity: .init(notBefore: now, expiresAt: now + 1000), fields: fields(name), at: now,
      using: crypto)
  }
  func enrollment(for device: DeviceSigner) throws -> (
    PendingDeviceEnrollment, EnrollmentConfirmation
  ) {
    let request = try device.enrollmentRequest(
      identityID: created.profile.id, at: now, using: crypto)
    let pending = try PendingDeviceEnrollment(
      request: request,
      confirmedPairingDigest: request.digest(using: crypto), at: now, using: crypto)
    return (pending, try device.confirmEnrollment(pending, at: now, using: crypto))
  }
}

@Suite struct DeviceAuthorityTests {
  @Test(arguments: [KeyAlgorithm.ed25519, .p256Signing], [KeyAlgorithm.x25519, .p256Agreement])
  func independentAlgorithms(signing: KeyAlgorithm, wrapping: KeyAlgorithm) throws {
    let f = try Fixture(signing: signing, wrapping: wrapping)
    #expect(f.device.signingKey.protection == .software)
    #expect(f.device.wrappingKey.protection == .software)
    #expect(f.created.profile.id.count == 32)
    #expect(f.created.profile.id == f.created.profile.identityKey.id(using: crypto))
    #expect(f.created.profile.deviceList.body.devices.count == 1)
    let decoded = try SignedProfile.decode(f.created.profile.encoding)
    try decoded.verify(at: now, using: crypto)
    #expect(decoded.encoding == f.created.profile.encoding)
    #expect(
      f.device.signingKey.publicKey.id(using: crypto)
        != f.device.wrappingKey.publicKey.id(using: crypto))
    let renewed = try IdentityController.renew(
      profile: decoded, controller: f.device,
      envelope: .decode(f.created.envelope.encoding), at: now)
    try renewed.verify(identityKey: decoded.identityKey, at: now, using: crypto)
  }

  @Test func ordinaryEnrollmentHasNoRootAndCanUpdateHome() throws {
    let f = try Fixture()
    let ordinary = try crypto.makeDevice()
    let (pending, confirmation) = try f.enrollment(for: ordinary)
    let result = try IdentityController.enroll(
      pending, confirmation: confirmation,
      profile: f.created.profile, controller: f.device, envelope: f.created.envelope, at: now)
    #expect(result.controllerEnvelope == nil)
    #expect(result.deviceList.body.devices.last?.identityController == false)
    let updated = try f.profile(
      revision: 1, name: "new-home.example", signer: ordinary, list: result.deviceList)
    try updated.verify(at: now, using: crypto)
    #expect(throws: DeviceIdentityError.controllerRequired) {
      try IdentityController.renew(
        profile: updated, controller: ordinary, envelope: f.created.envelope, at: now)
    }
    // Neither a public profile nor its ordinary entry has a controller envelope field.
    #expect(updated.encoding.count < 2000)
  }

  @Test func explicitControllerPromotionCanRenewRoster() throws {
    let f = try Fixture()
    let second = try crypto.makeDevice(signing: .p256Signing, wrapping: .p256Agreement)
    let (pending, confirmation) = try f.enrollment(for: second)
    let result = try IdentityController.enroll(
      pending, confirmation: confirmation,
      grant: .identityControllerAcknowledgingPermanentRootTrust,
      profile: f.created.profile, controller: f.device, envelope: f.created.envelope, at: now)
    let envelope = try #require(result.controllerEnvelope)
    #expect(envelope.recipient.identityController)
    let profile = try f.profile(revision: 1, signer: second, list: result.deviceList)
    let next = try IdentityController.renew(
      profile: profile, controller: second, envelope: envelope, at: now)
    #expect(next.body.revision == 3)
  }

  @Test func pairingAndBothKeyPossessionsAreRequired() throws {
    let f = try Fixture()
    let second = try crypto.makeDevice()
    let attacker = try crypto.makeDevice()
    let request = try second.enrollmentRequest(
      identityID: f.created.profile.id, at: now, using: crypto)
    #expect(throws: DeviceIdentityError.pairingNotConfirmed) {
      try PendingDeviceEnrollment(
        request: request, confirmedPairingDigest: [0], at: now, using: crypto)
    }
    let (pending, confirmation) = try f.enrollment(for: second)
    #expect(throws: (any Error).self) {
      try attacker.wrappingKey.open(pending.challenge, context: pending.requestDigest)
    }
    #expect(throws: DeviceIdentityError.invalidEnrollment) {
      try attacker.confirmEnrollment(pending, at: now, using: crypto)
    }
    let otherRequest = try second.enrollmentRequest(
      identityID: f.created.profile.id, at: now, using: crypto)
    let other = try PendingDeviceEnrollment(
      request: otherRequest,
      confirmedPairingDigest: otherRequest.digest(using: crypto), at: now, using: crypto)
    #expect(throws: DeviceIdentityError.invalidEnrollment) {
      try other.confirm(confirmation, at: now, using: crypto)
    }
    #expect(throws: DeviceIdentityError.expired) {
      try pending.confirm(confirmation, at: now + 601, using: crypto)
    }
    let decoded = try DeviceEnrollmentRequest.decode(request.encoding)
    try decoded.verify(at: now, using: crypto)
    #expect(decoded.encoding == request.encoding)
    _ = try pending.confirm(.decode(confirmation.encoding), at: now, using: crypto)
  }

  @Test func wrappingKeySubstitutionInvalidatesEnrollmentSignature() throws {
    let f = try Fixture()
    let second = try crypto.makeDevice()
    let attacker = try crypto.makeDevice()
    let request = try second.enrollmentRequest(
      identityID: f.created.profile.id, at: now, using: crypto)
    var a = try #require(try CanonicalCBOR.decode(request.payloadBytes).arrayValue())
    a[3] = .array([
      .byteString(ArraySlice(second.signingKey.publicKey.encoding)),
      .byteString(ArraySlice(attacker.wrappingKey.publicKey.encoding)), .bool(false),
    ])
    let substituted = CBOR.array([
      .byteString(ArraySlice(CBOR.array(a).encode())),
      .byteString(ArraySlice(request.signature)),
    ]).encode()
    #expect(throws: DeviceIdentityError.invalidSignature) {
      try DeviceEnrollmentRequest.decode(substituted).verify(at: now, using: crypto)
    }
  }

  @Test func wrongIdentityAndRootSignaturesCannotSignProfiles() throws {
    let f = try Fixture()
    let other = try Fixture()
    let wrong = try SignedProfile(
      identityKey: other.created.profile.identityKey,
      deviceList: f.created.profile.deviceList, payloadBytes: f.created.profile.payloadBytes,
      signature: f.created.profile.signature)
    #expect(throws: DeviceIdentityError.identityMismatch) {
      try wrong.verify(at: now, using: crypto)
    }
    // A controller CAN retain the root. Demonstrate that it still isn't a device signer.
    let raw = try f.device.wrappingKey.open(
      f.created.envelope.box, context: f.created.envelope.context)
    let root = try Curve25519.Signing.PrivateKey(rawRepresentation: raw)
    let rootSigned = try SignedProfile(
      identityKey: f.created.profile.identityKey,
      deviceList: f.created.profile.deviceList, payloadBytes: f.created.profile.payloadBytes,
      signature: Array(root.signature(for: f.created.profile.payloadBytes)))
    #expect(throws: DeviceIdentityError.invalidSignature) {
      try rootSigned.verify(at: now, using: crypto)
    }
    #expect(throws: (any Error).self) {
      try other.device.wrappingKey.open(f.created.envelope.box, context: f.created.envelope.context)
    }
    #expect(throws: (any Error).self) {
      try f.device.wrappingKey.open(f.created.envelope.box, context: other.created.envelope.context)
    }
  }

  @Test func signatureBindsExactBytesAndPurpose() throws {
    let f = try Fixture()
    let changed = try f.profile()
    let mismatch = try SignedProfile(
      identityKey: changed.identityKey, deviceList: changed.deviceList,
      payloadBytes: changed.payloadBytes, signature: f.created.profile.signature)
    #expect(throws: DeviceIdentityError.invalidSignature) {
      try mismatch.verify(at: now, using: crypto)
    }
    for purpose in DeviceProofPurpose.allCases {
      let proof = try f.device.sign(
        [1, 2, 3], purpose: purpose, profile: f.created.profile, at: now, using: crypto)
      try DeviceProof.decode(proof.encoding).verify(
        purpose: purpose, profile: f.created.profile, at: now, using: crypto)
      #expect(throws: DeviceIdentityError.roleConfusion) {
        try proof.verify(
          purpose: purpose == .login ? .action : .login,
          profile: f.created.profile, at: now, using: crypto)
      }
      #expect(throws: DeviceIdentityError.identityMismatch) {
        try proof.verify(purpose: purpose, profile: changed, at: now, using: crypto)
      }
      #expect(throws: DeviceIdentityError.expired) {
        try proof.verify(
          purpose: purpose, profile: f.created.profile,
          at: now + DeviceAuthorityLimits.profileLifetime, using: crypto)
      }
    }
  }

  @Test func strictCBORRejectsDuplicateFieldsTrailingBytesAndResourceExhaustion() throws {
    for bad: [UInt8] in [
      [0xa2, 0, 1, 0, 2], [0, 0], [0x18, 0], [0x9f, 0xff],
      Array(repeating: 0x81, count: 18) + [0], [0x63, 0xff, 0xff, 0xff],
      [0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
    ] {
      #expect(throws: (any Error).self) { try CanonicalCBOR.decode(bad) }
    }
    #expect(throws: (any Error).self) {
      try CanonicalCBOR.decode(Array(repeating: 0, count: 262_145))
    }
    let f = try Fixture()
    #expect(throws: (any Error).self) { try SignedProfile.decode(f.created.profile.encoding + [0]) }
  }

  @Test func validityCannotOutliveRosterOrPolicy() throws {
    let f = try Fixture()
    for expires in [now, now + DeviceAuthorityLimits.profileLifetime + 1] {
      #expect(throws: DeviceIdentityError.invalidValidity) {
        try f.device.signProfile(
          identityKey: f.created.profile.identityKey,
          deviceList: f.created.profile.deviceList, revision: 1, previousDigest: [],
          validity: .init(notBefore: now, expiresAt: expires), fields: fields("bad"), at: now,
          using: crypto)
      }
    }
    #expect(throws: DeviceIdentityError.expired) {
      try f.created.profile.verify(at: now - 1, using: crypto)
    }
  }

  @Test func removedDeviceCannotSignUnderNewRoster() throws {
    let f = try Fixture()
    let second = try crypto.makeDevice()
    let (pending, confirmation) = try f.enrollment(for: second)
    let enrolled = try IdentityController.enroll(
      pending, confirmation: confirmation,
      profile: f.created.profile, controller: f.device, envelope: f.created.envelope, at: now)
    let profile = try f.profile(revision: 1, signer: second, list: enrolled.deviceList)
    let removed = try IdentityController.remove(
      deviceID: second.signingKey.publicKey.id(using: crypto),
      profile: profile, controller: f.device, envelope: f.created.envelope, at: now)
    #expect(throws: DeviceIdentityError.deviceNotListed) {
      try f.profile(revision: 1, signer: second, list: removed)
    }
    let current = try f.profile(revision: 1, list: removed)
    #expect(throws: DeviceIdentityError.deviceNotListed) {
      try second.sign([1], purpose: .action, profile: current, at: now, using: crypto)
    }
  }

  @Test func controllerCanRecoverAfterExpiryWithoutAuthorizingExpiredActions() throws {
    let f = try Fixture()
    let later = now + DeviceAuthorityLimits.rosterLifetime + 1
    let renewed = try IdentityController.renew(
      profile: f.created.profile, controller: f.device,
      envelope: f.created.envelope, at: later)
    try renewed.verify(identityKey: f.created.profile.identityKey, at: later, using: crypto)
    #expect(throws: DeviceIdentityError.expired) {
      try f.created.profile.verify(at: later, using: crypto)
    }
  }
}

@Suite struct ProfileAuthorityStateTests {
  @Test func versionsConflictsRevocationAndCAS() throws {
    let f = try Fixture()
    let initial = f.created.profile
    var state = ProfileAuthorityState(identityKey: initial.identityKey, deviceList: initial.deviceList)
    try state.accept(initial, at: now, expecting: .missing, using: crypto)
    try state.accept(initial, at: now, using: crypto)
    #expect(try state.current(at: now, using: crypto)?.encoding == initial.encoding)
    let next = try f.profile()
    let fork = try f.profile(name: "conflicting")
    try state.accept(next, at: now, expecting: .digest(initial.digest(using: crypto)), using: crypto)
    #expect(throws: DeviceIdentityError.versionConflict) { try state.accept(fork, at: now, using: crypto) }
    #expect(throws: DeviceIdentityError.staleVersion) { try state.accept(initial, at: now, using: crypto) }
    #expect(throws: DeviceIdentityError.compareAndSwapFailed) {
      try state.accept(next, at: now, expecting: .digest(initial.digest(using: crypto)), using: crypto)
    }
    let roster = try IdentityController.renew(
      profile: initial, controller: f.device,
      envelope: f.created.envelope, at: now)
    try state.accept(roster, identityKey: initial.identityKey, at: now, using: crypto)
    #expect(try state.current(at: now, using: crypto) == nil)
    #expect(throws: DeviceIdentityError.staleVersion) { try state.accept(next, at: now, using: crypto) }
    let newest = try f.profile(revision: 1, list: roster)
    try state.accept(newest, at: now, using: crypto)
    #expect(try state.current(at: now, using: crypto)?.body.revision == 1)
    #expect(throws: DeviceIdentityError.expired) {
      try state.current(at: now + 2000, using: crypto)
    }
  }
}

import Crypto
import Diem
import DiemSecretMemory
import Foundation

/// Root operations deliberately have no arbitrary signing method. Plaintext root
/// bytes exist only while creating or opening an envelope, never in returned state.
public enum IdentityController {
  public struct Creation: Sendable {
    public let profile: SignedProfile
    public let envelope: IdentityKeyEnvelope
  }
  public struct Enrollment: Sendable {
    public let deviceList: SignedDeviceList
    public let controllerEnvelope: IdentityKeyEnvelope?
  }
  public enum Grant: Sendable {
    case ordinaryDevice
    /// The calling UI must explain that a recipient can permanently retain root authority.
    case identityControllerAcknowledgingPermanentRootTrust
  }

  public static func create(
    on device: DeviceSigner, fields: CBOR, at now: UInt64,
    using crypto: any DeviceCrypto = SoftwareDeviceCrypto()
  ) throws -> Creation {
    guard now <= UInt64.max - DeviceAuthorityLimits.rosterLifetime else {
      throw DeviceIdentityError.invalidValidity
    }
    let root = Curve25519.Signing.PrivateKey()
    let publicKey = try publicKey(root)
    let controller = try device.entry(identityController: true)
    let list = try DeviceList(
      identityID: publicKey.id(using: crypto), revision: 1,
      previousDigest: [],
      validity: .init(
        notBefore: now,
        expiresAt: now + DeviceAuthorityLimits.rosterLifetime), devices: [controller])
    let signed = try sign(list, root: root)
    let profile = try device.signProfile(
      identityKey: publicKey, deviceList: signed,
      revision: 1, previousDigest: [],
      validity: .init(notBefore: now, expiresAt: now + DeviceAuthorityLimits.profileLifetime),
      fields: fields, at: now, using: crypto)
    return try Creation(profile: profile, envelope: wrap(root, to: controller, using: crypto))
  }

  public static func enroll(
    _ pending: PendingDeviceEnrollment,
    confirmation: EnrollmentConfirmation, grant: Grant = .ordinaryDevice,
    profile: SignedProfile, controller: DeviceSigner, envelope: IdentityKeyEnvelope,
    at now: UInt64, using crypto: any DeviceCrypto = SoftwareDeviceCrypto()
  ) throws -> Enrollment {
    let ordinary = try pending.confirm(confirmation, at: now, using: crypto)
    guard pending.request.identityID == profile.id else {
      throw DeviceIdentityError.identityMismatch
    }
    let promoted = grant == .identityControllerAcknowledgingPermanentRootTrust
    let entry = try DeviceEntry(
      signingKey: ordinary.signingKey, wrappingKey: ordinary.wrappingKey,
      identityController: promoted)
    var devices = profile.deviceList.body.devices
    if let i = devices.firstIndex(where: { $0.signingKey == entry.signingKey }) {
      guard promoted, !devices[i].identityController, devices[i].wrappingKey == entry.wrappingKey
      else {
        throw DeviceIdentityError.invalidEnrollment
      }
      devices[i] = entry
    } else {
      devices.append(entry)
    }
    return try withRoot(
      profile: profile, controller: controller, envelope: envelope, at: now, using: crypto
    ) { root in
      let signed = try nextList(
        profile: profile, devices: devices, at: now, root: root, using: crypto)
      return try Enrollment(
        deviceList: signed,
        controllerEnvelope: promoted ? wrap(root, to: entry, using: crypto) : nil)
    }
  }

  public static func remove(
    deviceID: [UInt8], profile: SignedProfile, controller: DeviceSigner,
    envelope: IdentityKeyEnvelope, at now: UInt64,
    using crypto: any DeviceCrypto = SoftwareDeviceCrypto()
  ) throws -> SignedDeviceList {
    let devices = profile.deviceList.body.devices.filter { $0.id(using: crypto) != deviceID }
    guard devices.count < profile.deviceList.body.devices.count,
      devices.contains(where: \.identityController)
    else { throw DeviceIdentityError.controllerRequired }
    return try withRoot(
      profile: profile, controller: controller, envelope: envelope, at: now, using: crypto
    ) { root in
      try nextList(profile: profile, devices: devices, at: now, root: root, using: crypto)
    }
  }

  public static func renew(
    profile: SignedProfile, controller: DeviceSigner,
    envelope: IdentityKeyEnvelope, at now: UInt64,
    using crypto: any DeviceCrypto = SoftwareDeviceCrypto()
  ) throws -> SignedDeviceList {
    try withRoot(
      profile: profile, controller: controller, envelope: envelope,
      at: now, allowExpiredRoster: true, using: crypto
    ) { root in
      try nextList(
        profile: profile, devices: profile.deviceList.body.devices, at: now, root: root,
        using: crypto)
    }
  }

  private static func nextList(
    profile: SignedProfile, devices: [DeviceEntry], at now: UInt64,
    root: Curve25519.Signing.PrivateKey, using crypto: any DeviceCrypto
  ) throws -> SignedDeviceList {
    guard now <= UInt64.max - DeviceAuthorityLimits.rosterLifetime else {
      throw DeviceIdentityError.invalidValidity
    }
    let list = try DeviceList(
      identityID: profile.id, revision: profile.deviceList.body.revision + 1,
      previousDigest: profile.deviceList.digest(using: crypto),
      validity: .init(notBefore: now, expiresAt: now + DeviceAuthorityLimits.rosterLifetime),
      devices: devices)
    let result = try sign(list, root: root)
    try result.verify(identityKey: profile.identityKey, at: now, using: crypto)
    return result
  }
  private static func publicKey(_ root: Curve25519.Signing.PrivateKey) throws -> DevicePublicKey {
    try DevicePublicKey(
      algorithm: .ed25519, rawRepresentation: Array(root.publicKey.rawRepresentation))
  }
  private static func sign(_ list: DeviceList, root: Curve25519.Signing.PrivateKey) throws
    -> SignedDeviceList
  {
    try SignedDeviceList(
      payloadBytes: list.encoding, signature: Array(root.signature(for: list.encoding)))
  }
  private static func wrap(
    _ root: Curve25519.Signing.PrivateKey, to controller: DeviceEntry,
    using crypto: any DeviceCrypto
  ) throws -> IdentityKeyEnvelope {
    guard controller.identityController else { throw DeviceIdentityError.controllerRequired }
    let key = try publicKey(root)
    var secret = Array(root.rawRepresentation)
    defer { secret.withUnsafeMutableBytes { diem_clear($0.baseAddress, $0.count) } }
    return try IdentityKeyEnvelope(
      identityKey: key, recipient: controller,
      box: crypto.seal(
        secret, to: controller.wrappingKey,
        context: IdentityKeyEnvelope.context(identityKey: key, recipient: controller)))
  }
  private static func withRoot<T>(
    profile: SignedProfile, controller: DeviceSigner,
    envelope: IdentityKeyEnvelope, at now: UInt64, allowExpiredRoster: Bool = false,
    using crypto: any DeviceCrypto,
    body: (Curve25519.Signing.PrivateKey) throws -> T
  ) throws -> T {
    // Profile expiry does not strand root recovery. The root-signed roster is
    // what grants controller membership; ordinary operations still require a live profile.
    // Root recovery can renew an expired roster. This verifies its signature at
    // issuance, then proves possession of the same root; it grants no live action.
    try profile.deviceList.verify(
      identityKey: profile.identityKey,
      at: allowExpiredRoster ? profile.deviceList.body.validity.notBefore : now, using: crypto)
    let entry = try controller.entry(identityController: true)
    guard profile.deviceList.body.devices.contains(entry), envelope.recipient == entry,
      envelope.identityKey == profile.identityKey
    else { throw DeviceIdentityError.controllerRequired }
    var secret = try controller.wrappingKey.open(envelope.box, context: envelope.context)
    defer { secret.withUnsafeMutableBytes { diem_clear($0.baseAddress, $0.count) } }
    let root = try Curve25519.Signing.PrivateKey(rawRepresentation: secret)
    guard try publicKey(root) == profile.identityKey else {
      throw DeviceIdentityError.identityMismatch
    }
    return try body(root)
  }
}

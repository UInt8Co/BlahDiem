import BlahDiem
#if canImport(CryptoKit) && canImport(Security)
  import CryptoKit
  import DiemSwiftCrypto
  import Foundation
  import Security
  import Testing

  @Suite(.enabled(if: SecureEnclave.isAvailable))
  struct SecureEnclaveDeviceTests {
    @Test func hardwareSigningWrappingAndRestoration() throws {
      let access = try #require(
        SecAccessControlCreateWithFlags(
          nil,
          kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .privateKeyUsage, nil))
      let signing = try SecureEnclaveSigningKey(accessControl: access)
      let wrapping = try SecureEnclaveWrappingKey(accessControl: access)
      let device = try DeviceSigner(signingKey: signing, wrappingKey: wrapping)
      let crypto = SoftwareDeviceCrypto()
      let now = UInt64(Date().timeIntervalSince1970)
      let created = try IdentityController.create(on: device, fields: .map([]), at: now)
      try created.profile.verify(at: now, using: crypto)
      let restored = try DeviceSigner(
        signingKey: SecureEnclaveSigningKey(persistentReference: signing.persistentReference),
        wrappingKey: SecureEnclaveWrappingKey(persistentReference: wrapping.persistentReference))
      let roster = try IdentityController.renew(
        profile: created.profile, controller: restored,
        envelope: created.envelope, at: now)
      try roster.verify(identityKey: created.profile.identityKey, at: now, using: crypto)
      #expect(restored.signingKey.protection == .secureEnclave)
      #expect(restored.wrappingKey.protection == .secureEnclave)
    }
  }
#endif

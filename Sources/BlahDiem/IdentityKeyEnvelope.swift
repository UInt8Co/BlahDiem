/// Private controller custody. This type is never part of a public profile.
/// A controller may retain a recovered root key forever; promotion is a long-lived
/// root-trust grant, not a cryptographically revocable device permission.
public struct IdentityKeyEnvelope: Sendable {
  public let identityKey: DevicePublicKey
  public let recipient: DeviceEntry
  public let box: WrappedSecret

  public init(identityKey: DevicePublicKey, recipient: DeviceEntry, box: WrappedSecret)
    throws
  {
    guard identityKey.algorithm == .ed25519, recipient.identityController else {
      throw DeviceIdentityError.controllerRequired
    }
    self.identityKey = identityKey
    self.recipient = recipient
    self.box = box
  }

  public static func context(identityKey: DevicePublicKey, recipient: DeviceEntry) -> [UInt8] {
    CBOR.array([
      .textString("Diem/identity-envelope"), .unsignedInt(2),
      bytes(identityKey.encoding), recipient.cbor,
    ]).encode()
  }
  public var context: [UInt8] { Self.context(identityKey: identityKey, recipient: recipient) }
  public var encoding: [UInt8] {
    CBOR.array([bytes(context), bytes(box.encapsulatedKey), bytes(box.ciphertext)]).encode()
  }
  public static func decode(_ encoded: [UInt8]) throws -> Self {
    let a = try CanonicalCBOR.array(encoded, count: 3)
    let c = try CanonicalCBOR.array(octets(a[0]), count: 4)
    guard try string(c[0]) == "Diem/identity-envelope", try uint(c[1]) == 2 else {
      throw DiemError.invalidCBOR
    }
    return try Self(
      identityKey: .decode(octets(c[2])), recipient: .init(cbor: c[3]),
      box: .init(encapsulatedKey: octets(a[1]), ciphertext: octets(a[2])))
  }
}

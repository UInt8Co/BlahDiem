public struct DeviceEntry: Sendable, Equatable {
  public let signingKey: DevicePublicKey
  public let wrappingKey: DevicePublicKey
  public let identityController: Bool

  public init(
    signingKey: DevicePublicKey, wrappingKey: DevicePublicKey,
    identityController: Bool = false
  ) throws {
    guard signingKey.algorithm.isSigning, !wrappingKey.algorithm.isSigning else {
      throw DeviceIdentityError.roleConfusion
    }
    self.signingKey = signingKey
    self.wrappingKey = wrappingKey
    self.identityController = identityController
  }

  public func id(using crypto: some DeviceCrypto) -> [UInt8] { signingKey.id(using: crypto) }
  package var cbor: CBOR {
    .array([bytes(signingKey.encoding), bytes(wrappingKey.encoding), .bool(identityController)])
  }
  package init(cbor: CBOR) throws {
    let a = try record(cbor, count: 3)
    guard case .bool(let controller) = a[2] else { throw DiemError.invalidCBOR }
    try self.init(
      signingKey: .decode(octets(a[0])), wrappingKey: .decode(octets(a[1])),
      identityController: controller)
  }
}

public struct AuthorityValidity: Sendable, Equatable {
  public let notBefore: UInt64
  public let expiresAt: UInt64
  public init(notBefore: UInt64, expiresAt: UInt64) {
    self.notBefore = notBefore
    self.expiresAt = expiresAt
  }
  public func validate(at now: UInt64, maximumLifetime: UInt64) throws {
    guard expiresAt > notBefore, expiresAt - notBefore <= maximumLifetime else {
      throw DeviceIdentityError.invalidValidity
    }
    guard notBefore <= now, now < expiresAt else { throw DeviceIdentityError.expired }
  }
}

/// Hard maximum stale windows. Applications may impose shorter lifetimes.
public enum DeviceAuthorityLimits {
  public static let rosterLifetime: UInt64 = 30 * 24 * 60 * 60
  public static let profileLifetime: UInt64 = 24 * 60 * 60
  public static let maximumDevices = 128
}

public struct DeviceList: Sendable {
  public let identityID: [UInt8]
  public let revision: UInt64
  public let previousDigest: [UInt8]
  public let validity: AuthorityValidity
  public let devices: [DeviceEntry]

  public init(
    identityID: [UInt8], revision: UInt64, previousDigest: [UInt8],
    validity: AuthorityValidity, devices: [DeviceEntry]
  ) throws {
    guard identityID.count == 32, revision > 0, revision <= UInt64(Int64.max),
      previousDigest.count == (revision == 1 ? 0 : 32),
      !devices.isEmpty, devices.count <= DeviceAuthorityLimits.maximumDevices
    else {
      throw DeviceIdentityError.invalidRevision
    }
    self.identityID = identityID
    self.revision = revision
    self.previousDigest = previousDigest
    self.validity = validity
    self.devices = devices
  }

  public var encoding: [UInt8] {
    CBOR.array([
      .textString("Diem/devices"), .unsignedInt(2), bytes(identityID),
      .unsignedInt(revision), bytes(previousDigest), .unsignedInt(validity.notBefore),
      .unsignedInt(validity.expiresAt), .array(devices.map { $0.cbor }),
    ]).encode()
  }

  public static func decode(_ encoded: [UInt8]) throws -> Self {
    let a = try CanonicalCBOR.array(encoded, count: 8)
    guard try string(a[0]) == "Diem/devices", try uint(a[1]) == 2,
      let entries = try a[7].arrayValue()
    else { throw DiemError.invalidCBOR }
    return try Self(
      identityID: octets(a[2], count: 32), revision: uint(a[3]),
      previousDigest: octets(a[4]),
      validity: .init(notBefore: uint(a[5]), expiresAt: uint(a[6])),
      devices: entries.map { (value) throws in try DeviceEntry(cbor: value) })
  }
}

/// Only this record is authorized by an identity key. The exact signed bytes
/// are the only source of its decoded representation.
public struct SignedDeviceList: Sendable {
  public let payloadBytes: [UInt8]
  public let signature: [UInt8]
  public let body: DeviceList

  public init(payloadBytes: [UInt8], signature: [UInt8]) throws {
    self.body = try DeviceList.decode(payloadBytes)
    self.payloadBytes = payloadBytes
    self.signature = signature
  }
  public var encoding: [UInt8] { CBOR.array([bytes(payloadBytes), bytes(signature)]).encode() }
  public func digest(using crypto: some DeviceCrypto) -> [UInt8] {
    // Hash the statement, not its potentially nondeterministic ECDSA signature.
    crypto.sha256(payloadBytes)
  }
  public static func decode(_ encoded: [UInt8]) throws -> Self {
    let a = try CanonicalCBOR.array(encoded, count: 2)
    return try Self(payloadBytes: octets(a[0]), signature: octets(a[1]))
  }

  public func verify(
    identityKey: DevicePublicKey, at now: UInt64,
    using crypto: some DeviceCrypto
  ) throws {
    guard identityKey.algorithm.isSigning,
      identityKey.id(using: crypto) == body.identityID
    else {
      throw DeviceIdentityError.identityMismatch
    }
    try body.validity.validate(at: now, maximumLifetime: DeviceAuthorityLimits.rosterLifetime)
    var signingKeys = Set<[UInt8]>()
    var wrappingKeys = Set<[UInt8]>()
    for device in body.devices {
      guard device.signingKey != identityKey,
        signingKeys.insert(device.signingKey.encoding).inserted,
        wrappingKeys.insert(device.wrappingKey.encoding).inserted,
        device.signingKey.rawRepresentation != device.wrappingKey.rawRepresentation
      else {
        throw DeviceIdentityError.roleConfusion
      }
    }
    guard try crypto.verify(signature, message: payloadBytes, key: identityKey) else {
      throw DeviceIdentityError.invalidSignature
    }
  }
}

public struct DeviceProfileBody: Sendable {
  public let identityID: [UInt8]
  public let deviceListDigest: [UInt8]
  public let revision: UInt64
  public let previousDigest: [UInt8]
  public let validity: AuthorityValidity
  public let signerDeviceID: [UInt8]
  public let fields: CBOR

  public init(
    identityID: [UInt8], deviceListDigest: [UInt8], revision: UInt64,
    previousDigest: [UInt8], validity: AuthorityValidity, signerDeviceID: [UInt8],
    fields: CBOR
  ) throws {
    guard identityID.count == 32, deviceListDigest.count == 32, signerDeviceID.count == 32,
      revision > 0, revision <= UInt64(Int64.max),
      previousDigest.count == (revision == 1 ? 0 : 32),
      case .map = fields
    else { throw DiemError.invalidCBOR }
    _ = try CanonicalCBOR.encode(fields)
    self.identityID = identityID
    self.deviceListDigest = deviceListDigest
    self.revision = revision
    self.previousDigest = previousDigest
    self.validity = validity
    self.signerDeviceID = signerDeviceID
    self.fields = fields
  }

  public var encoding: [UInt8] {
    CBOR.array([
      .textString("Diem/profile"), .unsignedInt(2), bytes(identityID),
      bytes(deviceListDigest), .unsignedInt(revision), bytes(previousDigest),
      .unsignedInt(validity.notBefore), .unsignedInt(validity.expiresAt),
      bytes(signerDeviceID), fields,
    ]).encode()
  }

  public static func decode(_ encoded: [UInt8]) throws -> Self {
    let a = try CanonicalCBOR.array(encoded, count: 10)
    guard try string(a[0]) == "Diem/profile", try uint(a[1]) == 2 else {
      throw DiemError.invalidCBOR
    }
    return try Self(
      identityID: octets(a[2]), deviceListDigest: octets(a[3]),
      revision: uint(a[4]), previousDigest: octets(a[5]),
      validity: .init(notBefore: uint(a[6]), expiresAt: uint(a[7])),
      signerDeviceID: octets(a[8]), fields: a[9])
  }
}

public struct SignedProfile: Sendable {
  public let identityKey: DevicePublicKey
  public let deviceList: SignedDeviceList
  public let payloadBytes: [UInt8]
  public let signature: [UInt8]
  public let body: DeviceProfileBody
  public var id: [UInt8] { body.identityID }

  public init(
    identityKey: DevicePublicKey, deviceList: SignedDeviceList,
    payloadBytes: [UInt8], signature: [UInt8]
  ) throws {
    self.body = try DeviceProfileBody.decode(payloadBytes)
    self.identityKey = identityKey
    self.deviceList = deviceList
    self.payloadBytes = payloadBytes
    self.signature = signature
  }
  public var encoding: [UInt8] {
    CBOR.array([
      bytes(identityKey.encoding), bytes(deviceList.encoding),
      bytes(payloadBytes), bytes(signature),
    ]).encode()
  }
  public func digest(using crypto: some DeviceCrypto) -> [UInt8] { crypto.sha256(payloadBytes) }
  public static func decode(_ encoded: [UInt8]) throws -> Self {
    let a = try CanonicalCBOR.array(encoded, count: 4)
    return try Self(
      identityKey: .decode(octets(a[0])), deviceList: .decode(octets(a[1])),
      payloadBytes: octets(a[2]), signature: octets(a[3]))
  }
  public func verify(at now: UInt64, using crypto: some DeviceCrypto) throws {
    try deviceList.verify(identityKey: identityKey, at: now, using: crypto)
    guard id == deviceList.body.identityID else { throw DeviceIdentityError.identityMismatch }
    guard body.deviceListDigest == deviceList.digest(using: crypto) else {
      throw DeviceIdentityError.invalidSignature
    }
    try body.validity.validate(at: now, maximumLifetime: DeviceAuthorityLimits.profileLifetime)
    guard body.validity.notBefore >= deviceList.body.validity.notBefore,
      body.validity.expiresAt <= deviceList.body.validity.expiresAt
    else {
      throw DeviceIdentityError.invalidValidity
    }
    guard
      let signer = deviceList.body.devices.first(where: {
        $0.id(using: crypto) == body.signerDeviceID
      })
    else {
      throw DeviceIdentityError.deviceNotListed
    }
    guard try crypto.verify(signature, message: payloadBytes, key: signer.signingKey) else {
      throw DeviceIdentityError.invalidSignature
    }
  }
}

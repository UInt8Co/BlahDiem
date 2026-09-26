import DiemSwiftCrypto
import Foundation

/// Separate, long-lived DC signing key. This is never a user's identity key.
public struct FederationIdentity: Sendable {
  public let signingKey: SoftwareSigningKey
  public let device: DeviceSigner
  public let destination: FederationDestination
  public init(domain: String, privateKey: [UInt8], devicePrivateKey: [UInt8]? = nil) throws {
    signingKey = try SoftwareSigningKey(algorithm: .ed25519, restoring: privateKey)
    let crypto = SoftwareDeviceCrypto()
    let deviceSeed = devicePrivateKey
      ?? crypto.sha256(Array("Blah/DC-signing-device".utf8) + privateKey)
    device = try DeviceSigner(
      signingKey: SoftwareSigningKey(algorithm: .ed25519, restoring: deviceSeed),
      wrappingKey: SoftwareWrappingKey(algorithm: .x25519,
        restoring: crypto.sha256(Array("Blah/DC-wrapping-device".utf8) + deviceSeed)))
    destination = try FederationDestination(
      domain: domain, keyID: signingKey.publicKey.id(using: SoftwareDeviceCrypto()))
  }
  public static func load(domain: String, path: String, devicePath: String? = nil) throws -> Self {
    try Self(domain: domain, privateKey: Array(Data(contentsOf: URL(fileURLWithPath: path))),
      devicePrivateKey: devicePath.map { try Array(Data(contentsOf: URL(fileURLWithPath: $0))) })
  }

  /// The current DC statement. Validity rolls daily; endpoints are taken from
  /// this DC's live local configuration and the root signs only its device list.
  public func profile(configuration: KnownDCConfiguration, at now: UInt64) throws -> SignedProfile {
    guard configuration.domain == destination.domain,
      configuration.publicKey == Data(signingKey.publicKey.encoding)
    else { throw FederationError.invalidDelegation }
    let fields = try DCPublicProfile(configuration: configuration).fields
    let day = now - now % 86_400
    let roster = try DeviceList(identityID: destination.keyID, revision: 1, previousDigest: [],
      validity: .init(notBefore: day, expiresAt: day + DeviceAuthorityLimits.rosterLifetime),
      devices: [device.entry()])
    let signed = try SignedDeviceList(payloadBytes: roster.encoding,
      signature: signingKey.signature(for: roster.encoding))
    return try device.signProfile(identityKey: signingKey.publicKey, deviceList: signed,
      revision: 1, previousDigest: [],
      validity: .init(notBefore: day, expiresAt: day + DeviceAuthorityLimits.profileLifetime),
      fields: fields, at: now, using: SoftwareDeviceCrypto())
  }
}

/// Public DC discovery carried by its own Diem identity. The operator pins
/// the root identity; the listed profile-signing device also signs BIDCOM.
public struct DCPublicProfile: Sendable, Equatable {
  public let domains: [ProfileDomain]
  public let endpoints: [KnownDCConfiguration.Endpoint]
  public let bidcomEndpoints: [KnownDCConfiguration.Endpoint]
  public let transportPublicKey: String
  public let namespaceVersion: String?

  public init(configuration: KnownDCConfiguration) throws {
    _ = try configuration.validatedDestination()
    guard let transportPublicKey = configuration.transportPublicKey,
      !transportPublicKey.isEmpty, !configuration.endpoints.isEmpty,
      !configuration.bidcomEndpoints.isEmpty
    else { throw FederationError.invalidDelegation }
    self.domains = [try ProfileDomain(configuration.domain)]
    self.endpoints = configuration.endpoints
    self.bidcomEndpoints = configuration.bidcomEndpoints
    self.transportPublicKey = transportPublicKey
    self.namespaceVersion = configuration.namespaceVersion
  }

  public func advertises(_ domain: String) -> Bool { domains.contains { $0.domain == domain } }

  public var fields: CBOR {
    func encoded(_ endpoints: [KnownDCConfiguration.Endpoint]) -> CBOR {
      .array(endpoints.map { .array([.textString($0.host), .unsignedInt(UInt64($0.port)), .bool($0.tls)]) })
    }
    return .map([
      CBORMapPair(key: .unsignedInt(BlahProfileField.dc.rawValue), value: .array([
        .unsignedInt(1), encoded(endpoints), encoded(bidcomEndpoints),
        .textString(transportPublicKey), namespaceVersion.map(CBOR.textString) ?? .null,
      ])),
      CBORMapPair(key: .unsignedInt(BlahProfileField.domains.rawValue), value: .array(domains.map {
        .array([.textString($0.domain), .bool($0.username)])
      })),
    ])
  }

  public init(profile: SignedProfile, at now: UInt64) throws {
    try profile.verify(at: now, using: SoftwareDeviceCrypto())
    guard case .map(let pairs) = profile.body.fields, pairs.count == 2,
      let value = pairs.first(where: { $0.key == .unsignedInt(BlahProfileField.dc.rawValue) }),
      case .array(let dc) = value.value, dc.count == 5, dc[0] == .unsignedInt(1),
      case .textString(let transportPublicKey) = dc[3],
      let domainsValue = pairs.first(where: { $0.key == .unsignedInt(BlahProfileField.domains.rawValue) }),
      case .array(let rawDomains) = domainsValue.value
    else { throw FederationError.invalidDelegation }
    func decoded(_ value: CBOR) throws -> [KnownDCConfiguration.Endpoint] {
      guard case .array(let entries) = value, !entries.isEmpty, entries.count <= 8
      else { throw FederationError.invalidDelegation }
      return try entries.map { value in
        guard case .array(let endpoint) = value, endpoint.count == 3,
          case .textString(let host) = endpoint[0], case .unsignedInt(let port) = endpoint[1],
          port > 0, port <= 65_535, case .bool(let tls) = endpoint[2],
          !host.isEmpty, host.utf8.count <= 253,
          !host.contains(where: { $0.isWhitespace || $0 == "/" || $0 == "@" })
        else { throw FederationError.invalidDelegation }
        return .init(host: host, port: Int(port), tls: tls)
      }
    }
    guard !transportPublicKey.isEmpty, transportPublicKey.utf8.count <= 8192,
      !rawDomains.isEmpty, rawDomains.count <= 16
    else { throw FederationError.invalidDelegation }
    let domains = try rawDomains.map { value -> ProfileDomain in
      guard case .array(let entry) = value, entry.count == 2,
        case .textString(let domain) = entry[0], entry[1] == .bool(false)
      else { throw FederationError.invalidDelegation }
      return try ProfileDomain(domain)
    }
    guard Set(domains.map(\.domain)).count == domains.count else { throw FederationError.invalidDelegation }
    let version: String?
    switch dc[4] {
    case .null: version = nil
    case .textString(let text):
      guard let number = UInt64(text), number > 0, number <= UInt64(Int64.max),
        String(number) == text else { throw FederationError.invalidDelegation }
      version = text
    default: throw FederationError.invalidDelegation
    }
    self.domains = domains
    endpoints = try decoded(dc[1])
    bidcomEndpoints = try decoded(dc[2])
    self.transportPublicKey = transportPublicKey
    namespaceVersion = version
  }
}

import Foundation

/// Operator admission is separate from a user's device-signed home designation.
/// Updating an endpoint never changes the pinned federation key.
public struct KnownDCConfiguration: Codable, Equatable, Sendable {
  public struct Endpoint: Codable, Equatable, Sendable {
    public let host: String
    public let port: Int
    public let tls: Bool
    public init(host: String, port: Int, tls: Bool) {
      self.host = host
      self.port = port
      self.tls = tls
    }
  }
  public var domain: String
  /// Algorithm-qualified Diem public-key encoding, base64 in JSON.
  public var publicKey: Data
  public var endpoints: [Endpoint]
  public var bidcomEndpoints: [Endpoint]
  /// RSA transport bootstrap for encrypted MTProto. Federation signatures still
  /// authenticate both ends independently of this replaceable transport key.
  public var transportPublicKey: String?
  /// Decimal UInt63, encoded as text so JSON clients cannot round the value.
  /// A fresh business database has a new generation even with the same DC key.
  public var namespaceVersion: String?
  public var admitsUsers: Bool
  public var admitsChannels: Bool

  public init(
    domain: String, publicKey: Data, endpoints: [Endpoint] = [],
    bidcomEndpoints: [Endpoint] = [], admitsUsers: Bool = true, admitsChannels: Bool = false,
    transportPublicKey: String? = nil, namespaceVersion: String? = nil
  ) {
    self.domain = domain
    self.publicKey = publicKey
    self.endpoints = endpoints
    self.bidcomEndpoints = bidcomEndpoints
    self.transportPublicKey = transportPublicKey
    self.namespaceVersion = namespaceVersion
    self.admitsUsers = admitsUsers
    self.admitsChannels = admitsChannels
  }
  public func validatedDestination() throws -> FederationDestination {
    let key = try DevicePublicKey.decode(Array(publicKey))
    guard key.algorithm == .ed25519 || key.algorithm == .p256Signing,
      endpoints.count <= 8, bidcomEndpoints.count <= 8,
      transportPublicKey.map({ !$0.isEmpty && $0.utf8.count <= 8192 }) ?? true,
      namespaceVersion.map({ value in
        guard let version = UInt64(value), version > 0, version <= UInt64(Int64.max) else {
          return false
        }
        return String(version) == value
      }) ?? true,
      (endpoints + bidcomEndpoints).allSatisfy({
        !$0.host.isEmpty && $0.host.utf8.count <= 253 && (1...65535).contains($0.port)
          && !$0.host.contains(where: { $0.isWhitespace || $0 == "/" || $0 == "@" })
      })
    else { throw FederationError.invalidDelegation }
    return try .init(domain: domain, keyID: key.id(using: SoftwareDeviceCrypto()))
  }
}

public struct KnownDC: Sendable, Equatable {
  public let localID: Int32
  public let configuration: KnownDCConfiguration
  public let enabled: Bool
  public init(localID: Int32, configuration: KnownDCConfiguration, enabled: Bool) {
    self.localID = localID
    self.configuration = configuration
    self.enabled = enabled
  }
}

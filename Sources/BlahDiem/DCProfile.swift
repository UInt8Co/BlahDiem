/// A DC's public profile: where clients and peer DCs reach it.
public struct DCProfile: BlahProfile {
  /// A DC's user account is permanently hosted by that same identity.
  public static let accountID: Int64 = 777000
  public static let accountEpoch: UInt64 = 1
  /// CBOR field keys in the signed profile content.
  public static let cborKeyKind: UInt64 = UserProfile.cborKeyKind
  public static let cborKeyEndpoints: UInt64 = UserProfile.cborKeyHome + 1
  public static let cborKeyBIDCOMEndpoints: UInt64 = cborKeyEndpoints + 1
  public static let cborKeyTransportPublicKey: UInt64 = cborKeyBIDCOMEndpoints + 1
  public static let cborKeyNamespaceGeneration: UInt64 = cborKeyTransportPublicKey + 1

  /// The transport carrying MTProto; TLS is independent of the transport.
  public enum Transport: UInt64, Sendable {
    case tcp = 0
    case webSocket = 1
  }

  /// A network address and, for WebSocket, its exact HTTP request path.
  public struct Endpoint: Hashable, Sendable {
    /// CBOR field keys.
    public static let cborKeyHost: UInt64 = 0
    public static let cborKeyPort: UInt64 = 1
    public static let cborKeyTLS: UInt64 = 2
    public static let cborKeyTransport: UInt64 = 3
    public static let cborKeyPath: UInt64 = 4

    public var host: String
    public var port: UInt16
    public var tls: Bool
    public var transport: Transport
    public var path: String?

    public init(host: String, port: UInt16, tls: Bool,
      transport: Transport = .tcp, path: String? = nil) {
      self.host = host
      self.port = port
      self.tls = tls
      self.transport = transport
      self.path = path
    }
  }

  public static let maximumEndpoints = 8
  public static var domainCount: ClosedRange<Int> { 1...ProfileFields.maximumDomains }

  public struct Content: Hashable, Sendable {
    /// The DC's discovery domains.
    public var domains: [DomainName]
    /// MTProto endpoints for clients.
    public var endpoints: [Endpoint]
    /// BIDCOM endpoints for peer DCs.
    public var bidcomEndpoints: [Endpoint]
    /// The MTProto RSA public key, PEM-encoded.
    public var transportPublicKey: String
    /// The DC's database generation. A new generation starts a new client namespace.
    public var namespaceGeneration: UInt64?

    public init(
      domains: [DomainName], endpoints: [Endpoint], bidcomEndpoints: [Endpoint],
      transportPublicKey: String, namespaceGeneration: UInt64? = nil
    ) {
      self.domains = domains
      self.endpoints = endpoints
      self.bidcomEndpoints = bidcomEndpoints
      self.transportPublicKey = transportPublicKey
      self.namespaceGeneration = namespaceGeneration
    }

    init(fields: ProfileFields) throws(BlahError) {
      let e = BlahError.invalidProfile
      let a = fields.application
      guard try HostedRecord.kind(of: fields) == .dc,
        (DCProfile.cborKeyEndpoints...DCProfile.cborKeyNamespaceGeneration).allSatisfy({ a[$0] != nil })
      else { throw e }
      func endpoints(_ value: CBOR) throws(BlahError) -> [Endpoint] {
        var result: [Endpoint] = []
        for entry in try value.array(e) {
          let a = try entry.record(e, requiredKeys: Endpoint.cborKeyHost..<(Endpoint.cborKeyPath + 1))
          guard let port = UInt16(exactly: try a[Endpoint.cborKeyPort]!.unsigned(e)),
            case .bool(let tls) = a[Endpoint.cborKeyTLS]!,
            let transport = Transport(rawValue: try a[Endpoint.cborKeyTransport]!.unsigned(e))
          else {
            throw e
          }
          result.append(
            Endpoint(
              host: try a[Endpoint.cborKeyHost]!.text(e), port: port, tls: tls,
              transport: transport,
              path: a[Endpoint.cborKeyPath]! == .null ? nil : try a[Endpoint.cborKeyPath]!.text(e)))
        }
        return result
      }
      self.init(
        domains: fields.domains,
        endpoints: try endpoints(a[DCProfile.cborKeyEndpoints]!),
        bidcomEndpoints: try endpoints(a[DCProfile.cborKeyBIDCOMEndpoints]!),
        transportPublicKey: try a[DCProfile.cborKeyTransportPublicKey]!.text(e),
        namespaceGeneration: a[DCProfile.cborKeyNamespaceGeneration]! == .null
          ? nil : try a[DCProfile.cborKeyNamespaceGeneration]!.unsigned(e))
      try validate()
    }

    var fields: ProfileFields {
      get throws(BlahError) {
        try validate()
        func encode(_ endpoints: [Endpoint]) -> CBOR {
          .array(
            endpoints.map {
              .record([
                Endpoint.cborKeyHost: .text($0.host), Endpoint.cborKeyPort: .unsigned(UInt64($0.port)),
                Endpoint.cborKeyTLS: .bool($0.tls),
                Endpoint.cborKeyTransport: .unsigned($0.transport.rawValue),
                Endpoint.cborKeyPath: $0.path.map(CBOR.text) ?? .null,
              ])
            })
        }
        return ProfileFields(domains: domains, application: [
          DCProfile.cborKeyKind: .unsigned(ProfileKind.dc.rawValue),
          DCProfile.cborKeyEndpoints: encode(endpoints),
          DCProfile.cborKeyBIDCOMEndpoints: encode(bidcomEndpoints),
          DCProfile.cborKeyTransportPublicKey: .text(transportPublicKey),
          DCProfile.cborKeyNamespaceGeneration: namespaceGeneration.map(CBOR.unsigned) ?? .null,
        ])
      }
    }

    private func validate() throws(BlahError) {
      try HostedRecord.validate(domains: domains, count: DCProfile.domainCount)
      let valid = [endpoints, bidcomEndpoints].allSatisfy { list in
        list.count <= DCProfile.maximumEndpoints && Set(list).count == list.count
          && list.allSatisfy { $0.isValid }
      }
      guard valid, !endpoints.isEmpty, bidcomEndpoints.allSatisfy({ $0.transport == .tcp }),
        !transportPublicKey.isEmpty, transportPublicKey.utf8.count <= 8192,
        namespaceGeneration.map({ (1...UInt64(Int64.max)).contains($0) }) ?? true
      else { throw .invalidProfile }
    }
  }

  public let record: ProfileRecord
  public let content: Content

  public init(record: ProfileRecord) throws(BlahError) {
    content = try Content(fields: record.fields)
    self.record = record
  }

  public static func fields(for content: Content) throws(BlahError) -> ProfileFields {
    try content.fields
  }

  /// The DC's own user account, hosted by this identity until the profile expires.
  public var home: Home? {
    Home(dc: id, epoch: Self.accountEpoch, expiresAt: validity.expiresAt, account: Self.accountID)
  }
  /// MTProto endpoints for clients.
  public var endpoints: [Endpoint] { content.endpoints }
  /// BIDCOM endpoints for peer DCs.
  public var bidcomEndpoints: [Endpoint] { content.bidcomEndpoints }
  /// The MTProto RSA public key, PEM-encoded.
  public var transportPublicKey: String { content.transportPublicKey }
  /// The DC's database generation. A new generation starts a new client namespace.
  public var namespaceGeneration: UInt64? { content.namespaceGeneration }
}

extension DCProfile.Endpoint {
  /// Shared validation for profile publishers and configuration editors.
  public var isValid: Bool {
    guard !host.isEmpty, host.utf8.count <= DomainName.maximumLength, port > 0,
      host.utf8.allSatisfy({
        (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0)
          || [45, 46, 58].contains($0)
      })
    else { return false }
    switch transport {
    case .tcp: return path == nil
    case .webSocket:
      guard let path, path.hasPrefix("/"), !path.hasPrefix("//"), path.utf8.count <= 2048,
        path.utf8.allSatisfy({ $0 > 32 && $0 < 127 && $0 != 35 && $0 != 92 })
      else { return false }
      return true
    }
  }
}

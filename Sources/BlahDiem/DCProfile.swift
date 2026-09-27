/// A DC's public profile: where clients and peer DCs reach it.
public struct DCProfile: BlahProfile {
  /// A network address.
  public struct Endpoint: Hashable, Sendable {
    public var host: String
    public var port: UInt16
    public var tls: Bool

    public init(host: String, port: UInt16, tls: Bool) {
      self.host = host
      self.port = port
      self.tls = tls
    }
  }

  public static let maximumEndpoints = 8

  /// The DC's discovery domains.
  public var domains: [String]
  /// MTProto endpoints for clients.
  public var endpoints: [Endpoint]
  /// BIDCOM endpoints for peer DCs.
  public var bidcomEndpoints: [Endpoint]
  /// The MTProto RSA public key, PEM-encoded.
  public var transportPublicKey: String
  /// The DC's database generation. A new generation starts a new client namespace.
  public var namespaceGeneration: UInt64?

  public init(
    domains: [String], endpoints: [Endpoint], bidcomEndpoints: [Endpoint],
    transportPublicKey: String, namespaceGeneration: UInt64? = nil
  ) {
    self.domains = domains
    self.endpoints = endpoints
    self.bidcomEndpoints = bidcomEndpoints
    self.transportPublicKey = transportPublicKey
    self.namespaceGeneration = namespaceGeneration
  }

  public init(data: [UInt8]) throws(BlahError) {
    let e = BlahError.invalidProfile
    let fields = try CBOR.record(data, tag: .profile, count: 8, error: e)
    guard fields[2] == .unsigned(ProfileKind.dc.rawValue) else { throw e }
    func endpoints(_ value: CBOR) throws(BlahError) -> [Endpoint] {
      var result: [Endpoint] = []
      for entry in try value.array(e) {
        let a = try entry.array(e, count: 3)
        guard let port = UInt16(exactly: try a[1].unsigned(e)), case .bool(let tls) = a[2] else {
          throw e
        }
        result.append(Endpoint(host: try a[0].text(e), port: port, tls: tls))
      }
      return result
    }
    var domains: [String] = []
    for domain in try fields[3].array(e) { domains.append(try domain.text(e)) }
    self.domains = domains
    self.endpoints = try endpoints(fields[4])
    self.bidcomEndpoints = try endpoints(fields[5])
    self.transportPublicKey = try fields[6].text(e)
    self.namespaceGeneration = fields[7] == .null ? nil : try fields[7].unsigned(e)
    try validate()
  }

  public func encoded() throws(BlahError) -> [UInt8] {
    try validate()
    func encode(_ endpoints: [Endpoint]) -> CBOR {
      .array(endpoints.map { .array([.text($0.host), .unsigned(UInt64($0.port)), .bool($0.tls)]) })
    }
    return CBOR.array([
      .unsigned(BlahTag.profile.rawValue), .unsigned(1), .unsigned(ProfileKind.dc.rawValue),
      .array(domains.map(CBOR.text)), encode(endpoints), encode(bidcomEndpoints),
      .text(transportPublicKey), namespaceGeneration.map(CBOR.unsigned) ?? .null,
    ]).encoded
  }

  private func validate() throws(BlahError) {
    guard (1...HostedRecord.maximumDomains).contains(domains.count),
      Set(domains).count == domains.count, domains.allSatisfy(DomainName.isValid)
    else { throw .invalidName }
    let valid = [endpoints, bidcomEndpoints].allSatisfy { list in
      (1...Self.maximumEndpoints).contains(list.count)
        && list.allSatisfy { endpoint in
          !endpoint.host.isEmpty && endpoint.host.utf8.count <= DomainName.maximumLength
            && endpoint.port > 0
            && !endpoint.host.contains { $0.isWhitespace || $0 == "/" || $0 == "@" }
        }
    }
    guard valid, !transportPublicKey.isEmpty, transportPublicKey.utf8.count <= 8192,
      namespaceGeneration.map({ (1...UInt64(Int64.max)).contains($0) }) ?? true
    else { throw .invalidProfile }
  }
}

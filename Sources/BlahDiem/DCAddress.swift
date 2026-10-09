/// A DC's discovery domain and identity ID.
public struct DCAddress: Hashable, Sendable {
  public let domain: DomainName
  public let id: Digest

  public init(domain: DomainName, id: Digest) {
    self.domain = domain
    self.id = id
  }
}

extension CBOR {
  /// The DC address at `domainKey` and `idKey` of a decoded record.
  static func dcAddress(_ fields: [UInt64: CBOR], domain domainKey: UInt64, id idKey: UInt64,
    error: BlahError) throws(BlahError) -> DCAddress
  {
    DCAddress(domain: try fields[domainKey]!.domain(error), id: try fields[idKey]!.digest(error))
  }
}

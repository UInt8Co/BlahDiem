extension AnyBlahProfile.Content {
  /// Replaces the ordered domains under the profile kind's native name rules.
  /// Use as the transform of Diem's `claiming` and `releasing` operations.
  public func replacingDomains(_ domains: [DomainName]) throws(BlahError) -> Self {
    let next: Self
    switch self {
    case .user(var content):
      content.domains = domains
      next = .user(content)
    case .bot(var content):
      content.domains = domains
      next = .bot(content)
    case .channel(var content):
      content.domains = domains
      next = .channel(content)
    case .stickerSet(var content):
      guard domains.count == 1 else { throw .invalidName }
      content.shortName = domains[0]
      next = .stickerSet(content)
    case .dc(var content):
      content.domains = domains
      next = .dc(content)
    }
    _ = try AnyBlahProfile.fields(for: next)
    return next
  }
}

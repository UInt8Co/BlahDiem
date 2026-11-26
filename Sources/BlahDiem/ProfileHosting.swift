extension AnyBlahProfile.Content {
  /// Replaces the ordered domains under the profile kind's native name rules; see
  /// ``AnyBlahProfile/content(_:replacingDomains:)``, which Diem's `claiming` and
  /// `releasing` operations use.
  public func replacingDomains(_ domains: [DomainName]) throws(BlahError) -> Self {
    try AnyBlahProfile.content(self, replacingDomains: domains)
  }
}

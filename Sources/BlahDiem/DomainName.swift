/// A name that crosses DCs is a DNS domain: lowercase letter-digit-hyphen labels,
/// at least two of them, 253 bytes at most. The same rule governs home domains,
/// publishers and every resource's public name.
public enum DomainName {
  public static let maximumLength = 253

  /// `raw` lowercased, or `nil` when it is not a domain.
  public static func normalized(_ raw: String) -> String? {
    let value = raw.lowercased()
    return isValid(value) ? value : nil
  }

  public static func isValid(_ value: String) -> Bool {
    guard value.utf8.count <= maximumLength, value == value.lowercased(), value.contains(".") else {
      return false
    }
    return value.split(separator: ".", omittingEmptySubsequences: false).allSatisfy { label in
      !label.isEmpty && label.utf8.count <= 63 && label.first != "-" && label.last != "-"
        && label.utf8.allSatisfy { (97...122).contains($0) || (48...57).contains($0) || $0 == 45 }
    }
  }

  /// Whether `name` lies strictly below `domain`, whose operator can host
  /// the profile at that name.
  public static func name(_ name: String, isBelow domain: String) -> Bool {
    name.count > domain.count + 1 && name.hasSuffix("." + domain)
  }
}

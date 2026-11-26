import BlahDiem
import DiemTesting

enum Fixture {
  static let dcID = Digest(hashing: [7])
  static let dc = DCAddress(domain: try! DomainName("one.example"), id: dcID)
  static let nonce = [UInt8](repeating: 9, count: 32)
  static func home(account: Int64? = nil) -> Home {
    Home(dc: dcID, epoch: 1, expiresAt: TestBackend.start + 3600, account: account)
  }
}

extension ProfileFields {
  /// The Blah map, for tests that sign altered fields directly.
  var blah: CBOR.Record {
    get { try! applications[.blah]!.recordValue(requiredKeys: 0..<0) }
    set { applications[.blah] = newValue.value }
  }
}

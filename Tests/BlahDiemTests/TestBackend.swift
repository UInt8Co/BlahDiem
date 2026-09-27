import BlahDiem
import DiemSwiftCrypto
import Synchronization

/// Swift Crypto with a clock that tests move.
final class TestBackend: CryptoBackend {
  static let start: UInt64 = 1_800_000_000
  let base = SwiftCryptoBackend()
  private let time = Atomic<UInt64>(TestBackend.start)

  var now: UInt64 { time.load(ordering: .relaxed) }
  func advance(by seconds: UInt64) { time.add(seconds, ordering: .relaxed) }

  func randomBytes(count: Int) -> [UInt8] { base.randomBytes(count: count) }
  func makePrivateKey(_ algorithm: PublicKey.Algorithm, restoring raw: [UInt8]?) async throws
    -> PrivateKey
  { try await base.makePrivateKey(algorithm, restoring: raw) }
  func isValidSignature(_ signature: [UInt8], for message: [UInt8], by key: PublicKey)
    async throws -> Bool
  { try await base.isValidSignature(signature, for: message, by: key) }
  func makeEncryptionKey(_ algorithm: EncryptionPublicKey.Algorithm, restoring raw: [UInt8]?)
    async throws -> EncryptionPrivateKey
  { try await base.makeEncryptionKey(algorithm, restoring: raw) }
  func seal(_ plaintext: [UInt8], to key: EncryptionPublicKey, context: [UInt8]) async throws
    -> SealedBox
  { try await base.seal(plaintext, to: key, context: context) }
}

enum Fixture {
  static let dcID = Digest(hashing: [7])
  static let dc = try! DCAddress(domain: "one.example", id: dcID)
  static let nonce = [UInt8](repeating: 9, count: 32)
  static func home(account: Int64? = nil) -> Home {
    Home(dc: dcID, epoch: 1, expiresAt: TestBackend.start + 3600, account: account)
  }
}

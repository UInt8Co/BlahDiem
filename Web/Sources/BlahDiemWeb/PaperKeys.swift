import BlahDiem
import JavaScriptKit

/// A paper device key's canonical words, the Ed25519 seed WebCrypto signs with and the
/// encoded Diem device public key to certify.
@JS public struct PaperKeyResult {
  public let phrase: String
  public let seed: [UInt8]
  public let device: [UInt8]
  public init(phrase: String, seed: [UInt8], device: [UInt8]) {
    self.phrase = phrase; self.seed = seed; self.device = device
  }
}

/// The paper key that 32 bytes of random `entropy` encode.
@JS public func newPaperKey(entropy: [UInt8], crypto: JSObject) async throws(JSException) -> PaperKeyResult {
  do { return try await paperKeyResult(PaperDeviceKey(entropy: entropy), crypto: crypto) }
  catch { throw JSException(message: bridgeError(error)) }
}

/// The paper key that written words encode; checks the word list, count and checksum.
@JS public func paperKey(phrase: String, crypto: JSObject) async throws(JSException) -> PaperKeyResult {
  do { return try await paperKeyResult(PaperDeviceKey(phrase: phrase), crypto: crypto) }
  catch { throw JSException(message: bridgeError(error)) }
}

private func paperKeyResult(_ paper: PaperDeviceKey, crypto: JSObject) async throws -> PaperKeyResult {
  let key = try await paper.deviceKey(.ed25519, using: BrowserBackend(now: 0, crypto: crypto))
  return PaperKeyResult(phrase: paper.phrase, seed: key.rawRepresentation ?? [],
    device: key.publicKey.key.encoding)
}

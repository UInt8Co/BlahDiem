/// DC-issued data that a device signs as a ``BlahProof``.
public protocol BlahStatement: Sendable, Hashable {
  /// Decodes a statement from its ``encoding``.
  init(encoding: [UInt8]) throws(BlahError)
  /// The canonical encoding.
  var encoding: [UInt8] { get }
  /// Checks that `identity` may sign this statement now.
  func validate<I: Identity>(for identity: I) throws(BlahError) where I.Profile: BlahProfile
}

/// A Diem proof whose data is a ``BlahStatement``.
public struct BlahProof<Statement: BlahStatement>: Proof {
  public let record: ProofRecord
  public let statement: Statement

  /// Decodes the statement that `record` signs.
  public init(record: ProofRecord) throws(BlahError) {
    self.record = record
    statement = try Statement(encoding: record.data)
  }
}

extension Identity where Profile: BlahProfile {
  /// A proof of `statement` by this device, after the statement's own checks.
  public func prove<Statement: BlahStatement>(_ statement: Statement) async throws
    -> BlahProof<Statement>
  {
    try statement.validate(for: self)
    return try BlahProof(record: await prove(statement.encoding))
  }

  /// Signing-time check shared by DC challenges: the challenge expires within the
  /// signing window.
  func requireLive(until expiresAt: UInt64) throws(BlahError) {
    // The longest time before its expiry that a device signs a challenge.
    let challengeWindow: UInt64 = 120
    let now = backend.now
    guard now < expiresAt, expiresAt - now <= challengeWindow else {
      throw .challengeExpired
    }
  }

  /// Signing-time check shared by DC challenges: `dc` hosts this identity.
  func requireHome(_ dc: Digest) throws(BlahError) {
    guard profile.home?.dc == dc else { throw .wrongHome }
  }
}

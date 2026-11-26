/// DC-issued data that a device signs as a ``BlahProof``: a Diem `Statement` of
/// application ``ApplicationID/blah``, whose proof value is the statement's record.
///
/// A conforming type decodes and encodes its record as ``Statement/value``;
/// ``encoding`` is that record's canonical bytes, exactly as the DC issued them.
public protocol BlahStatement: Statement {
  /// Checks that `identity` may sign this statement now.
  func validate<I: Identity>(for identity: I) throws(BlahError) where I.Profile: BlahProfile
}

extension BlahStatement {
  public static var application: ApplicationID { .blah }

  /// Decodes a statement from its ``encoding``.
  public init(encoding: [UInt8]) throws(BlahError) {
    // Statements throw only ``BlahError/invalidChallenge`` when decoding.
    do { try self.init(value: CBOR(decoding: encoding)) } catch { throw .invalidChallenge }
  }

  /// The canonical encoding: the bytes of ``Statement/value``.
  public var encoding: [UInt8] { value.encoded }
}

/// A Diem proof whose value is a ``BlahStatement``.
public typealias BlahProof<S: BlahStatement> = StatementProof<S>

extension Identity where Profile: BlahProfile {
  /// A proof of `statement` by this device, after the statement's own checks.
  public func prove<S: BlahStatement>(_ statement: S) async throws -> BlahProof<S> {
    try statement.validate(for: self)
    return try BlahProof(record: await prove(statement.value, for: S.application))
  }

  /// Signing-time check shared by DC challenges: the challenge expires within the
  /// signing window.
  func requireLive(until expiresAt: UInt64) throws(BlahError) {
    // The longest time before its expiry that a device signs a challenge.
    let challengeWindow: UInt64 = 120
    do { try requireLive(until: expiresAt, window: challengeWindow) } catch {
      throw .challengeExpired
    }
  }

  /// Signing-time check shared by DC challenges: `dc` hosts this identity.
  func requireHome(_ dc: Digest) throws(BlahError) {
    guard profile.home?.dc == dc else { throw .wrongHome }
  }
}

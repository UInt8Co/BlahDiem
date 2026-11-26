extension ApplicationID {
  /// Blah's application ID, `com.blahim`: the key of Blah's field in Diem profiles and
  /// proofs, and of a device-link grant's Blah metadata.
  public static let blah = try! ApplicationID("com.blahim")
}

/// Tags of Blah records, stored at integer key 0; key 1 holds the version.
enum BlahTag: UInt64 {
  static let cborKeyTag: UInt64 = 0
  static let cborKeyVersion: UInt64 = 1

  case login = 3
  case invocationChallenge = 4
  case invocationStatement = 5
  case oauthConsent = 6
  case accountLink = 8
  case dcAdmin = 9
  case clientNamespace = 10
  // Tags 14–20 are retired; device-link records are Diem's.
}

/// Profile kind codes, at ``UserProfile/cborKeyKind`` in every Blah profile's field.
enum ProfileKind: UInt64 {
  case user = 1
  case channel = 2
  case bot = 3
  case stickerSet = 4
  case dc = 5
  case application = 6
}

/// Decoding helpers that map Diem encoding errors to one Blah error.
extension CBOR {
  /// The version 1 Blah record with `tag` in canonical `bytes`.
  static func record(_ bytes: [UInt8], tag: BlahTag, requiredKeys: Range<UInt64>, error: BlahError)
    throws(BlahError) -> CBOR.Record
  {
    guard let value = try? CBOR(decoding: bytes) else { throw error }
    return try value.record(tag: tag, requiredKeys: requiredKeys, error: error)
  }

  /// This value as the version 1 Blah record with `tag`.
  func record(tag: BlahTag, requiredKeys: Range<UInt64>, error: BlahError)
    throws(BlahError) -> CBOR.Record
  {
    try field(error) { value throws(DiemError) in
      try value.recordValue(tag: .unsigned(tag.rawValue), version: 1, requiredKeys: requiredKeys)
    }
  }

  func record(_ error: BlahError, requiredKeys: Range<UInt64>) throws(BlahError) -> CBOR.Record {
    try field(error) { value throws(DiemError) in try value.recordValue(requiredKeys: requiredKeys) }
  }

  func field<T>(_ failure: BlahError, _ read: (CBOR) throws(DiemError) -> T) throws(BlahError) -> T {
    do { return try read(self) } catch { throw failure }
  }

  func domain(_ error: BlahError) throws(BlahError) -> DomainName {
    try field(error) { value throws(DiemError) in try DomainName(value.textValue()) }
  }

  func digest(_ error: BlahError) throws(BlahError) -> Digest {
    try field(error) { value throws(DiemError) in try Digest(bytes: value.bytesValue()) }
  }

  func unsigned(_ error: BlahError) throws(BlahError) -> UInt64 {
    try field(error) { value throws(DiemError) in try value.unsignedValue() }
  }

  func bytes(_ error: BlahError, count: Int? = nil) throws(BlahError) -> [UInt8] {
    try field(error) { value throws(DiemError) in try value.bytesValue(count: count) }
  }

  func text(_ error: BlahError) throws(BlahError) -> String {
    try field(error) { value throws(DiemError) in try value.textValue() }
  }

  func array(_ error: BlahError, count: Int? = nil) throws(BlahError) -> [CBOR] {
    try field(error) { value throws(DiemError) in try value.arrayValue(count: count) }
  }
}

import BlahDiem
import JavaScriptKit

@JS public struct KeyFileInfo {
  public let id: String
  public let salt: [UInt8]
  public init(id: String, salt: [UInt8]) { self.id = id; self.salt = salt }
}

// Metadata key 7 is application-owned; version-one native and older browser readers
// accept unknown metadata entries. Pending publication snapshots never enter this record.
struct KeyFileHosting {
  public let domain: String
  public let held: [String]
  public let proofs: [HostingProofInfo]

  public init(domain: String, held: [String], proofs: [HostingProofInfo]) {
    self.domain = domain; self.held = held; self.proofs = proofs
  }

  func validated() throws -> Self {
    guard try DomainName(domain).name == domain, Set(held).count == held.count,
      Set(proofs.map { $0.label }).count == proofs.count else { throw DiemError.invalidEncoding }
    let labels = Set(held + proofs.map { $0.label })
    guard labels.count <= 16 else { throw DiemError.invalidEncoding }
    for label in labels {
      guard !label.contains("."), try DomainName(label + "." + domain).name == label + "." + domain
      else { throw DiemError.invalidEncoding }
    }
    guard proofs.allSatisfy({ (1...64).contains($0.nonce.count) }) else { throw DiemError.invalidEncoding }
    return self
  }

  func encoded() throws -> CBOR {
    _ = try validated()
    return .record([0: .text(domain), 1: .array(held.map { .text($0) }),
      2: .array(proofs.map { .array([.text($0.label), .bytes($0.nonce)]) })])
  }

  init(_ value: CBOR) throws {
    let fields = try value.recordValue(requiredKeys: 0..<3)
    domain = try fields[0]!.textValue()
    held = try fields[1]!.arrayValue().map { try $0.textValue() }
    proofs = try fields[2]!.arrayValue().map {
      let pair = try $0.arrayValue()
      guard pair.count == 2 else { throw DiemError.invalidEncoding }
      return try HostingProofInfo(label: pair[0].textValue(), nonce: pair[1].bytesValue())
    }
    _ = try validated()
  }
}

@JS public struct KeyFilePayload {
  public let profile: [UInt8]
  public let identity: [UInt8]?
  public let device: [UInt8]?
  public let domain: String
  public let publisher: String
  public let token: String
  public let profileDays: Double
  public let deviceDays: Double
  public let autoRenew: Bool
  public let publicationPending: Bool
  public let hostingDomain: String?
  public let hostingHeld: [String]
  public let hostingProofs: [HostingProofInfo]

  public init(profile: [UInt8], identity: [UInt8]?, device: [UInt8]?, domain: String,
    publisher: String, token: String, profileDays: Double, deviceDays: Double,
    autoRenew: Bool, publicationPending: Bool, hostingDomain: String?, hostingHeld: [String], hostingProofs: [HostingProofInfo]) {
    self.profile = profile; self.identity = identity; self.device = device
    self.domain = domain; self.publisher = publisher; self.token = token
    self.profileDays = profileDays; self.deviceDays = deviceDays
    self.autoRenew = autoRenew; self.publicationPending = publicationPending
    self.hostingDomain = hostingDomain; self.hostingHeld = hostingHeld; self.hostingProofs = hostingProofs
  }
}

@JS public func keyFileInfo(encoding: [UInt8]) throws(JSException) -> KeyFileInfo {
  do {
    let file = try KeyFile(encoding: encoding)
    return KeyFileInfo(id: file.identityID.description, salt: file.salt)
  } catch { throw JSException(message: bridgeError(error)) }
}

@JS public func sealKeyFile(input: KeyFilePayload, salt: [UInt8], crypto: JSObject) async throws(JSException) -> [UInt8] {
  do {
    let backend = BrowserBackend(now: 0, crypto: crypto)
    let profile = try AnyBlahProfile(encoding: input.profile)
    guard profile.serves(input.domain),
      let profileDays = UInt64(exactly: input.profileDays), profileDays > 0,
      let deviceDays = UInt64(exactly: input.deviceDays), deviceDays >= profileDays,
      input.deviceDays * 86400 <= 9007199254740991,
      input.publisher.utf8.count <= 4096, input.token.utf8.count <= 8192
    else { throw DiemError.invalidEncoding }
    var keys: [KeyFilePrivateKey] = []
    for (purpose, raw) in [(PublicKey.Purpose.identity, input.identity), (.device, input.device)] {
      if let raw {
        let key = try await backend.makePrivateKey(.ed25519, for: purpose, restoring: raw)
        keys.append(try KeyFilePrivateKey(publicKey: key.publicKey, secret: raw))
      }
    }
    var fields: [UInt64: CBOR] = [0: .text(input.domain), 1: .text(input.publisher), 2: .text(input.token),
      3: .unsigned(profileDays), 4: .unsigned(deviceDays), 5: .bool(input.autoRenew), 6: .bool(input.publicationPending)]
    if let domain = input.hostingDomain {
      fields[7] = try KeyFileHosting(domain: domain, held: input.hostingHeld, proofs: input.hostingProofs).encoded()
    }
    let metadata = CBOR.record(fields)
    let contents = try KeyFileContents(profile: profile, keys: keys, metadata: metadata)
    let recipient = try await backend.makeEncryptionKey(.p256)
    return try await KeyFile.seal(contents, salt: salt, to: recipient.publicKey, using: backend).encoding
  } catch { throw JSException(message: bridgeError(error)) }
}

@JS public func openKeyFile(encoding: [UInt8], crypto: JSObject) async throws(JSException) -> KeyFilePayload {
  do {
    let backend = BrowserBackend(now: 0, crypto: crypto)
    let file = try KeyFile(encoding: encoding)
    let recipient = try await backend.makeEncryptionKey(.p256)
    let contents = try await file.open(with: recipient, using: backend)
    guard contents.keys.allSatisfy({ $0.publicKey.algorithm == .ed25519 }) else {
      throw DiemError.unsupportedAlgorithm
    }
    let metadata = try contents.metadata.recordValue(requiredKeys: 0..<0)
    let domains = contents.profile.domains.map { $0.name }
    let domain = try metadata[0]?.textValue() ?? domains.first ?? ""
    guard domains.contains(domain) else { throw DiemError.identityMismatch }
    let hosting = try metadata[7].map { try KeyFileHosting($0) }
    return try KeyFilePayload(profile: contents.profile.encoding,
      identity: contents.keys.first(where: { $0.publicKey.purpose == .identity })?.secret,
      device: contents.keys.first(where: { $0.publicKey.purpose == .device })?.secret,
      domain: domain, publisher: metadata[1]?.textValue() ?? "", token: metadata[2]?.textValue() ?? "",
      profileDays: Double(metadata[3]?.unsignedValue() ?? 180), deviceDays: Double(metadata[4]?.unsignedValue() ?? 180),
      autoRenew: metadata[5]?.boolValue() ?? true, publicationPending: metadata[6]?.boolValue() ?? false,
      hostingDomain: hosting?.domain, hostingHeld: hosting?.held ?? [], hostingProofs: hosting?.proofs ?? [])
  } catch { throw JSException(message: bridgeError(error)) }
}

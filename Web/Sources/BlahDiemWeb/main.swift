import BlahDiem
import JavaScriptKit
import JavaScriptEventLoop

// WebCrypto owns the keys. The shared BlahDiem/Diem implementation owns all
// certificate, profile, purpose and wire-format rules, compiled for the browser.
// The WASM target is single-threaded; each call retains its own signer.
struct BrowserBackend: CryptoBackend, @unchecked Sendable {
  let now: UInt64
  let crypto: JSObject
  func randomBytes(count: Int) -> [UInt8] { bytes(crypto.random!(count)) }
  func makePrivateKey(_ algorithm: PublicKey.Algorithm, for purpose: PublicKey.Purpose,
    restoring rawRepresentation: [UInt8]?) async throws -> PrivateKey {
    guard algorithm == .ed25519, rawRepresentation == nil else { throw DiemError.unsupportedAlgorithm }
    let role = purpose == .identity ? "identity" : "device"
    let raw = bytes(crypto.publicKey!(role))
    return try PrivateKey(publicKey: PublicKey(purpose: purpose, algorithm: .ed25519,
      rawRepresentation: raw), protection: .software, rawRepresentation: nil) { message in
      let value = try await JSPromise(crypto.sign!(role, message).object!)!.value
      return bytes(value)
    }
  }
  func isValidSignature(_ signature: [UInt8], for message: [UInt8], by key: PublicKey) async throws -> Bool {
    guard key.algorithm == .ed25519 else { throw DiemError.unsupportedAlgorithm }
    return try await JSPromise(crypto.verify!(
      key.rawRepresentation, message, signature).object!)!.value.boolean!
  }
  func makeEncryptionKey(_ algorithm: EncryptionPublicKey.Algorithm,
    restoring rawRepresentation: [UInt8]?) async throws -> EncryptionPrivateKey {
    throw DiemError.unsupportedAlgorithm
  }
  func seal(_ plaintext: [UInt8], to key: EncryptionPublicKey, context: [UInt8]) async throws -> SealedBox {
    throw DiemError.unsupportedAlgorithm
  }
}

func bytes(_ value: JSValue) -> [UInt8] {
  let array = JSObject.global.Array.from(value)
  return (0..<Int(array.length.number!)).map { UInt8(array[$0].number!) }
}


/// Decimal strings preserve 64-bit identifiers across the JavaScript boundary.
@JS public struct IdentityRequest {
  public let operation: String
  public let domain: String
  public let profile: [UInt8]
  public let now: Double
  public let dc: [UInt8]
  public let dcDomain: String
  public let generation: String
  public let account: String?
  public let device: [UInt8]?
  public let challenge: [UInt8]?
  public let query: [UInt8]?
  public let keyID: String?
  public let sessionID: String?
  public let expiresAt: Double?

  public init(operation: String, domain: String, profile: [UInt8], now: Double, dc: [UInt8], dcDomain: String, generation: String, account: String?, device: [UInt8]?, challenge: [UInt8]?, query: [UInt8]?, keyID: String?, sessionID: String?, expiresAt: Double?) {
    self.operation = operation
    self.domain = domain
    self.profile = profile
    self.now = now
    self.dc = dc
    self.dcDomain = dcDomain
    self.generation = generation
    self.account = account
    self.device = device
    self.challenge = challenge
    self.query = query
    self.keyID = keyID
    self.sessionID = sessionID
    self.expiresAt = expiresAt
  }
}

@JS public struct DeviceInfo {
  public let id: String
  public let key: [UInt8]
  public let current: Bool

  public init(id: String, key: [UInt8], current: Bool) {
    self.id = id
    self.key = key
    self.current = current
  }
}

@JS public struct IdentityResult {
  public let id: String
  public let namespace: String
  public let profile: [UInt8]
  public let proof: [UInt8]
  public let account: String
  public let expiresAt: Double
  public let devices: [DeviceInfo]

  public init(id: String, namespace: String, profile: [UInt8], proof: [UInt8], account: String, expiresAt: Double, devices: [DeviceInfo]) {
    self.id = id
    self.namespace = namespace
    self.profile = profile
    self.proof = proof
    self.account = account
    self.expiresAt = expiresAt
    self.devices = devices
  }
}

JavaScriptEventLoop.installGlobalExecutor()
@JS public func identityOperation(input: IdentityRequest, crypto: JSObject) async throws(JSException) -> IdentityResult {
    do {
      guard input.now.isFinite, input.now >= 0, input.now <= 9007199254740991,
        let generation = UInt64(input.generation), generation > 0 else {
        throw BlahError.invalidProfile
      }
      let backend = BrowserBackend(now: UInt64(input.now), crypto: crypto)
      let deviceKey = try await DevicePrivateKey(backend.makePrivateKey(.ed25519, for: .device))
      let identityKey = input.operation != "prove"
        ? try await IdentityPrivateKey(backend.makePrivateKey(.ed25519, for: .identity)) : nil
      let dc = try Digest(bytes: input.dc)
      let domain = input.domain
      var identity: Identity
      if input.operation == "create" {
        let data = try UserProfile(home: Home(dc: dc, epoch: 1, expiresAt: backend.now + 30 * 86400),
          domains: [ProfileDomain(domain)]).encoded()
        guard let identityKey else { throw DiemError.identityKeyRequired }
        identity = try await Identity(data: data, identityKey: identityKey, deviceKey: deviceKey, using: backend)
      } else {
        identity = try await Identity(profile: Profile(encoding: input.profile),
          deviceKey: deviceKey, identityKey: identityKey, using: backend)
      }
      var user = try UserProfile(identity.profile)
      guard let home = user.home, home.dc == dc, user.domains.contains(where: { $0.name == domain })
      else { throw BlahError.wrongHome }
      var proof: [UInt8] = []
      switch input.operation {
      case "renew":
        user.home = Home(dc: home.dc, epoch: home.epoch, expiresAt: backend.now + 30 * 86400, account: home.account)
        try await identity.renew()
        try await identity.update(data: user.encoded())
      case "account":
        guard let account = Int64(input.account ?? ""), account > 0,
          home.account == nil || home.account == account else { throw BlahError.wrongNamespace }
        user.home = Home(dc: home.dc, epoch: home.epoch, expiresAt: home.expiresAt, account: account)
        try await identity.update(data: user.encoded())
      case "removeDevice":
        try await identity.remove(Digest(bytes: input.device ?? []))
      case "addDevice":
        try await identity.add(DevicePublicKey(PublicKey(encoding: input.device ?? [])))
      case "prove":
        let challenge = try InvocationChallenge(encoding: input.challenge ?? [])
        guard challenge.domain == domain, challenge.dc == dc, home.isActive(at: backend.now),
          UInt64(bitPattern: challenge.transportKeyID) == UInt64(input.keyID ?? ""),
          challenge.sessionID == UInt64(input.sessionID ?? ""),
          challenge.expiresAt == input.expiresAt.flatMap(UInt64.init(exactly:)) else { throw BlahError.invalidChallenge }
        proof = try await identity.prove(InvocationStatement(challenge: challenge, payload: input.query ?? [])).encoding
      case "create", "inspect": break
      default: throw BlahError.invalidProfile
      }
      let namespace = try ClientNamespace(profile: identity.profile,
        dc: DCAddress(domain: input.dcDomain, id: dc), generation: generation)
      return IdentityResult(id: identity.id.description, namespace: namespace.identifier,
        profile: identity.profile.encoding, proof: proof,
        account: user.home?.account.map(String.init) ?? "",
        expiresAt: Double(identity.profile.validity.expiresAt),
        devices: identity.profile.devices.map { certificate in
          DeviceInfo(id: certificate.device.id.description, key: certificate.device.key.encoding,
            current: certificate.device == deviceKey.publicKey)
        })
    } catch {
      throw JSException(message: bridgeError(error))
    }
}

// Explicit codes avoid pulling Swift reflection into the browser binary.
private func bridgeError(_ error: any Error) -> String {
  if let error = error as? JSException { return error.description }
  if let error = error as? BlahError {
    switch error {
    case .invalidProfile: return "invalidProfile"
    case .invalidName: return "invalidName"
    case .wrongHome: return "wrongHome"
    case .invalidChallenge: return "invalidChallenge"
    case .challengeExpired: return "challengeExpired"
    case .wrongNamespace: return "wrongNamespace"
    }
  }
  if let error = error as? DiemError {
    switch error {
    case .invalidEncoding: return "invalidEncoding"
    case .invalidKey: return "invalidKey"
    case .invalidSignature: return "invalidSignature"
    case .unsupportedAlgorithm: return "unsupportedAlgorithm"
    case .invalidValidity: return "invalidValidity"
    case .expired: return "expired"
    case .identityMismatch: return "identityMismatch"
    case .deviceNotListed: return "deviceNotListed"
    case .identityKeyRequired: return "identityKeyRequired"
    case .encryptionFailed: return "encryptionFailed"
    case .decryptionFailed: return "decryptionFailed"
    }
  }
  return "cryptoBackendFailed"
}

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
    guard key.algorithm == .ed25519 || key.algorithm == .p256 else { throw DiemError.unsupportedAlgorithm }
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
  public let profileLifetime: Double
  public let deviceLifetime: Double
  public let account: String?
  public let device: [UInt8]?
  public let challenge: [UInt8]?
  public let query: [UInt8]?
  public let keyID: String?
  public let sessionID: String?
  public let expiresAt: Double?
  public let kind: String
  public let challengeKind: String?
  public let approvedChallenge: [UInt8]?
  public let domains: [String]?
  public let usernameDomains: [String]?

  public init(operation: String, domain: String, profile: [UInt8], now: Double, dc: [UInt8], dcDomain: String, generation: String, profileLifetime: Double, deviceLifetime: Double, account: String?, device: [UInt8]?, challenge: [UInt8]?, query: [UInt8]?, keyID: String?, sessionID: String?, expiresAt: Double?, kind: String, challengeKind: String?, approvedChallenge: [UInt8]?, domains: [String]? = nil, usernameDomains: [String]? = nil) {
    self.operation = operation
    self.domain = domain
    self.profile = profile
    self.now = now
    self.dc = dc
    self.dcDomain = dcDomain
    self.generation = generation
    self.profileLifetime = profileLifetime
    self.deviceLifetime = deviceLifetime
    self.account = account
    self.device = device
    self.challenge = challenge
    self.query = query
    self.keyID = keyID
    self.sessionID = sessionID
    self.expiresAt = expiresAt
    self.kind = kind
    self.challengeKind = challengeKind
    self.approvedChallenge = approvedChallenge
    self.domains = domains
    self.usernameDomains = usernameDomains
  }
}

@JS public struct DeviceInfo {
  public let id: String
  public let key: [UInt8]
  public let current: Bool
  public let notBefore: Double
  public let expiresAt: Double

  public init(id: String, key: [UInt8], current: Bool, notBefore: Double, expiresAt: Double) {
    self.id = id
    self.key = key
    self.current = current
    self.notBefore = notBefore
    self.expiresAt = expiresAt
  }
}

@JS public struct IdentityResult {
  public let id: String
  public let namespace: String
  public let domains: [String]
  public let profile: [UInt8]
  public let proof: [UInt8]
  public let account: String
  public let notBefore: Double
  public let expiresAt: Double
  public let devices: [DeviceInfo]
  public let usernameDomains: [String]

  public init(id: String, namespace: String, domains: [String], profile: [UInt8], proof: [UInt8], account: String, notBefore: Double, expiresAt: Double, devices: [DeviceInfo], usernameDomains: [String] = []) {
    self.id = id
    self.namespace = namespace
    self.domains = domains
    self.profile = profile
    self.proof = proof
    self.account = account
    self.notBefore = notBefore
    self.expiresAt = expiresAt
    self.devices = devices
    self.usernameDomains = usernameDomains
  }
}

JavaScriptEventLoop.installGlobalExecutor()
@JS public func identityOperation(input: IdentityRequest, crypto: JSObject) async throws(JSException) -> IdentityResult {
    do {
      guard input.now.isFinite, input.now >= 0, input.now <= 9007199254740991,
        let generation = UInt64(input.generation), generation > 0,
        let profileLifetime = UInt64(exactly: input.profileLifetime), profileLifetime > 0,
        let deviceLifetime = UInt64(exactly: input.deviceLifetime), deviceLifetime >= profileLifetime,
        deviceLifetime <= 9007199254740991 - UInt64(input.now) else {
        throw BlahError.invalidProfile
      }
      let backend = BrowserBackend(now: UInt64(input.now), crypto: crypto)
      let deviceKey = try await DevicePrivateKey(backend.makePrivateKey(.ed25519, for: .device))
      let identityKey = input.operation != "prove"
        ? try await IdentityPrivateKey(backend.makePrivateKey(.ed25519, for: .identity)) : nil
      let dc = try Digest(bytes: input.dc)
      let domain = input.domain
      let kind = input.kind
      var identity: Identity
      if input.operation == "create" {
        let data = try HostedProfile(kind: kind,
          home: Home(dc: dc, epoch: 1, expiresAt: backend.now + deviceLifetime),
          domains: [ProfileDomain(domain)]).encoded()
        guard let identityKey else { throw DiemError.identityKeyRequired }
        identity = try await Identity(data: data, identityKey: identityKey, deviceKey: deviceKey,
          profileLifetime: profileLifetime, deviceLifetime: deviceLifetime, using: backend)
      } else {
        identity = try await Identity(profile: Profile(encoding: input.profile),
          deviceKey: deviceKey, identityKey: identityKey,
          profileLifetime: profileLifetime, deviceLifetime: deviceLifetime, using: backend)
      }
      var hosted = try HostedProfile(identity.profile, kind: kind)
      guard let home = hosted.home, home.dc == dc, hosted.domains.contains(where: { $0.name == domain })
      else { throw BlahError.wrongHome }
      var proof: [UInt8] = []
      switch input.operation {
      case "renew":
        hosted.home = Home(dc: home.dc, epoch: home.epoch, expiresAt: backend.now + deviceLifetime, account: home.account)
        try await identity.renew()
        try await identity.update(data: hosted.encoded())
      case "domains":
        guard kind == "user", let names = input.domains, !names.isEmpty,
          let usernames = input.usernameDomains, Set(usernames).count == usernames.count,
          Set(usernames).isSubset(of: Set(names)) else { throw BlahError.invalidName }
        hosted.domains = try names.map { try ProfileDomain($0, isUsername: usernames.contains($0)) }
        try await identity.update(data: hosted.encoded())
      case "account":
        guard let account = Int64(input.account ?? ""), account > 0,
          home.account == nil || home.account == account else { throw BlahError.wrongNamespace }
        hosted.home = Home(dc: home.dc, epoch: home.epoch, expiresAt: home.expiresAt, account: account)
        try await identity.update(data: hosted.encoded())
      case "removeDevice":
        try await identity.remove(Digest(bytes: input.device ?? []))
      case "addDevice":
        try await identity.add(DevicePublicKey(PublicKey(encoding: input.device ?? [])))
      case "prove":
        proof = try await proveChallenge(input, identity: identity, home: home)
      case "create", "inspect": break
      default: throw BlahError.invalidProfile
      }
      let namespace = try ClientNamespace(profile: identity.profile,
        dc: DCAddress(domain: input.dcDomain, id: dc), generation: generation)
      return IdentityResult(id: identity.id.description, namespace: namespace.identifier, domains: hosted.domains.map { $0.name },
        profile: identity.profile.encoding, proof: proof,
        account: hosted.home?.account.map(String.init) ?? "",
        notBefore: Double(identity.profile.validity.notBefore),
        expiresAt: Double(identity.profile.validity.expiresAt),
        devices: deviceInfo(identity), usernameDomains: hosted.domains.filter { $0.isUsername }.map { $0.name })
    } catch {
      throw JSException(message: bridgeError(error))
    }
}

func deviceInfo(_ identity: Identity) -> [DeviceInfo] {
  identity.profile.devices.map { certificate in
    DeviceInfo(id: certificate.device.id.description, key: certificate.device.key.encoding,
      current: certificate.device == identity.deviceKey.publicKey,
      notBefore: Double(certificate.validity.notBefore), expiresAt: Double(certificate.validity.expiresAt))
  }
}

// Explicit codes avoid pulling Swift reflection into the browser binary.
func bridgeError(_ error: any Error) -> String {
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

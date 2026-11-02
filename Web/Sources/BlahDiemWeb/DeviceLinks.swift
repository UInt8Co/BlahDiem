import BlahDiem
import JavaScriptKit

@JS public struct DeviceLinkInspection {
  public let device: [UInt8]
  public let label: String
  public let verifies: [Double]

  public init(device: [UInt8], label: String, verifies: [Double]) {
    self.device = device; self.label = label; self.verifies = verifies
  }
}

func inspectedLink(parameter: String, request: [UInt8]) throws -> (DeviceLinkCode, DeviceLinkRequest) {
  let code = try DeviceLinkCode(parameter: parameter)
  guard code.matches(request) else { throw BlahError.invalidDeviceLink }
  return (code, try DeviceLinkRequest(encoding: request))
}

@JS public func inspectDeviceLink(parameter: String, request: [UInt8]) throws(JSException) -> DeviceLinkInspection {
  do {
    let (_, request) = try inspectedLink(parameter: parameter, request: request)
    return DeviceLinkInspection(device: request.device.key.encoding, label: request.label,
      verifies: request.verifies.map { Double($0.rawValue) })
  } catch { throw JSException(message: bridgeError(error)) }
}

@JS public struct DeviceLinkBeginning {
  public let request: [UInt8]
  public let parameter: String
  public let session: String

  public init(request: [UInt8], parameter: String, session: String) {
    self.request = request; self.parameter = parameter; self.session = session
  }
}

private struct LinkSession {
  let request: DeviceLinkRequest
  let code: DeviceLinkCode
  let recipient: EncryptionPrivateKey
  let backend: BrowserBackend
}

// Each linking worker owns its HPKE recipient and one WASM session.
private var linkSessions: [String: LinkSession] = [:]

@JS public func destroyDeviceLink(session: String) {
  linkSessions.removeValue(forKey: session)
}

@JS public func beginDeviceLink(label: String, crypto: JSObject) async throws(JSException) -> DeviceLinkBeginning {
  do {
    let backend = BrowserBackend(now: 0, crypto: crypto)
    let device = try DevicePublicKey(PublicKey(purpose: .device, algorithm: .p256,
      rawRepresentation: bytes(crypto.publicKey!("device"))))
    let recipient = try await backend.makeEncryptionKey(.p256)
    let request = try DeviceLinkRequest(device: device, recipient: recipient.publicKey,
      label: label, verifies: [.ed25519, .p256])
    let code = try DeviceLinkCode(request: request, using: backend)
    let session = Digest(hashing: backend.randomBytes(count: 32)).description
    linkSessions[session] = LinkSession(request: request, code: code,
      recipient: recipient, backend: backend)
    return DeviceLinkBeginning(request: request.encoding, parameter: code.parameter, session: session)
  } catch { throw JSException(message: bridgeError(error)) }
}

@JS public struct DeviceLinkOpening {
  public let profile: [UInt8]
  public let domain: String
  public let seed: [UInt8]?
  public let metadata: [UInt8]?

  public init(profile: [UInt8], domain: String, seed: [UInt8]?, metadata: [UInt8]?) {
    self.profile = profile; self.domain = domain; self.seed = seed; self.metadata = metadata
  }
}

@JS public func openDeviceLink(session: String, response: [UInt8], expectedDC: [UInt8], now: Double)
  async throws(JSException) -> DeviceLinkOpening {
  do {
    guard let state = linkSessions.removeValue(forKey: session),
      let time = UInt64(exactly: now), now <= 9007199254740991 else { throw BlahError.invalidDeviceLink }
    let opened = try await DeviceLinkResponse.open(response, recipientKey: state.recipient,
      request: state.request, code: state.code, expectedDC: Digest(bytes: expectedDC), at: time, using: state.backend)
    return DeviceLinkOpening(profile: opened.grant.profile, domain: opened.grant.domain.name,
      seed: opened.seed?.entropy, metadata: opened.grant.metadata)
  } catch { throw JSException(message: bridgeError(error)) }
}

@JS public struct DeviceLinkApproval {
  public let code: String
  public let request: [UInt8]
  public let profile: [UInt8]
  public let domain: String
  public let seed: [UInt8]?
  public let metadata: [UInt8]?
  public let now: Double

  public init(code: String, request: [UInt8], profile: [UInt8], domain: String,
    seed: [UInt8]?, metadata: [UInt8]?, now: Double) {
    self.code = code; self.request = request; self.profile = profile; self.domain = domain
    self.seed = seed; self.metadata = metadata; self.now = now
  }
}

@JS public func respondToDeviceLink(input: DeviceLinkApproval, crypto: JSObject)
  async throws(JSException) -> [UInt8] {
  do {
    let (code, request) = try inspectedLink(parameter: input.code, request: input.request)
    guard let time = UInt64(exactly: input.now), input.now <= 9007199254740991,
      input.seed != nil || input.metadata == nil else { throw BlahError.invalidDeviceLink }
    let backend = BrowserBackend(now: time, crypto: crypto)
    let profile = try AnyBlahProfile(encoding: input.profile)
    try request.requireCompatible(identityKey: profile.identityKey, device: profile.record.signer)
    let sealed = try await input.seed.map { try IdentitySeed(entropy: $0) }?
      .sealed(to: request.recipient, identity: profile.identityKey, using: backend)
    let grant = try DeviceLinkGrant(profile: input.profile, domain: DomainName(input.domain),
      seed: sealed, metadata: input.metadata)
    return try await DeviceLinkResponse.seal(grant, for: request, code: code, using: backend)
  } catch { throw JSException(message: bridgeError(error)) }
}

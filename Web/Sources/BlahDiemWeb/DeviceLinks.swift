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
  let device: DevicePrivateKey
  let recipient: EncryptionPrivateKey
  let backend: BrowserBackend
}

// Each linking worker owns one WASM instance. No signing secret crosses its public API
// until open returns the canonical KeyFileContents through the existing custody path.
private var linkSessions: [String: LinkSession] = [:]

@JS public func destroyDeviceLink(session: String) {
  linkSessions.removeValue(forKey: session)
}

@JS public func beginDeviceLink(label: String, crypto: JSObject) async throws(JSException) -> DeviceLinkBeginning {
  do {
    let backend = BrowserBackend(now: 0, crypto: crypto)
    let device = try await DevicePrivateKey(backend.makePrivateKey(.ed25519, for: .device,
      restoring: backend.randomBytes(count: 32)))
    let recipient = try await backend.makeEncryptionKey(.p256)
    let request = try DeviceLinkRequest(device: device.publicKey, recipient: recipient.publicKey,
      label: label, verifies: [.ed25519])
    let code = try DeviceLinkCode(request: request, using: backend)
    let session = Digest(hashing: backend.randomBytes(count: 32)).description
    linkSessions[session] = LinkSession(request: request, code: code, device: device,
      recipient: recipient, backend: backend)
    return DeviceLinkBeginning(request: request.encoding, parameter: code.parameter, session: session)
  } catch { throw JSException(message: bridgeError(error)) }
}

@JS public struct DeviceLinkOpening {
  public let profile: [UInt8]
  public let domain: String
  public let identityKey: Bool
  public let metadata: [UInt8]?
  public let keyFileContents: [UInt8]

  public init(profile: [UInt8], domain: String, identityKey: Bool, metadata: [UInt8]?, keyFileContents: [UInt8]) {
    self.profile = profile; self.domain = domain; self.identityKey = identityKey
    self.metadata = metadata; self.keyFileContents = keyFileContents
  }
}

@JS public func openDeviceLink(session: String, response: [UInt8], expectedDC: [UInt8], now: Double)
  async throws(JSException) -> DeviceLinkOpening {
  do {
    guard let state = linkSessions.removeValue(forKey: session),
      let time = UInt64(exactly: now), now <= 9007199254740991 else { throw BlahError.invalidDeviceLink }
    let opened = try await DeviceLinkResponse.open(response, recipientKey: state.recipient,
      request: state.request, code: state.code, expectedDC: Digest(bytes: expectedDC), at: time, using: state.backend)
    guard let secret = state.device.rawRepresentation else { throw DiemError.invalidKey }
    var keys = [try KeyFilePrivateKey(publicKey: state.device.publicKey.key, secret: secret)]
    if let identityKey = opened.identityKey {
      guard let secret = identityKey.rawRepresentation else { throw DiemError.invalidKey }
      keys.append(try KeyFilePrivateKey(publicKey: identityKey.publicKey.key, secret: secret))
    }
    let contents = try KeyFileContents(profile: opened.profile, keys: keys,
      metadata: linkMetadata(opened.grant.metadata, domain: opened.grant.domain))
    return DeviceLinkOpening(profile: opened.grant.profile, domain: opened.grant.domain.name,
      identityKey: opened.identityKey != nil, metadata: opened.grant.metadata, keyFileContents: contents.encoding)
  } catch { throw JSException(message: bridgeError(error)) }
}

@JS public struct DeviceLinkApproval {
  public let parameter: String
  public let request: [UInt8]
  public let profile: [UInt8]
  public let domain: String
  public let transferIdentity: Bool
  public let metadata: [UInt8]?
  public let now: Double

  public init(parameter: String, request: [UInt8], profile: [UInt8], domain: String,
    transferIdentity: Bool, metadata: [UInt8]?, now: Double) {
    self.parameter = parameter; self.request = request; self.profile = profile; self.domain = domain
    self.transferIdentity = transferIdentity; self.metadata = metadata; self.now = now
  }
}

@JS public func respondToDeviceLink(input: DeviceLinkApproval, keyFile: [UInt8], crypto: JSObject)
  async throws(JSException) -> [UInt8] {
  do {
    let (code, request) = try inspectedLink(parameter: input.parameter, request: input.request)
    guard let time = UInt64(exactly: input.now), input.now <= 9007199254740991,
      input.transferIdentity || input.metadata == nil else { throw BlahError.invalidDeviceLink }
    let backend = BrowserBackend(now: time, crypto: crypto)
    let recipient = try await backend.makeEncryptionKey(.p256)
    let contents = try await KeyFile(encoding: keyFile).open(with: recipient, using: backend)
    guard let identity = contents.keys.first(where: { $0.publicKey.purpose == .identity }) else {
      throw DiemError.identityKeyRequired
    }
    guard let device = contents.keys.first(where: { $0.publicKey.purpose == .device }),
      contents.profile.encoding == input.profile else { throw DiemError.identityMismatch }
    try request.requireCompatible(identityKey: contents.profile.identityKey, device: DevicePublicKey(device.publicKey))
    let identityKey = try await IdentityPrivateKey(backend.makePrivateKey(identity.publicKey.algorithm,
      for: .identity, restoring: identity.secret))
    var metadata: [UInt8]?
    var sealed: SealedIdentityKey?
    if input.transferIdentity {
      sealed = try await identityKey.sealed(to: request.recipient, using: backend)
      var fields = try contents.metadata.recordValue(requiredKeys: 0..<0)
      fields.removeValue(forKey: 6)
      metadata = input.metadata ?? CBOR.record(fields).encoded
    }
    let grant = try DeviceLinkGrant(profile: input.profile, domain: DomainName(input.domain),
      identityKey: sealed, metadata: metadata)
    return try await DeviceLinkResponse.seal(grant, for: request, code: code, using: backend)
  } catch { throw JSException(message: bridgeError(error)) }
}

/// Portable browser metadata is optional. Unknown formats carry no browser settings.
func linkMetadata(_ bytes: [UInt8]?, domain: DomainName) -> CBOR {
  var fields: [UInt64: CBOR] = [:]
  if let bytes, let value = try? CBOR(decoding: bytes),
    let decoded = try? value.recordValue(requiredKeys: 0..<0) {
    // Read known settings individually so opaque or future metadata never prevents login.
    for key: UInt64 in [1, 2] {
      if let text = try? decoded[key]?.textValue(), text.utf8.count <= (key == 1 ? 4096 : 8192) {
        fields[key] = .text(text)
      }
    }
    if let profileDays = try? decoded[3]?.unsignedValue(), profileDays > 0,
      let deviceDays = try? decoded[4]?.unsignedValue(), deviceDays >= profileDays,
      deviceDays <= 9007199254740991 / 86400 {
      fields[3] = .unsigned(profileDays); fields[4] = .unsigned(deviceDays)
    }
    if let autoRenew = try? decoded[5]?.boolValue() { fields[5] = .bool(autoRenew) }
    if let hosting = decoded[7], (try? KeyFileHosting(hosting)) != nil { fields[7] = hosting }
  }
  fields[0] = .text(domain.name)
  // Publication state is local to the approving device and never transfers.
  fields[6] = .bool(false)
  return .record(fields)
}

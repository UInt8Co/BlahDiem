import BlahDiem
import JavaScriptKit

@JS public struct KeyFileInfo {
  public let id: String
  public let salt: [UInt8]
  public init(id: String, salt: [UInt8]) { self.id = id; self.salt = salt }
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

  public init(profile: [UInt8], identity: [UInt8]?, device: [UInt8]?, domain: String,
    publisher: String, token: String, profileDays: Double, deviceDays: Double,
    autoRenew: Bool, publicationPending: Bool) {
    self.profile = profile; self.identity = identity; self.device = device
    self.domain = domain; self.publisher = publisher; self.token = token
    self.profileDays = profileDays; self.deviceDays = deviceDays
    self.autoRenew = autoRenew; self.publicationPending = publicationPending
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
    let profile = try Profile(encoding: input.profile)
    guard try AnyBlahProfile(profile).domains.contains(input.domain),
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
    let metadata = CBOR.record([0: .text(input.domain), 1: .text(input.publisher), 2: .text(input.token),
      3: .unsigned(profileDays), 4: .unsigned(deviceDays), 5: .bool(input.autoRenew), 6: .bool(input.publicationPending)])
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
    let domains = try AnyBlahProfile(contents.profile).domains
    let domain = try metadata[0]?.textValue() ?? domains.first ?? ""
    guard domains.contains(domain) else { throw DiemError.identityMismatch }
    return try KeyFilePayload(profile: contents.profile.encoding,
      identity: contents.keys.first(where: { $0.publicKey.purpose == .identity })?.secret,
      device: contents.keys.first(where: { $0.publicKey.purpose == .device })?.secret,
      domain: domain, publisher: metadata[1]?.textValue() ?? "", token: metadata[2]?.textValue() ?? "",
      profileDays: Double(metadata[3]?.unsignedValue() ?? 180), deviceDays: Double(metadata[4]?.unsignedValue() ?? 180),
      autoRenew: metadata[5]?.boolValue() ?? true, publicationPending: metadata[6]?.boolValue() ?? false)
  } catch { throw JSException(message: bridgeError(error)) }
}

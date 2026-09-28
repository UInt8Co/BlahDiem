import BlahDiem
import JavaScriptKit

@JS public struct DCEndpointInfo {
  public let host: String
  public let port: Double
  public let tls: Bool
  public let transport: String
  public let path: String?

  public init(host: String, port: Double, tls: Bool, transport: String, path: String?) {
    self.host = host
    self.port = port
    self.tls = tls
    self.transport = transport
    self.path = path
  }
}

@JS public struct DCDiscoveryResult {
  public let id: String
  public let generation: String
  public let revision: String
  public let digest: String
  public let namespaceGeneration: String
  public let expiresAt: String
  public let endpoints: [DCEndpointInfo]
  public let transportPublicKey: String

  public init(id: String, generation: String, revision: String, digest: String,
    namespaceGeneration: String, expiresAt: String, endpoints: [DCEndpointInfo],
    transportPublicKey: String) {
    self.id = id
    self.generation = generation
    self.revision = revision
    self.digest = digest
    self.namespaceGeneration = namespaceGeneration
    self.expiresAt = expiresAt
    self.endpoints = endpoints
    self.transportPublicKey = transportPublicKey
  }
}

/// Verifies public discovery bytes without requesting any private key material.
@JS public func verifyDCProfile(domain: String, encoding: [UInt8], now: Double,
  crypto: JSObject) async throws(JSException) -> DCDiscoveryResult {
  do {
    guard let time = UInt64(exactly: now), time <= 9007199254740991 else {
      throw BlahError.invalidProfile
    }
    let profile = try Profile(encoding: encoding)
    try await profile.verify(using: BrowserBackend(now: time, crypto: crypto))
    let dc = try DCProfile(profile)
    guard dc.domains.contains(domain), let namespace = dc.namespaceGeneration else {
      throw BlahError.invalidProfile
    }
    return DCDiscoveryResult(id: profile.id.description,
      generation: String(profile.generation), revision: String(profile.revision),
      digest: profile.digest.description, namespaceGeneration: String(namespace),
      expiresAt: String(profile.validity.expiresAt),
      endpoints: dc.endpoints.map { DCEndpointInfo(host: $0.host, port: Double($0.port),
        tls: $0.tls, transport: $0.transport == .webSocket ? "webSocket" : "tcp", path: $0.path) },
      transportPublicKey: dc.transportPublicKey)
  } catch {
    throw JSException(message: bridgeError(error))
  }
}

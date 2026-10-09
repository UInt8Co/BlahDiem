import BlahDiem
import JavaScriptKit

/// All identifiers and timestamps are decimal strings; absent fields are nil.
@JS public struct ChallengeInfo {
  public let kind: String
  public var dc: [UInt8] = []
  public var dcDomain: String? = nil
  public var domain: String? = nil
  public var nonce: [UInt8] = []
  public var expiresAt: String = ""
  public var operation: String? = nil
  public var keyID: String? = nil
  public var sessionID: String? = nil
  public var identityID: [UInt8]? = nil
  public var deviceID: [UInt8]? = nil
  public var profileDigest: [UInt8]? = nil
  public var appID: String? = nil
  public var appName: String? = nil
  public var appVersion: String? = nil
  public var redirectURI: String? = nil
  public var scopes: [String]? = nil
  public var codeChallenge: String? = nil
  public var state: String? = nil
  public var oidcNonce: String? = nil
  public var revision: String? = nil
  public var document: [UInt8]? = nil
  public var requestID: [UInt8]? = nil
  public var externalID: String? = nil
  public var previousExternalID: String? = nil
  public var label: String? = nil
  public init(kind: String, dc: [UInt8] = [], dcDomain: String? = nil, domain: String? = nil, nonce: [UInt8] = [], expiresAt: String = "", operation: String? = nil, keyID: String? = nil, sessionID: String? = nil, identityID: [UInt8]? = nil, deviceID: [UInt8]? = nil, profileDigest: [UInt8]? = nil, appID: String? = nil, appName: String? = nil, appVersion: String? = nil, redirectURI: String? = nil, scopes: [String]? = nil, codeChallenge: String? = nil, state: String? = nil, oidcNonce: String? = nil, revision: String? = nil, document: [UInt8]? = nil, requestID: [UInt8]? = nil, externalID: String? = nil, previousExternalID: String? = nil, label: String? = nil) {
    self.kind = kind
    self.dc = dc
    self.dcDomain = dcDomain
    self.domain = domain
    self.nonce = nonce
    self.expiresAt = expiresAt
    self.operation = operation
    self.keyID = keyID
    self.sessionID = sessionID
    self.identityID = identityID
    self.deviceID = deviceID
    self.profileDigest = profileDigest
    self.appID = appID
    self.appName = appName
    self.appVersion = appVersion
    self.redirectURI = redirectURI
    self.scopes = scopes
    self.codeChallenge = codeChallenge
    self.state = state
    self.oidcNonce = oidcNonce
    self.revision = revision
    self.document = document
    self.requestID = requestID
    self.externalID = externalID
    self.previousExternalID = previousExternalID
    self.label = label
  }
}

/// Decodes a DC challenge for the caller to compare with its session or display for consent.
@JS public func inspectChallenge(kind: String, encoding: [UInt8]) throws(JSException) -> ChallengeInfo {
  do {
    var info = ChallengeInfo(kind: kind)
    switch kind {
    case "invocation":
      let c = try InvocationChallenge(encoding: encoding)
      info.dc = c.dc.bytes; info.domain = c.domain.name; info.nonce = c.nonce
      info.expiresAt = String(c.expiresAt)
      info.keyID = String(UInt64(bitPattern: c.transportKeyID)); info.sessionID = String(c.sessionID)
    case "login":
      let c = try LoginChallenge(encoding: encoding)
      info.dc = c.dc.id.bytes; info.dcDomain = c.dc.domain.name; info.nonce = c.nonce
      info.expiresAt = String(c.expiresAt); info.operation = c.operation == .signUp ? "signUp" : "signIn"
      info.keyID = String(UInt64(bitPattern: c.authKeyID)); info.sessionID = String(c.sessionID)
      info.identityID = c.identityID.bytes; info.deviceID = c.deviceID.bytes
      info.profileDigest = c.profileDigest.bytes
    case "oauthConsent":
      let c = try OAuthConsentChallenge(encoding: encoding)
      info.dc = c.dc.id.bytes; info.dcDomain = c.dc.domain.name; info.nonce = c.nonce
      info.expiresAt = String(c.expiresAt); info.appID = String(c.appID); info.appName = c.appName
      info.appVersion = String(c.appVersion); info.redirectURI = c.redirectURI; info.scopes = c.scopes
      info.codeChallenge = c.codeChallenge; info.state = c.state; info.oidcNonce = c.oidcNonce
    case "accountLink":
      let c = try AccountLinkChallenge(encoding: encoding)
      info.dc = c.dc.id.bytes; info.dcDomain = c.dc.domain.name; info.nonce = c.nonce
      info.expiresAt = String(c.expiresAt)
      switch c.operation {
      case .read: info.operation = "read"
      case .start: info.operation = "start"
      case .confirm: info.operation = "confirm"
      case .unlink: info.operation = "unlink"
      }
      info.identityID = c.identityID?.bytes; info.requestID = c.requestID
      info.externalID = c.externalID; info.previousExternalID = c.previousExternalID; info.label = c.label
    case "dcAdmin":
      let c = try DCAdminChallenge(encoding: encoding)
      info.dc = c.dc.id.bytes; info.dcDomain = c.dc.domain.name; info.nonce = c.nonce
      info.expiresAt = String(c.expiresAt); info.revision = String(c.revision); info.document = c.document
      switch c.operation {
      case .read: info.operation = "read"
      case .replace: info.operation = "replace"
      case .linkBot: info.operation = "linkBot"
      }
    default: throw BlahError.invalidChallenge
    }
    return info
  } catch {
    throw JSException(message: bridgeError(error))
  }
}

func proveChallenge(_ input: IdentityRequest, identity: BasicIdentity<AnyBlahProfile>, home: Home) async throws -> [UInt8] {
  let encoding = input.challenge ?? []
  let kind = input.challengeKind ?? ""
  let info = try inspectChallenge(kind: kind, encoding: encoding)
  guard home.isActive(at: identity.backend.now), info.dc == home.dc.bytes,
    info.dcDomain == nil || info.dcDomain == input.dcDomain,
    let expiresAt = input.expiresAt.flatMap(UInt64.init(exactly:)), info.expiresAt == String(expiresAt)
  else { throw BlahError.invalidChallenge }
  // Pin the bytes the application actually reviewed; never silently approve a replacement.
  guard input.approvedChallenge == encoding else { throw BlahError.invalidChallenge }
  if kind == "invocation" || kind == "login" {
    guard info.keyID == input.keyID, info.sessionID == input.sessionID else {
      throw BlahError.invalidChallenge
    }
  }
  switch kind {
  case "invocation":
    guard info.domain == input.domain, let query = input.query else { throw BlahError.invalidChallenge }
    return try await identity.prove(InvocationStatement(
      challenge: InvocationChallenge(encoding: encoding), payload: query)).encoding
  case "login": return try await identity.prove(LoginChallenge(encoding: encoding)).encoding
  case "oauthConsent": return try await identity.prove(OAuthConsentChallenge(encoding: encoding)).encoding
  case "accountLink": return try await identity.prove(AccountLinkChallenge(encoding: encoding)).encoding
  case "dcAdmin": return try await identity.prove(DCAdminChallenge(encoding: encoding)).encoding
  default: throw BlahError.invalidChallenge
  }
}

/// Exact, one-attempt authorization-code consent. The client compares these
/// fields with the app and permissions the user reviewed before signing.
public struct OAuthConsentChallenge: Sendable {
  public let destination: FederationDestination
  public let nonce: [UInt8]
  public let expiresAt: UInt64
  public let appID: UInt64
  public let appName: String
  public let appVersion: UInt64
  public let redirectURI: String
  public let scopes: [String]
  public let codeChallenge: String
  public let state: String
  public let oidcNonce: String

  public init(
    destination: FederationDestination, nonce: [UInt8], expiresAt: UInt64,
    appID: UInt64, appName: String, appVersion: UInt64, redirectURI: String,
    scopes: [String], codeChallenge: String, state: String, oidcNonce: String
  ) throws {
    guard nonce.count == 32, expiresAt <= UInt64(Int64.max), appID > 0,
      appID <= UInt64(Int32.max), appVersion <= UInt64(Int64.max),
      !appName.isEmpty, appName.utf8.count <= 256, !redirectURI.isEmpty,
      redirectURI.utf8.count <= 2048, !scopes.isEmpty, scopes.count <= 16,
      scopes == Array(Set(scopes)).sorted(),
      scopes.allSatisfy({ !$0.isEmpty && $0.utf8.count <= 64 }),
      codeChallenge.utf8.count == 43,
      codeChallenge.utf8.allSatisfy({
        (65...90).contains($0) || (97...122).contains($0) || (48...57).contains($0)
          || $0 == 45 || $0 == 95
      }), state.utf8.count <= 1024, oidcNonce.utf8.count <= 1024
    else { throw FederationError.invalidChallenge }
    self.destination = destination
    self.nonce = nonce
    self.expiresAt = expiresAt
    self.appID = appID
    self.appName = appName
    self.appVersion = appVersion
    self.redirectURI = redirectURI
    self.scopes = scopes
    self.codeChallenge = codeChallenge
    self.state = state
    self.oidcNonce = oidcNonce
  }

  public var encoding: [UInt8] {
    CBOR.array([
      .unsignedInt(BlahDiemTag.oauthConsent.rawValue), .unsignedInt(1), .textString(destination.domain),
      .byteString(destination.keyID[...]), .byteString(nonce[...]), .unsignedInt(expiresAt),
      .unsignedInt(appID), .textString(appName), .unsignedInt(appVersion),
      .textString(redirectURI), .array(scopes.map(CBOR.textString)),
      .textString(codeChallenge), .textString(state), .textString(oidcNonce),
    ]).encode()
  }
  public static func decode(_ bytes: [UInt8]) throws -> Self {
    let a = try CanonicalCBOR.array(bytes, count: 14)
    guard a[0] == .unsignedInt(BlahDiemTag.oauthConsent.rawValue), a[1] == .unsignedInt(1),
      case .textString(let domain) = a[2], case .byteString(let key) = a[3],
      case .byteString(let nonce) = a[4], case .unsignedInt(let expiry) = a[5],
      case .unsignedInt(let appID) = a[6], case .textString(let name) = a[7],
      case .unsignedInt(let version) = a[8], case .textString(let redirect) = a[9],
      case .array(let scopeValues) = a[10], case .textString(let pkce) = a[11],
      case .textString(let state) = a[12], case .textString(let oidcNonce) = a[13]
    else { throw FederationError.invalidChallenge }
    let scopes = try scopeValues.map { value -> String in
      guard case .textString(let scope) = value else { throw FederationError.invalidChallenge }
      return scope
    }
    return try .init(
      destination: .init(domain: domain, keyID: Array(key)), nonce: Array(nonce),
      expiresAt: expiry, appID: appID, appName: name, appVersion: version,
      redirectURI: redirect, scopes: scopes, codeChallenge: pkce, state: state,
      oidcNonce: oidcNonce)
  }

  /// `reviewed` is constructed from the consent screen the user approved, not
  /// blindly decoded from an untrusted relay's response.
  public func approve(
    device: DeviceSigner, profile: SignedProfile, reviewed: Self, at now: UInt64
  ) throws -> DeviceProof {
    guard encoding == reviewed.encoding, expiresAt > now, expiresAt - now <= 120 else {
      throw FederationError.invalidChallenge
    }
    try HomeDelegation(profile: profile, at: now).requireHome(destination)
    return try device.sign(
      encoding, purpose: .action, profile: profile, at: now, using: SoftwareDeviceCrypto())
  }
}

/// Descendant credentials remain tied to the device and authority which granted
/// them. A changed roster requires fresh consent, including after re-enrollment.
public struct DeviceCredentialAuthority: Sendable {
  public let identityID: [UInt8]
  public let deviceID: [UInt8]
  public let rosterRevision: UInt64
  public let homeEpoch: UInt64
  public let destination: FederationDestination

  public init(
    proof: DeviceProof, profile: SignedProfile, destination: FederationDestination, at now: UInt64
  ) throws {
    try proof.verify(purpose: .action, profile: profile, at: now, using: SoftwareDeviceCrypto())
    let home = try HomeDelegation(profile: profile, at: now)
    try home.requireHome(destination)
    identityID = proof.identityID
    deviceID = proof.deviceID
    rosterRevision = profile.deviceList.body.revision
    homeEpoch = home.epoch
    self.destination = destination
  }
  /// The authority of a device that is already signed in: a live, validated session
  /// stands in for a fresh proof, as when the device answers a prompt in Blah.
  public static func session(
    identityID: [UInt8], deviceID: [UInt8], profile: SignedProfile, homeEpoch: UInt64,
    destination: FederationDestination
  ) throws -> Self {
    try Self(identityID: identityID, deviceID: deviceID,
      rosterRevision: profile.deviceList.body.revision, homeEpoch: homeEpoch, destination: destination)
  }
  private init(
    identityID: [UInt8], deviceID: [UInt8], rosterRevision: UInt64, homeEpoch: UInt64,
    destination: FederationDestination
  ) throws {
    guard identityID.count == 32, deviceID.count == 32, rosterRevision > 0, homeEpoch > 0 else {
      throw FederationError.invalidDelegation
    }
    self.identityID = identityID
    self.deviceID = deviceID
    self.rosterRevision = rosterRevision
    self.homeEpoch = homeEpoch
    self.destination = destination
  }
  public var encoding: [UInt8] {
    CBOR.array([
      .unsignedInt(BlahDiemTag.credentialAuthority.rawValue), .unsignedInt(1), .byteString(identityID[...]),
      .byteString(deviceID[...]), .unsignedInt(rosterRevision), .unsignedInt(homeEpoch),
      .textString(destination.domain), .byteString(destination.keyID[...]),
    ]).encode()
  }
  public static func decode(_ bytes: [UInt8]) throws -> Self {
    let a = try CanonicalCBOR.array(bytes, count: 8)
    guard a[0] == .unsignedInt(BlahDiemTag.credentialAuthority.rawValue), a[1] == .unsignedInt(1),
      case .byteString(let identity) = a[2], case .byteString(let device) = a[3],
      case .unsignedInt(let revision) = a[4], case .unsignedInt(let epoch) = a[5],
      case .textString(let domain) = a[6], case .byteString(let key) = a[7]
    else { throw FederationError.invalidDelegation }
    return try .init(
      identityID: Array(identity), deviceID: Array(device), rosterRevision: revision,
      homeEpoch: epoch, destination: .init(domain: domain, keyID: Array(key)))
  }
  public func validate(
    profile: SignedProfile, destination expected: FederationDestination, at now: UInt64
  ) throws {
    let crypto = SoftwareDeviceCrypto()
    try profile.verify(at: now, using: crypto)
    let home = try HomeDelegation(profile: profile, at: now)
    try home.requireHome(expected)
    guard destination == expected, profile.id == identityID,
      profile.deviceList.body.revision == rosterRevision, home.epoch == homeEpoch,
      profile.deviceList.body.devices.contains(where: { $0.id(using: crypto) == deviceID })
    else { throw FederationError.authorityUnavailable }
  }
}

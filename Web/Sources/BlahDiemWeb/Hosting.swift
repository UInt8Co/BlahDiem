import BlahDiem
import DiemProfileHostingClient
import JavaScriptKit
import JavaScriptEventLoop

// Callback objects belong to one operation on this single-threaded WASM runtime.
struct BrowserHostingHTTP: HostingHTTPClient, @unchecked Sendable {
  let callbacks: JSObject

  func send(_ request: HostingHTTPRequest) async throws -> HostingHTTPResponse {
    let names = Array(request.headers.keys)
    let value = try await JSPromise(callbacks.http!(request.method.rawValue, request.url,
      names, names.map { request.headers[$0]! }, request.body).object!)!.value.object!
    let keys = JSObject.global.Array.from(value.names)
    let values = JSObject.global.Array.from(value.values)
    var headers: [String: String] = [:]
    for index in 0..<Int(keys.length.number!) {
      headers[keys[index].string!] = values[index].string!
    }
    return HostingHTTPResponse(status: Int(value.status.number!), headers: headers, body: bytes(value.body))
  }
}

struct BrowserHostingSolver: ProofOfWorkSolver, @unchecked Sendable {
  let callbacks: JSObject

  func solve(_ puzzle: ProofOfWorkPuzzle) async throws -> [UInt8] {
    bytes(try await JSPromise(callbacks.solve!(puzzle.label, puzzle.input,
      puzzle.requiredBits).object!)!.value)
  }
}

@JS public struct HostingWorkInfo {
  public let algorithm: String
  public let baseBits: Double
  public let bitsPerShorterCharacter: Double
  public let referenceLength: Double

  public init(algorithm: String, baseBits: Double, bitsPerShorterCharacter: Double, referenceLength: Double) {
    self.algorithm = algorithm; self.baseBits = baseBits
    self.bitsPerShorterCharacter = bitsPerShorterCharacter; self.referenceLength = referenceLength
  }
}

@JS public struct HostingNamesInfo {
  public let labelPattern: String
  public let maxClaimsPerIdentity: Double
  public let maxUpdatesPerIdentityPerHour: Double
  public let claimGraceAfterExpiry: Double
  public let proofOfWork: HostingWorkInfo

  public init(labelPattern: String, maxClaimsPerIdentity: Double,
    maxUpdatesPerIdentityPerHour: Double, claimGraceAfterExpiry: Double, proofOfWork: HostingWorkInfo) {
    self.labelPattern = labelPattern; self.maxClaimsPerIdentity = maxClaimsPerIdentity
    self.maxUpdatesPerIdentityPerHour = maxUpdatesPerIdentityPerHour
    self.claimGraceAfterExpiry = claimGraceAfterExpiry; self.proofOfWork = proofOfWork
  }
}

@JS public struct HostingPolicyInfo {
  public let domain: String
  public let apex: Bool
  public let names: HostingNamesInfo?

  public init(domain: String, apex: Bool, names: HostingNamesInfo?) {
    self.domain = domain; self.apex = apex; self.names = names
  }
}

@JS public struct HostingPuzzleInfo {
  public let label: String
  public let input: [UInt8]
  public let requiredBits: Double

  public init(label: String, input: [UInt8], requiredBits: Double) {
    self.label = label; self.input = input; self.requiredBits = requiredBits
  }
}

@JS public struct HostingNameInfo {
  public let label: String
  public let status: String
  public let requiredBits: Double?
  public let puzzle: HostingPuzzleInfo?

  public init(label: String, status: String, requiredBits: Double?, puzzle: HostingPuzzleInfo?) {
    self.label = label; self.status = status; self.requiredBits = requiredBits; self.puzzle = puzzle
  }
}

@JS public struct HostingProofInfo {
  public let label: String
  public let nonce: [UInt8]

  public init(label: String, nonce: [UInt8]) { self.label = label; self.nonce = nonce }
}

@JS public struct HostingPublishedInfo {
  public let identity: String
  public let revision: String
  public let domains: [String]

  public init(identity: String, revision: String, domains: [String]) {
    self.identity = identity; self.revision = revision; self.domains = domains
  }
}

@JS public func hostingPolicy(domain: String, callbacks: JSObject) async throws(JSException) -> HostingPolicyInfo {
  do {
    let policy = try await ProfileHostingClient(domain: DomainName(domain),
      http: BrowserHostingHTTP(callbacks: callbacks)).policy()
    let names = policy.names.map { names in
      HostingNamesInfo(labelPattern: names.labelPattern,
        maxClaimsPerIdentity: Double(names.maxClaimsPerIdentity),
        maxUpdatesPerIdentityPerHour: Double(names.maxUpdatesPerIdentityPerHour),
        claimGraceAfterExpiry: Double(names.claimGraceAfterExpiry),
        proofOfWork: HostingWorkInfo(algorithm: names.algorithm, baseBits: Double(names.baseBits),
          bitsPerShorterCharacter: Double(names.bitsPerShorterCharacter), referenceLength: Double(names.referenceLength)))
    }
    return HostingPolicyInfo(domain: policy.domain.name, apex: policy.apex, names: names)
  } catch { throw hostingError(error) }
}

@JS public func hostingPlan(domain: String, labels: [String], identity: [UInt8], callbacks: JSObject)
  async throws(JSException) -> [HostingNameInfo] {
  do {
    let host = try ProfileHostingClient(domain: DomainName(domain), http: BrowserHostingHTTP(callbacks: callbacks))
    let id = try Digest(bytes: identity)
    let plan = try await host.plan(labels: labels, identity: id)
    return try plan.names.map { name in
      let status: String
      var bits: Double?
      var puzzle: HostingPuzzleInfo?
      switch name.status {
      case .invalid: status = "invalid"
      case .taken: status = "taken"
      case .held: status = "held"
      case .needsProof(let required):
        status = "needsProof"
        guard (0...64).contains(required) else { throw ProfileHostingError.unsolvable(name.label) }
        bits = Double(required)
        if required > 0 {
          let work = try ProofOfWorkPuzzle(domain: host.domain, label: name.label, identityID: id, requiredBits: Int(required))
          puzzle = HostingPuzzleInfo(label: name.label, input: work.input, requiredBits: Double(required))
        }
      }
      return HostingNameInfo(label: name.label, status: status, requiredBits: bits, puzzle: puzzle)
    }
  } catch { throw hostingError(error) }
}

@JS public func hostingPublish(domain: String, encoding: [UInt8], via: String?, apex: Bool,
  proofs: [HostingProofInfo], solve: Bool, callbacks: JSObject) async throws(JSException) -> HostingPublishedInfo {
  do {
    let host = try ProfileHostingClient(domain: DomainName(domain), http: BrowserHostingHTTP(callbacks: callbacks))
    let profile = try ProfileRecord(encoding: encoding)
    let hosted = host.labels(in: profile)
    // The host checks supplied nonces; checking them here would cost a difficulty request
    // per name on every publication. Solver nonces are checked by the client.
    var nonces: [String: [UInt8]] = [:]
    for proof in proofs {
      guard hosted.contains(proof.label), nonces[proof.label] == nil else { throw ProfileHostingError.invalidProof(proof.label) }
      nonces[proof.label] = proof.nonce
    }
    let target: HostingTarget? = apex ? .apex : via.map { .name($0) }
    let publication: HostingPublication<ProfileRecord>
    if let target { publication = HostingPublication(profile: profile, proofs: nonces, via: target) }
    else { publication = HostingPublication(profile: profile, proofs: nonces) }
    if solve {
      try await host.publish(publication, solver: BrowserHostingSolver(callbacks: callbacks))
    } else if let target {
      try await host.publish(profile, via: target, proofs: nonces)
    } else { try await host.publish(profile, proofs: nonces) }
    let domains = profile.domains.filter { name in
      name == host.domain || hosted.contains { name.name == $0 + "." + host.domain.name }
    }.map { $0.name }
    return HostingPublishedInfo(identity: profile.id.description, revision: String(profile.revision), domains: domains)
  } catch { throw hostingError(error) }
}

@JS public func hostingProfile(domain: String, label: String?, apex: Bool, callbacks: JSObject)
  async throws(JSException) -> [UInt8]? {
  do {
    let host = try ProfileHostingClient(domain: DomainName(domain), http: BrowserHostingHTTP(callbacks: callbacks))
    let target: HostingTarget
    if apex { target = .apex }
    else if let label { target = .name(label) }
    else { throw ProfileHostingError.invalidLabel("") }
    return try await host.profile(at: target)
  } catch { throw hostingError(error) }
}

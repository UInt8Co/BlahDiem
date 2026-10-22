import Diem
import Foundation
import DiemProfileHostingClient

// Independent wire encoder/decoder; production JSON and header formatting are not used.
actor HostingTestHost: HostingHTTPClient {
  let domain = "id.example"
  var bits = 4
  var claims: [String: ProfileRecord] = [:]
  var revisions: [Digest: ProfileRecord] = [:]
  var requests: [HostingHTTPRequest] = []
  var limited = false

  func send(_ request: HostingHTTPRequest) async throws -> HostingHTTPResponse {
    requests.append(request)
    let url = URL(string: request.url)!
    let host = url.host!
    let path = url.path
    if host == domain {
      guard request.method == .get else { return .init(status: 404) }
      if path == "/.well-known/diem/hosting" { return Self.json(Self.policy()) }
      let prefix = "/.well-known/diem/hosting/names/"
      guard path.hasPrefix(prefix) else { return .init(status: 404) }
      let label = String(path.dropFirst(prefix.count))
      return Self.json(["label": label,
        "status": label == "reserved" ? "invalid" : claims[label] == nil ? "available" : "claimed",
        "requiredBits": bits])
    }
    guard host.hasSuffix("." + domain), path == "/.well-known/diem/profile.cbor" else {
      return .init(status: 404)
    }
    let label = String(host.dropLast(domain.count + 1))
    guard !label.contains(".") else { return .init(status: 404) }
    if request.method == .get || request.method == .head {
      guard let profile = claims[label] else { return .init(status: 404) }
      return .init(status: 200, body: request.method == .head ? [] : profile.encoding)
    }
    let profile = try ProfileRecord(encoding: request.body ?? [])
    let names = profile.domains.map(\.name).filter { $0.hasSuffix("." + domain) }
      .map { String($0.dropLast(domain.count + 1)) }
    guard names.contains(label) || (names.isEmpty && claims[label]?.id == profile.id) else {
      return problem("host-not-listed", status: 422)
    }
    if let previous = revisions[profile.id] {
      if previous == profile { return published(profile, names: names) }
      if previous.revision >= profile.revision { return problem("stale-revision", status: 409) }
    }
    let taken = names.filter { claims[$0] != nil && claims[$0]?.id != profile.id }
    if !taken.isEmpty { return problem("name-taken", status: 409, labels: taken) }
    var proofs: [String: [UInt8]] = [:]
    if let header = request.headers["Diem-Hosting-Proof"] {
      for entry in header.components(separatedBy: ", ") {
        let pair = entry.components(separatedBy: "=")
        guard pair.count == 2, proofs[pair[0]] == nil else {
          return problem("proof-required", status: 403, labels: names)
        }
        let value = pair[1].replacingOccurrences(of: "-", with: "+")
          .replacingOccurrences(of: "_", with: "/")
        guard let nonce = Data(base64Encoded: value + String(repeating: "=",
          count: (4 - value.count % 4) % 4)) else {
          return problem("proof-required", status: 403, labels: names)
        }
        proofs[pair[0]] = Array(nonce)
      }
    }
    let missing = names.filter { name in
      if claims[name]?.id == profile.id { return false }
      guard let nonce = proofs[name], (1...64).contains(nonce.count) else { return true }
      let input = Array("diem-profile-hosting-pow-v1\0id.example\0\(name)\0".utf8)
        + profile.id.bytes + nonce
      return SHA2.sha256(input)[0] >> (8 - bits) != 0
    }
    if !missing.isEmpty {
      return problem("proof-required", status: 403, labels: missing.isEmpty ? names : missing)
    }
    if limited { return problem("rate-limited", status: 429) }
    claims = claims.filter { $0.value.id != profile.id }
    for name in names { claims[name] = profile }
    revisions[profile.id] = profile
    return published(profile, names: names)
  }

  func published(_ profile: ProfileRecord, names: [String]) -> HostingHTTPResponse {
    Self.json(["identity": Self.base64(profile.id.bytes), "revision": profile.revision,
      "domains": names.sorted().map { $0 + "." + domain }])
  }

  func problem(_ code: String, status: Int, labels: [String] = []) -> HostingHTTPResponse {
    Self.json(["type": "urn:diem:profile-hosting:" + code, "title": code,
      "status": status, "detail": "Refused", "labels": labels.map { label in
        var item: [String: Any] = ["label": label, "reason": code]
        if code == "proof-required" { item["requiredBits"] = bits }
        return item
      }], status: status, headers: status == 429 ? ["rEtRy-AfTeR": "37"] : [:])
  }

  static func base64(_ bytes: [UInt8]) -> String {
    Data(bytes).base64EncodedString().replacingOccurrences(of: "+", with: "-")
      .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
  }

  static func json(_ object: [String: Any], status: Int = 200,
    headers: [String: String] = [:]
  ) -> HostingHTTPResponse {
    .init(status: status, headers: headers,
      body: Array(try! JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])))
  }

  static func policy(domain: String = "id.example", algorithm: String = "sha256-leading-zero-bits-v1",
    base: Int64 = 4, slope: Int64 = 0, length: Int64 = 8
  ) -> [String: Any] {
    ["domain": domain, "labelPattern": "[a-z0-9-]+", "maxClaimsPerIdentity": 3,
      "maxUpdatesPerIdentityPerHour": 12, "claimGraceAfterExpiry": 2_592_000,
      "proofOfWork": ["algorithm": algorithm, "baseBits": base,
        "bitsPerShorterCharacter": slope, "referenceLength": length]]
  }
}

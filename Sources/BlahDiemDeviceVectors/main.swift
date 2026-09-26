import Crypto
import BlahDiem
import Foundation

let crypto = SoftwareDeviceCrypto()
let now: UInt64 = 1_800_000_000
var vectors: [[String: Any]] = []
for algorithm: KeyAlgorithm in [.ed25519, .p256Signing] {
  let device = try crypto.makeDevice(signing: algorithm, wrapping: .p256Agreement)
  let created = try IdentityController.create(on: device, fields: .map([]), at: now)
  let p = created.profile
  let proof = try device.sign(
    Array("cross-language".utf8), purpose: .message,
    profile: p, at: now, using: crypto)
  // Software-only test key, deliberately public fixture material. Never a device credential.
  let wrappingFixture = P256.KeyAgreement.PrivateKey()
  let wrappingPublic = try DevicePublicKey(
    algorithm: .p256Agreement,
    rawRepresentation: Array(wrappingFixture.publicKey.x963Representation))
  let context = Array("Diem/v2/independent-HPKE-vector".utf8)
  let plaintext = crypto.randomBytes(count: 32)
  let wrapped = try crypto.seal(plaintext, to: wrappingPublic, context: context)
  vectors.append([
    "signingAlgorithm": algorithm.rawValue,
    "identityID": p.id.hexString,
    "identityPublicKey": p.identityKey.encoding.hexString,
    "deviceID": device.signingKey.publicKey.id(using: crypto).hexString,
    "devicePublicKey": device.signingKey.publicKey.encoding.hexString,
    "rosterBytes": p.deviceList.payloadBytes.hexString,
    "rosterSignature": p.deviceList.signature.hexString,
    "rosterDigest": p.deviceList.digest(using: crypto).hexString,
    "profileBytes": p.payloadBytes.hexString,
    "profileSignature": p.signature.hexString,
    "profileDigest": p.digest(using: crypto).hexString,
    "profile": p.encoding.hexString,
    "proofBytes": proof.payloadBytes.hexString,
    "proofSignature": proof.signature.hexString,
    "proof": proof.encoding.hexString,
    "hpkePrivateKey": Array(wrappingFixture.rawRepresentation).hexString,
    "hpkePublicKey": wrappingPublic.rawRepresentation.hexString,
    "hpkeEncapsulatedKey": wrapped.encapsulatedKey.hexString,
    "hpkeCiphertext": wrapped.ciphertext.hexString,
    "hpkeContext": context.hexString,
    "hpkePlaintext": plaintext.hexString,
  ])
}
let json = try JSONSerialization.data(
  withJSONObject: ["protocol": "Diem/v2", "now": now, "vectors": vectors],
  options: [.prettyPrinted, .sortedKeys])
print(String(decoding: json, as: UTF8.self))

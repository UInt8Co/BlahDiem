import BlahDiem
import DiemTesting
import Testing

/// Blah's QR device link uses Diem's records unchanged; these bytes were assembled
/// independently of Diem's encoder.
@Suite struct LinkEncodingVectorTests {
  private func hex(_ text: String) -> [UInt8] {
    let characters = Array(text)
    return stride(from: 0, to: characters.count, by: 2).map {
      UInt8(String(characters[$0...($0 + 1)]), radix: 16)!
    }
  }

  @Test func fixedRequestCodeAndContext() throws {
    let request = try DeviceLinkRequest(
      device: DevicePublicKey(PublicKey(purpose: .device, algorithm: .ed25519,
        rawRepresentation: Array(0..<32))),
      recipient: EncryptionPublicKey(algorithm: .p256, rawRepresentation: hex(
        "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")),
      label: "Desktop", verifies: [.ed25519, .p256])
    let encoded = hex("a60078184469656d2f6465766963652d6c696e6b2d726571756573740101025834a500684469656d2f6b6579010302020301045820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f035855a500684469656d2f6b6579010302030304045841046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f504674465736b746f7005820102")
    #expect(request.encoding == encoded)
    #expect(try DeviceLinkRequest(encoding: encoded).encoding == encoded)
    #expect(request.digest.bytes == hex("220d928bedac538a97e26b9b52df912ce3068bad5b1d9d3cd39d8ddbdd8bda69"))
    let code = try DeviceLinkCode(requestDigest: request.digest, secret: Array(0..<16))
    #expect(code.encoding == hex("a400754469656d2f6465766963652d6c696e6b2d636f64650101025820220d928bedac538a97e26b9b52df912ce3068bad5b1d9d3cd39d8ddbdd8bda690350000102030405060708090a0b0c0d0e0f"))
    #expect(code.parameter == "pAB1RGllbS9kZXZpY2UtbGluay1jb2RlAQECWCAiDZKL7axTipfia5tS35Es4waLrVsdnTzTnY3b3YvaaQNQAAECAwQFBgcICQoLDA0ODw")
    #expect(try DeviceLinkCode(parameter: code.parameter).matches(encoded))
    #expect(DeviceLinkContext(code: code).encoding == hex("a40078184469656d2f6465766963652d6c696e6b2d636f6e746578740101025820220d928bedac538a97e26b9b52df912ce3068bad5b1d9d3cd39d8ddbdd8bda690350000102030405060708090a0b0c0d0e0f"))
  }
}

# BlahDiem

Blah's device authority and identity contracts build on [Diem](https://github.com/UInt8Co/diem)
CBOR, key, signature, encryption and protected-memory primitives. BlahDiem owns
device rosters, profiles, enrollment and proofs, alongside
home delegation, DC discovery, canonical references and cache namespaces.
Servers and clients share these contracts.
The package has no Telegram transport or server storage dependency.

Signed Blah records use canonical CBOR with fixed numeric tags and fixed field
positions. `BlahDiemTag` assigns record tags; `BlahProfileField` assigns numeric
keys inside a Diem profile. Every decoder validates the exact record shape.

See [Device authority](Documentation.docc/DeviceAuthority.md) for the authority
contract. Run `swift test` to check it. The package is licensed under MIT; see
[LICENSE](LICENSE).

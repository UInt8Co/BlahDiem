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

See [Device authority](Sources/BlahDiem/BlahDiem.docc/DeviceAuthority.md) for the authority
contract. Run `swift test` to check it. The package is licensed under MIT; see
[LICENSE](LICENSE).

## API documentation

Run `npm ci && npm run build` to generate the static DocC site in `dist/blahdiem/`.
The build uses Swift 6.4.0, installing it with Swiftly on Linux when needed. The site is
configured for <https://docs.blahim.com/blahdiem/>; run `npm run preview` to inspect it
locally or `npm run deploy` to publish it manually.

For Cloudflare Workers Builds, connect this repository to a Worker named `blahdiem-docs`.
Use the repository root, `npm run build` as the build command, and `npm run deploy` as the
deploy command. The Wrangler routes publish only `/blahdiem` and `/blahdiem/*` on the
existing `docs.blahim.com` hostname.

# BlahDiem

BlahDiem carries Blah's profiles and proofs on [Diem](https://github.com/UInt8Co/diem)
identities: user, bot, channel, sticker-set, DC and application profiles, the DC challenges that
devices sign, Blah's rules for Diem's QR device linking, and the client cache namespace. Blah
clients and DCs share it. It is Foundation-free and runs on any Diem `CryptoBackend`.

Diem owns the integer keys of its records; Blah's application ID is `com.blahim`. Blah
profile types adopt Diem's profile protocols and sign their kind and fields as a map under
`com.blahim` in the Diem profile, and a proof's `com.blahim` value is the signed
challenge's record. Blah's own records are canonical CBOR maps with unsigned integer field
keys and fixed numeric tags. Types expose their field numbers, including those inside the
`com.blahim` map, as public static `cborKey…` constants. Decoders validate required fields
and accept unknown keys; arrays contain lists only. Every profile domain is a username
candidate.

Name claims use Diem’s profile-hosting client with Blah’s native domain rules.
See [Identities, profiles and proofs](Sources/BlahDiem/BlahDiem.docc/DeviceAuthority.md)
for Blah's wire layout and rules. Requires Swift 6.4 or later. Run `swift test` to check
the contracts; the tests use Diem's `DiemTesting` backend and profile host. The package is
licensed under MIT; see [LICENSE](LICENSE).

## API documentation

Run `npm ci && npm run build` to generate the static DocC site in `dist/blahdiem/`.
The build uses Swift 6.4.0, installing it with Swiftly on Linux when needed. The site is
configured for <https://docs.blahim.com/blahdiem/>; run `npm run preview` to inspect it
locally or `npm run deploy` to publish it manually.

For Cloudflare Workers Builds, connect this repository to a Worker named `blahdiem-docs`.
Use the repository root, `npm run build` as the build command, and `npm run deploy` as the
deploy command. The Wrangler routes publish only `/blahdiem` and `/blahdiem/*` on the
existing `docs.blahim.com` hostname.

## Web clients

[Web/README.md](Web/README.md) describes the BridgeJS-generated WASM library,
worker support, minimized release artifacts and reproducible build/test procedure.
Native consumers do not depend on the web package or its JavaScript build tools.

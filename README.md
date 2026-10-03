# BlahDiem

BlahDiem carries Blah's profiles and proofs on [Diem](https://github.com/UInt8Co/diem)
identities: user, bot, channel, sticker-set and DC profiles, the DC challenges that
devices sign, password-protected HPKE key files, and the client cache namespace. Blah clients and DCs share it. It is
Foundation-free and runs on any Diem `CryptoBackend`.

Blah records are canonical CBOR maps with unsigned integer field keys and fixed numeric
tags. Record types expose their field numbers as public static `cborKey…` constants.
Decoders validate required fields and accept unknown integer keys; arrays contain
lists only. The tuple encoding is not accepted. Every profile domain is a username candidate.

See [Identities, profiles and proofs](Sources/BlahDiem/BlahDiem.docc/DeviceAuthority.md).
Run `swift test` to check the contracts. The package is licensed under MIT; see
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

## Web clients

[Web/README.md](Web/README.md) describes the BridgeJS-generated WASM library,
worker support, minimized release artifacts and reproducible build/test procedure.
Native consumers do not depend on the web package or its JavaScript build tools.

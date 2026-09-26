// Independent WebCrypto verifier for committed Diem v2 wire vectors.
// deno run --allow-read Scripts/verify-device-vectors.ts
function assert(condition: unknown): asserts condition {
  if (!condition) throw new Error("Vector assertion failed");
}
function assertEquals(a: unknown[], b: unknown[]) {
  assert(a.length === b.length && a.every((v, i) => v === b[i]));
}
function assertThrows(body: () => unknown) {
  try { body(); } catch { return; }
  throw new Error("Malformed encoding was accepted");
}

function hex(s: string): Uint8Array {
  assert(s.length % 2 === 0 && /^[0-9a-f]*$/.test(s));
  return Uint8Array.from(s.match(/../g) ?? [], x => parseInt(x, 16));
}
function equal(a: Uint8Array, b: Uint8Array) { return a.length === b.length && a.every((v, i) => v === b[i]); }
async function hash(b: Uint8Array) { return new Uint8Array(await crypto.subtle.digest("SHA-256", new Uint8Array(b))); }

type Value = bigint | string | Uint8Array | Value[] | boolean | null;
function decode(input: Uint8Array): Value {
  assert(input.length <= 262144);
  let p = 0, items = 0;
  function byte() { assert(p < input.length); return input[p++]; }
  function read(depth: number): Value {
    assert(depth <= 16 && ++items <= 8192);
    const first = byte(), major = first >> 5, extra = first & 31;
    if (major === 7) { assert(extra >= 20 && extra <= 22); return extra === 22 ? null : extra === 21; }
    assert(major <= 5 && extra <= 27);
    let n = BigInt(extra);
    if (extra >= 24) {
      n = 0n;
      for (let i = 0; i < 1 << (extra - 24); i++) n = (n << 8n) | BigInt(byte());
      assert(n >= [24n, 256n, 65536n, 4294967296n][extra - 24]);
    }
    if (major === 0) return n;
    if (major === 1) return -1n - n;
    assert(n <= BigInt(input.length - p));
    if (major === 2 || major === 3) {
      const b = input.slice(p, p += Number(n));
      return major === 2 ? b : new TextDecoder("utf-8", { fatal: true }).decode(b);
    }
    const values: Value[] = [];
    let previous: Uint8Array | undefined;
    for (let i = 0; i < Number(n); i++) {
      const start = p;
      values.push(read(depth + 1));
      if (major === 5) {
        const key = input.slice(start, p);
        if (previous) {
          let lex = 0;
          for (let j = 0; j < Math.min(previous.length, key.length); j++) {
            if (previous[j] !== key[j]) { lex = previous[j] - key[j]; break; }
          }
          assert(previous.length < key.length || (previous.length === key.length && lex < 0));
        }
        previous = key;
        values.push(read(depth + 1));
      }
    }
    return values;
  }
  const result = read(0);
  assert(p === input.length);
  return result;
}

function array(v: Value, length: number): Value[] { assert(Array.isArray(v) && v.length === length); return v; }
function bytes(v: Value): Uint8Array { assert(v instanceof Uint8Array); return v; }
async function verify(encodedKey: Uint8Array, body: Uint8Array, signature: Uint8Array) {
  const key = array(decode(encodedKey), 4);
  assertEquals(key.slice(0, 2), ["Diem/key", 2n]);
  const alg = key[2] === 1n ? { name: "Ed25519" } : { name: "ECDSA", namedCurve: "P-256", hash: "SHA-256" };
  assert(key[2] === 1n || key[2] === 2n);
  const imported = await crypto.subtle.importKey("raw", new Uint8Array(bytes(key[3])), alg, false, ["verify"]);
  return crypto.subtle.verify(alg, imported, new Uint8Array(signature), new Uint8Array(body));
}

const fixture = JSON.parse(await Deno.readTextFile(new URL("../Tests/Vectors/device-authority-v2.json", import.meta.url)));
assert(fixture.protocol === "Diem/v2");
for (const v of fixture.vectors) {
  const root = hex(v.identityPublicKey), device = hex(v.devicePublicKey);
  assert(equal(await hash(root), hex(v.identityID)));
  assert(equal(await hash(device), hex(v.deviceID)));
  for (const [prefix, key] of [["roster", root], ["profile", device], ["proof", device]] as const) {
    const body = hex(v[prefix + "Bytes"]), sig = hex(v[prefix + "Signature"]);
    assert(await verify(key, body, sig));
    const tampered = body.slice(); tampered[tampered.length - 1] ^= 1;
    assert(!await verify(key, tampered, sig));
  }
  assert(!await verify(root, hex(v.profileBytes), hex(v.profileSignature)));
  const roster = array(decode(hex(v.rosterBytes)), 8);
  assertEquals(roster.slice(0, 2), ["Diem/devices", 2n]);
  assert(equal(bytes(roster[2]), hex(v.identityID)));
  const profile = array(decode(hex(v.profileBytes)), 10);
  assertEquals(profile.slice(0, 2), ["Diem/profile", 2n]);
  assert(equal(bytes(profile[3]), await hash(hex(v.rosterBytes))));
  assert(equal(bytes(profile[8]), hex(v.deviceID)));
  const proof = array(decode(hex(v.proofBytes)), 7);
  assertEquals(proof.slice(0, 3), ["Diem/device-proof", 2n, "message"]);
  assert(equal(bytes(proof[5]), await hash(hex(v.profileBytes))));
  assert(equal(bytes(proof[6]), new TextEncoder().encode("cross-language")));
  array(decode(hex(v.profile)), 4);
}
for (const malformed of ["a200010002", "1800", "0000", "9fff"]) {
  assertThrows(() => decode(hex(malformed)));
}
console.log(`Verified ${fixture.vectors.length} Diem v2 vectors with WebCrypto.`);

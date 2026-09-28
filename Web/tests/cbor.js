// Independent fixture codec: production wire formats always come from Swift.
export function encode(value) {
  const head = (major, value) => {
    let n = BigInt(value);
    if(n < 24n) return [major * 32 + Number(n)];
    const size = n <= 255n ? 1 : n <= 65535n ? 2 : n <= 4294967295n ? 4 : 8;
    const bytes = new Array(size);
    for(let i = size - 1; i >= 0; i--) { bytes[i] = Number(n & 255n); n >>= 8n; }
    return [major * 32 + ({1: 24, 2: 25, 4: 26, 8: 27})[size], ...bytes];
  };
  if(value === null) return [246];
  if(typeof value === 'boolean') return [value ? 245 : 244];
  if(typeof value === 'number' || typeof value === 'bigint') return head(0, value);
  if(typeof value === 'string') {
    const bytes = [...new TextEncoder().encode(value)];
    return [...head(3, bytes.length), ...bytes];
  }
  if(value instanceof Uint8Array) return [...head(2, value.length), ...value];
  return [...head(4, value.length), ...value.flatMap(encode)];
}

export function decode(input) {
  const bytes = new Uint8Array(input);
  let offset = 0;
  const read = () => {
    const tag = bytes[offset++], major = tag >> 5, extra = tag & 31;
    if(tag === 244 || tag === 245) return tag === 245;
    if(tag === 246) return null;
    let length = BigInt(extra);
    if(extra >= 24) {
      length = 0n;
      for(let i = 0; i < 2 ** (extra - 24); i++) length = (length << 8n) | BigInt(bytes[offset++]);
    }
    if(major === 0) return length <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(length) : length;
    if(major === 4) return Array.from({length: Number(length)}, read);
    const value = bytes.slice(offset, offset += Number(length));
    if(major === 2) return value;
    if(major === 3) return new TextDecoder().decode(value);
    throw new Error('Unexpected fixture CBOR');
  };
  const result = read();
  if(offset !== bytes.length) throw new Error('Trailing fixture CBOR');
  return result;
}

import type {IdentityRequest, IdentityResult, DCSetupRequest, DCSetupResult, DCDiscoveryResult, ChallengeInfo} from './bridge-js';
export type {IdentityRequest, IdentityResult, DeviceInfo, DCSetupRequest, DCSetupResult, DCDiscoveryResult, ChallengeInfo} from './bridge-js';

/** The runtime normalizes omitted optional values and typed byte arrays before BridgeJS. */
type OptionalIdentityField = 'account' | 'device' | 'challenge' | 'query' | 'keyID' | 'sessionID' | 'expiresAt'
  | 'challengeKind' | 'approvedChallenge' | 'domains' | 'profileLifetime' | 'deviceLifetime';
type InputValue<T> = T extends number[] ? number[] | Uint8Array : T;
type IdentityInputFields = {[K in keyof IdentityRequest]: InputValue<IdentityRequest[K]>};
export type IdentityInput = Omit<IdentityInputFields, OptionalIdentityField>
  & Partial<{[K in OptionalIdentityField]: IdentityInputFields[K] | undefined}>;

/** Keys remain with the caller; callbacks belong to this operation only. */
export interface CryptoBackend {
  random(length: number): Uint8Array;
  /** Raw public bytes: Ed25519 (32) for identity, SEC1 P-256 (65) for device.
   * Return an empty identity key for device-only operations. */
  publicKey(role: 'identity' | 'device'): Uint8Array;
  /** Identity: Ed25519. Device: ECDSA with SHA-256, fixed-width 64-byte r‖s. */
  sign(role: 'identity' | 'device', bytes: number[]): Promise<Uint8Array>;
  verify(key: number[], data: number[], signature: number[]): Promise<boolean>;
}
/** Verified public facts. All integers are exact decimal strings; IDs are lowercase hex. */
export interface ProfileInfo {
  id: string;
  kind: 'user' | 'channel' | 'bot' | 'stickerSet' | 'dc';
  generation: string;
  revision: string;
  notBefore: string;
  expiresAt: string;
  /** True when now < notBefore or now >= expiresAt. Signatures still verify. */
  lapsed: boolean;
  domains: string[];
  home: {dc: string; account: string | null; epoch: string} | null;
}
/** One HTTP exchange. The default transport is `hosting.fetchTransport()`. */
export interface HostingHTTPRequest {method: 'GET' | 'HEAD' | 'PUT'; url: string;
  headers: Record<string, string>; body: number[] | null}
export interface HostingHTTPResponse {status: number; headers: Record<string, string>;
  body: Uint8Array | number[]}
export type HostingTransport = (request: HostingHTTPRequest) => Promise<HostingHTTPResponse>;

/** A proof-of-work puzzle: find a nonce (1–64 bytes) so that SHA-256(input ‖ nonce) has at
 * least `requiredBits` leading zero bits. `input` already binds domain, label and identity. */
export interface HostingPuzzle {label: string; input: number[]; requiredBits: number}
export type HostingSolver = (puzzle: HostingPuzzle) => Promise<Uint8Array | number[]>;

/** A string targets a child label; {apex: true} targets the hosting domain itself. */
export type HostingTarget = string | {apex: true};
export interface HostingPolicy {
  domain: string; apex: boolean;
  /** Present only when the host serves child names. */
  names?: HostingNamesPolicy;
}
export interface HostingNamesPolicy {
  labelPattern: string; maxClaimsPerIdentity: number;
  maxUpdatesPerIdentityPerHour: number; claimGraceAfterExpiry: number;
  proofOfWork: {algorithm: 'sha256-leading-zero-bits-v1'; baseBits: number;
    bitsPerShorterCharacter: number; referenceLength: number};
}
export interface HostingPlanName {
  label: string;
  status: 'invalid' | 'taken' | 'held' | 'needsProof';
  /** Set for needsProof. 0 means no proof is needed. */
  requiredBits: number | null;
  /** Set for needsProof with requiredBits > 0. */
  puzzle: HostingPuzzle | null;
}
/** Apex planning checks policy support only; PUT decides ownership. No proof is needed. */
export interface HostingPlanApex {
  apex: true; status: 'available' | 'unsupported'; requiredBits: null; puzzle: null;
}
export interface HostingPublished {identity: string; revision: string; domains: string[]}

export interface HostingProblemError {
  type: 'hostingProblem'; code: string; status: number; detail: string;
  labels: {label: string; reason: string; requiredBits: number | null}[];
  retryAfter: number | null;
}
export interface HostingClientError {
  type: 'invalidLabel' | 'nameTaken' | 'unsolvable' | 'invalidProof' | 'noHostedName'
    | 'hostNotListed' | 'domainMismatch' | 'publishedMismatch' | 'invalidResponse'
    | 'unexpectedStatus' | 'tooLarge' | 'cancelled' | 'unsupportedAlgorithm';
  /** Present for unexpectedStatus. */
  status?: number;
}

/** A platform-held P-256 signing key. Persist the CryptoKey by structured clone, never bytes. */
export interface DeviceKey {privateKey: CryptoKey; publicKey: Uint8Array}
/** The public key uses Diem's purpose-qualified encoding; signer is non-extractable Ed25519. */
export interface SeedIdentity {publicKey: Uint8Array; id: string; signer: CryptoKey}
export type DCSetupInput = Omit<DCSetupRequest, 'data' | 'profile' | 'profileLifetime' | 'deviceLifetime' | 'removeDevices'> & {
  data: Uint8Array | number[];
  profile?: Uint8Array | number[] | null;
  seed: Uint8Array;
  device: DeviceKey;
  profileLifetime?: number;
  deviceLifetime?: number;
  /** IDs to prune after enrolling the fresh setup device. */
  removeDevices?: (Uint8Array | number[])[];
};

export interface DiemClient {
  deviceLink: {
    /** Non-extractable P-256 device + fresh P-256 HPKE recipient; safe in any worker realm. */
    begin(label: string): Promise<{request: Uint8Array; parameter: string; session: DeviceLinkSession}>;
    /** Consumes the session on success or failure. expectedDC is the connected DC's 32-byte identity. */
    open(session: DeviceLinkSession, response: Uint8Array | number[], expectedDC: Uint8Array | number[]): Promise<DeviceLinkOpened>;
    /** Call after certifying and publishing the exact profile. Supplying seed transfers approval authority. */
    respond(input: DeviceLinkApproval): Promise<Uint8Array>;
    /** Checks the QR digest before decoding the public request. Check verifies before certifying. */
    inspect(parameter: string, request: Uint8Array | number[]): Promise<{device: Uint8Array; label: string; verifies: number[]}>;
  };
  hosting: {
    /** fetch with redirect:'error', credentials:'omit', cache:'no-store',
     * referrerPolicy:'no-referrer', a timeout (default 15 s) combined with `signal`, and a
     * streamed 262,144-byte response cap. */
    fetchTransport(options?: {signal?: AbortSignal; timeout?: number}): HostingTransport;
    policy(domain: string, transport?: HostingTransport): Promise<HostingPolicy>;
    /** `identity` is the lowercase hex identity ID (ProfileInfo.id). Ownership of claimed
     * names is a hint from the name's current profile; the host decides at publication. */
    plan(domain: string, labels: string[], identity: string,
      transport?: HostingTransport): Promise<HostingPlanName[]>;
    plan(domain: string, target: {apex: true}, identity: string,
      transport?: HostingTransport): Promise<HostingPlanApex[]>;
    /** GET the child or apex profile bytes; null on 404. Does not verify signatures. */
    profile(domain: string, target: HostingTarget, transport?: HostingTransport): Promise<number[] | null>;
    /** Built-in single-threaded solver (@noble/hashes SHA-256 with a cloned prefix state,
     * 8-byte big-endian counters from `start` stepping by `stride`), yielding to the event
     * loop between batches. Rejects with type 'cancelled' when `signal` aborts.
     * Also usable as a HostingSolver: `puzzle => hosting.solve(puzzle)`. */
    solve(puzzle: HostingPuzzle, options?: {signal?: AbortSignal; start?: number;
      stride?: number; onProgress?: (attempts: number) => void}): Promise<number[]>;
    /** PUT the exact signed bytes. `via` defaults to the first direct child in signed
     * order, then a listed apex. A string selects a child (including a formerly held
     * name for release); {apex: true} selects https://<domain>/.well-known/diem/profile.cbor
     * and requires the profile to list <domain>. Apex never sends proofs or invokes the
     * solver. Child proofs map labels to nonce bytes; a solver answers one proof-required
     * refusal and retries once. Retry an unanswered PUT with the same saved bytes. */
    publish(domain: string, profile: Uint8Array | number[], options?: {via?: HostingTarget;
      proofs?: Record<string, number[]>; solver?: HostingSolver;
      transport?: HostingTransport}): Promise<HostingPublished>;
  };
  seeds: {
    generate(): {words: string[]; entropy: Uint8Array};
    /** ASCII-case-insensitive BIP 39 words; rejects bad words, count or checksum. */
    restore(phrase: string): Uint8Array;
    words(entropy: Uint8Array | number[]): string[];
    /** Optional identityPublicKey is a Diem encoding; rejects a mismatch. */
    identity(entropy: Uint8Array | number[], identityPublicKey?: Uint8Array | number[]): Promise<SeedIdentity>;
  };
  deviceKeys: {generate(): Promise<DeviceKey>};
  /** create/enroll/inspect/renew/account/home/domains/addDevice/removeDevice/prove.
   * enroll derives authority from the identity signer and certifies a fresh device. */
  identityOperation(input: IdentityInput, crypto: CryptoBackend): Promise<IdentityResult>;
  dcSetup(input: DCSetupInput): Promise<DCSetupResult>;
  verifyDCProfile(domain: string, encoding: number[] | Uint8Array, now: number, crypto: Pick<CryptoBackend, 'verify'>): Promise<DCDiscoveryResult>;
  /** Verifies stored public profiles, including lapsed ones, without domain binding.
   * Callers own identity pinning and persistent generation/revision floors. */
  verifyProfile(encoding: number[] | Uint8Array, now: number, crypto: Pick<CryptoBackend, 'verify'>): Promise<ProfileInfo>;
  inspectChallenge(kind: string, encoding: number[] | Uint8Array): ChallengeInfo;
}
declare const deviceLinkSession: unique symbol;
export interface DeviceLinkSession {
  readonly [deviceLinkSession]: true;
  /** Releases the HPKE recipient, signer handle and WASM session; pending operations reject. */
  destroy(): void;
}
export interface DeviceLinkOpened {
  profile: Uint8Array;
  domain: string;
  device: DeviceKey;
  /** The transferred 32-byte root, only when the approving device allowed it. Encrypt at rest. */
  seed?: Uint8Array;
  metadata?: Uint8Array;
}
export interface DeviceLinkApproval {
  code: string;
  request: Uint8Array | number[];
  profile: Uint8Array | number[];
  domain: string;
  seed?: Uint8Array;
  /** At most 16 KiB, only with seed transfer; opaque application bytes. */
  metadata?: Uint8Array | number[];
}
export function createDiem(wasmURL?: string | URL): Promise<DiemClient>;

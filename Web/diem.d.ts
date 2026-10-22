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
  /** Return an empty identity key for device-only operations. */
  publicKey(role: 'identity' | 'device'): Uint8Array;
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

export interface HostingPolicy {
  domain: string; labelPattern: string; maxClaimsPerIdentity: number;
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

export interface DiemClient {
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
    /** Built-in single-threaded solver (@noble/hashes SHA-256 with a cloned prefix state,
     * 8-byte big-endian counters from `start` stepping by `stride`), yielding to the event
     * loop between batches. Rejects with type 'cancelled' when `signal` aborts.
     * Also usable as a HostingSolver: `puzzle => hosting.solve(puzzle)`. */
    solve(puzzle: HostingPuzzle, options?: {signal?: AbortSignal; start?: number;
      stride?: number; onProgress?: (attempts: number) => void}): Promise<number[]>;
    /** One PUT of the exact signed profile bytes to `https://<via>.<domain>/.well-known/
     * diem/profile.cbor` (`via` defaults to the profile's first hosted label), with the
     * `Diem-Hosting-Proof` header built from `proofs` (label → nonce). With `solver`, a
     * single proof-required refusal is answered by solving exactly the listed labels and
     * retrying once; solver nonces are checked natively before they are sent. Sending identical
     * bytes again succeeds, so callers retry an unanswered PUT with the same bytes. */
    publish(domain: string, profile: Uint8Array | number[], options?: {via?: string;
      proofs?: Record<string, number[]>; solver?: HostingSolver;
      transport?: HostingTransport}): Promise<HostingPublished>;
  };
  keyFiles: {
    inspect(file: Uint8Array | number[]): {id: string; salt: number[]};
    create(password: string): Promise<KeyFileSession>;
    unlock(file: Uint8Array | number[], password: string): Promise<{session: KeyFileSession; contents: KeyFileSecret}>;
  };
  paperKeys: {
    /** A new paper device key. Show its phrase once, then certify `device` with `addDevice`. */
    generate(): Promise<PaperKey>;
    /** Rejects unknown words, a wrong word count or a failed checksum with `invalidEncoding`. */
    restore(phrase: string): Promise<PaperKey>;
  };
  generateSigningKey(): Promise<SigningKey>;
  identityOperation(input: IdentityInput, crypto: CryptoBackend): Promise<IdentityResult>;
  dcSetup(input: DCSetupRequest, crypto: CryptoBackend): Promise<DCSetupResult>;
  verifyDCProfile(domain: string, encoding: number[] | Uint8Array, now: number, crypto: Pick<CryptoBackend, 'verify'>): Promise<DCDiscoveryResult>;
  /** Verifies stored public profiles, including lapsed ones, without domain binding.
   * Callers own identity pinning and persistent generation/revision floors. */
  verifyProfile(encoding: number[] | Uint8Array, now: number, crypto: Pick<CryptoBackend, 'verify'>): Promise<ProfileInfo>;
  inspectChallenge(kind: string, encoding: number[] | Uint8Array): ChallengeInfo;
}
export interface SigningKey {privateKey: string; publicKey: string}
/** The canonical lowercase words, single-spaced, the Ed25519 device key they derive and its encoded Diem public key. */
export interface PaperKey {phrase: string; key: SigningKey; device: number[]}
export interface KeyFileSecret {
  domain: string;
  profile: string;
  identity?: SigningKey;
  device?: SigningKey;
  publisher?: string;
  token?: string;
  renewal?: {profileDays: number; deviceDays: number; autoRenew: boolean};
  publicationPending?: boolean;
}
export interface KeyFileSession {
  seal(contents: KeyFileSecret): Promise<Uint8Array>;
  open(file: Uint8Array | number[]): Promise<KeyFileSecret>;
  destroy(): void;
}
export function createDiem(wasmURL?: string | URL): Promise<DiemClient>;

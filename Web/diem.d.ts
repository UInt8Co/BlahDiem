// Blah's runtime: Diem's web client (diem-web.d.ts, from the pinned diem checkout) plus
// Blah's operations. Generic declarations are Diem's; see its Web/README.md.
import type {IdentityRequest, IdentityResult, DCSetupRequest, DCSetupResult, DCDiscoveryResult, ChallengeInfo} from './bridge-js';
import type {CryptoBackend, DeviceKey, DeviceLink, DeviceLinkOpened as BaseDeviceLinkOpened,
  Hosting, Seeds} from './diem-web';
export type {IdentityRequest, IdentityResult, DeviceInfo, DCSetupRequest, DCSetupResult, DCDiscoveryResult, ChallengeInfo} from './bridge-js';
export type {CryptoBackend, DeviceKey, SeedIdentity, DeviceLinkSession, DeviceLinkInspection,
  HostingHTTPRequest, HostingHTTPResponse, HostingTransport, HostingPuzzle, HostingSolver,
  HostingTarget, HostingPolicy, HostingNamesPolicy, HostingPlanName, HostingPublished,
  HostingProblemError, HostingClientError} from './diem-web';

/** The runtime normalizes omitted optional values and typed byte arrays before BridgeJS. */
type OptionalIdentityField = 'account' | 'device' | 'challenge' | 'query' | 'keyID' | 'sessionID' | 'expiresAt'
  | 'challengeKind' | 'approvedChallenge' | 'domains' | 'fields' | 'profileLifetime' | 'deviceLifetime';
type InputValue<T> = T extends number[] ? number[] | Uint8Array : T;
type IdentityInputFields = {[K in keyof IdentityRequest]: InputValue<IdentityRequest[K]>};
export type IdentityInput = Omit<IdentityInputFields, OptionalIdentityField>
  & Partial<{[K in OptionalIdentityField]: IdentityInputFields[K] | undefined}>;

/** Verified public facts. All integers are exact decimal strings; IDs are lowercase hex. */
export interface ProfileInfo {
  id: string;
  kind: 'user' | 'channel' | 'bot' | 'stickerSet' | 'dc' | 'application';
  generation: string;
  revision: string;
  notBefore: string;
  expiresAt: string;
  /** True when now < notBefore or now >= expiresAt. Signatures still verify. */
  lapsed: boolean;
  domains: string[];
  home: {dc: string; account: string | null; epoch: string} | null;
  /** Decoded content; non-null exactly when `kind` is 'application'. */
  application: ApplicationInfo | null;
}
/** An application's decoded profile content. IDs are lowercase hex; versions are exact
 * decimal strings, strictly increasing boundaries. `null` versions enable every version;
 * an empty list enables none. Ranges alternate enabled/disabled, starting enabled. */
export interface ApplicationInfo {
  name: string;
  downloadURL: string | null;
  /** The application's bot identity and its home DC's identity. */
  bot: {id: string; dc: string} | null;
  oauth: {
    publicClient: boolean;
    redirectURIs: string[];
    /** `publicKey` is raw: Ed25519 (32 bytes) or SEC1 P-256 (65 bytes). */
    clientKeys: {keyID: string; algorithm: 'EdDSA' | 'ES256'; publicKey: number[]}[];
  } | null;
  push: {
    credentialsURL: string;
    apns: {topic: string; productionURL: string; sandboxURL: string} | null;
    /** `vapidPublicKey` is a 65-byte SEC1 P-256 key. */
    webPush: {proxyURL: string; vapidPublicKey: number[]} | null;
  } | null;
  versions: string[] | null;
}
/** The public MTProto `api_id` (a safe integer at least 0x40000000) and 32-hex `api_hash`. */
export interface ApplicationWirePair {apiID: number; apiHash: string}

export type DCSetupInput = Omit<DCSetupRequest, 'data' | 'profile' | 'profileLifetime' | 'deviceLifetime' | 'removeDevices'> & {
  /** Canonical CBOR of the DC's profile fields: `{9: [domains], "com.blahim": {0: 5,
   * 2: endpoints, 3: BIDCOM endpoints, 4: transport key, 5: namespace generation}}`. */
  data: Uint8Array | number[];
  profile?: Uint8Array | number[] | null;
  seed: Uint8Array;
  device: DeviceKey;
  profileLifetime?: number;
  deviceLifetime?: number;
  /** IDs to prune after enrolling the fresh setup device. */
  removeDevices?: (Uint8Array | number[])[];
};

/** A Blah device link's joining side: a user profile homed at the expected DC. */
export interface DeviceLinkOpened extends BaseDeviceLinkOpened {
  /** Blah's opaque metadata, present only with a transferred seed. */
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

export interface DiemClient {
  seeds: Seeds;
  deviceKeys: {generate(): Promise<DeviceKey>};
  hosting: Hosting;
  /** `open(session, response, expectedDC)`: expectedDC is the connected DC's 32-byte identity. */
  deviceLink: DeviceLink<[response: Uint8Array | number[], expectedDC: Uint8Array | number[]],
    DeviceLinkOpened, DeviceLinkApproval>;
  /** create/enroll/inspect/renew/account/home/domains/addDevice/removeDevice/prove.
   * enroll derives authority from the identity signer and certifies a fresh device.
   * create publishes the canonical `ProfileFields` encoding in `fields` when given (same
   * shape as `dcSetup`'s `data`), instead of a new epoch-1 home at `dc`. */
  identityOperation(input: IdentityInput, crypto: CryptoBackend): Promise<IdentityResult>;
  dcSetup(input: DCSetupInput): Promise<DCSetupResult>;
  verifyDCProfile(domain: string, encoding: number[] | Uint8Array, now: number, crypto: Pick<CryptoBackend, 'verify'>): Promise<DCDiscoveryResult>;
  /** Verifies stored public profiles, including lapsed ones, without domain binding.
   * Callers own identity pinning and persistent generation/revision floors. */
  verifyProfile(encoding: number[] | Uint8Array, now: number, crypto: Pick<CryptoBackend, 'verify'>): Promise<ProfileInfo>;
  /** Derives the wire pair from a verified `application` ProfileInfo, or from an application
   * identity ID (lowercase hex, e.g. one already pinned). Other kinds and malformed IDs throw
   * TypeError. A bare ID is not checked to be an application; verify its profile first. */
  applicationWirePair(source: ProfileInfo | string): ApplicationWirePair;
  inspectChallenge(kind: string, encoding: number[] | Uint8Array): ChallengeInfo;
}
export function createDiem(wasmURL?: string | URL): Promise<DiemClient>;

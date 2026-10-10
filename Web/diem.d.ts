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
export interface DiemClient {
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

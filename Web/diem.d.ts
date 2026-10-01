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
  publicKey(role: 'identity' | 'device'): Uint8Array;
  sign(role: 'identity' | 'device', bytes: number[]): Promise<Uint8Array>;
  verify(key: number[], data: number[], signature: number[]): Promise<boolean>;
}
export interface DiemClient {
  identityOperation(input: IdentityInput, crypto: CryptoBackend): Promise<IdentityResult>;
  dcSetup(input: DCSetupRequest, crypto: CryptoBackend): Promise<DCSetupResult>;
  verifyDCProfile(domain: string, encoding: number[] | Uint8Array, now: number, crypto: Pick<CryptoBackend, 'verify'>): Promise<DCDiscoveryResult>;
  inspectChallenge(kind: string, encoding: number[] | Uint8Array): ChallengeInfo;
}
export function createDiem(wasmURL?: string | URL): Promise<DiemClient>;

import type {IdentityRequest, IdentityResult, DCSetupRequest, DCSetupResult, DCDiscoveryResult, ChallengeInfo} from './bridge-js';
export type {IdentityRequest, IdentityResult, DeviceInfo, DCSetupRequest, DCSetupResult, DCDiscoveryResult, ChallengeInfo} from './bridge-js';

/** Keys remain with the caller; callbacks belong to this operation only. */
export interface CryptoBackend {
  random(length: number): Uint8Array;
  publicKey(role: 'identity' | 'device'): Uint8Array;
  sign(role: 'identity' | 'device', bytes: number[]): Promise<Uint8Array>;
  verify(key: number[], data: number[], signature: number[]): Promise<boolean>;
}
export interface DiemClient {
  identityOperation(input: IdentityRequest, crypto: CryptoBackend): Promise<IdentityResult>;
  dcSetup(input: DCSetupRequest, crypto: CryptoBackend): Promise<DCSetupResult>;
  verifyDCProfile(domain: string, encoding: number[] | Uint8Array, now: number, crypto: Pick<CryptoBackend, 'verify'>): Promise<DCDiscoveryResult>;
  inspectChallenge(kind: string, encoding: number[] | Uint8Array): ChallengeInfo;
}
export function createDiem(wasmURL?: string | URL): Promise<DiemClient>;

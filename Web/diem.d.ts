import type {IdentityRequest, IdentityResult, DCSetupRequest, DCSetupResult, ChallengeInfo} from './bridge-js';
export type {IdentityRequest, IdentityResult, DeviceInfo, DCSetupRequest, DCSetupResult, ChallengeInfo} from './bridge-js';

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
  inspectChallenge(kind: string, encoding: number[] | Uint8Array): ChallengeInfo;
}
export function createDiem(wasmURL?: string | URL): Promise<DiemClient>;

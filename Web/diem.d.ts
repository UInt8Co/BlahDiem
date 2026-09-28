import type {IdentityRequest, IdentityResult} from './bridge-js';
export type {IdentityRequest, IdentityResult, DeviceInfo} from './bridge-js';

/** Keys remain with the caller; callbacks belong to this operation only. */
export interface CryptoBackend {
  random(length: number): Uint8Array;
  publicKey(role: 'identity' | 'device'): Uint8Array;
  sign(role: 'identity' | 'device', bytes: number[]): Promise<Uint8Array>;
  verify(key: number[], data: number[], signature: number[]): Promise<boolean>;
}
export interface DiemClient {
  identityOperation(input: IdentityRequest, crypto: CryptoBackend): Promise<IdentityResult>;
}
export function createDiem(wasmURL?: string | URL): Promise<DiemClient>;

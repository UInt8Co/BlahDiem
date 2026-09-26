public enum DeviceIdentityError: Error, Sendable, Equatable {
  case invalidSignature, identityMismatch, roleConfusion, invalidValidity, expired
  case deviceNotListed, invalidRevision, staleVersion, versionConflict, compareAndSwapFailed
  case controllerRequired, pairingNotConfirmed, invalidEnrollment
}

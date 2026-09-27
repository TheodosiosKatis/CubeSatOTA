# ============================================================
# OTATypes.fpp  —  CubeSatOTA shared type definitions
# ============================================================

module CubeSatOTA {

  @ States of the OTA finite state machine owned by OTAManager
  enum OTAState : U8 {
    IDLE                = 0 @< Awaiting OTA_START command from ground
    RECEIVING           = 1 @< Accepting incoming firmware chunks
    VERIFYING_INTEGRITY = 2 @< SHA-256 integrity check in progress
    VERIFYING_AUTH      = 3 @< Ed25519 signature verification in progress
    WRITING             = 4 @< Writing verified image to Bank B
    COMMIT_PENDING      = 5 @< Boot flag set to Bank B; reboot scheduled
    VALIDATING          = 6 @< Post-reboot health validation in progress
    ACTIVE              = 7 @< Bank B confirmed stable; update complete
    ROLLBACK            = 8 @< Health check failed; reverting to Bank A
    ERROR               = 9 @< Unrecoverable error; next transition is IDLE
  }

  @ Generic binary result for verification and write operations
  enum OpResult : U8 {
    OK   = 0 @< Operation succeeded
    FAIL = 1 @< Operation failed
  }

  @ Firmware storage bank selector
  enum Bank : U8 {
    BANK_A = 0 @< Active golden bank; never overwritten during an update
    BANK_B = 1 @< Staging bank; receives all incoming updates
  }

  @ Error codes reported on entry to ERROR or ROLLBACK state
  enum OTAError : U8 {
    NONE              = 0 @< No error
    INTEGRITY_FAIL    = 1 @< SHA-256 hash mismatch
    AUTH_FAIL         = 2 @< Ed25519 signature invalid
    WRITE_FAIL        = 3 @< Storage write or read-back verification failed
    SESSION_TIMEOUT   = 4 @< Uplink session timed out before completion
    VERSION_REJECTED  = 5 @< Firmware version not monotonically increasing
    PLATFORM_MISMATCH = 6 @< Target platform ID does not match this OBC
  }

  @ 32-byte SHA-256 digest
  array Sha256Hash = [32] U8

  @ 64-byte Ed25519 digital signature
  array Ed25519Signature = [64] U8

  @ 32-byte Ed25519 public key (provisioned at manufacturing time)
  array Ed25519PublicKey = [32] U8

  @ Chunk reception statistics — carried by ChunksDonePort
  struct ChunksDoneInfo { totalBytes: U32, chunkCount: U16 }

  @ Cryptographic verification outcome — carried by VerifyResultPort
  struct VerifyResultInfo { opResult: U8, durationMs: U32 }

  @ Bank B write outcome — carried by WriteResultPort
  struct WriteResultInfo { opResult: U8, bytesWritten: U32 }

  @ Health-check cycle outcome — carried by HealthResultPort
  struct HealthResultInfo { healthy: bool, cycleNum: U8 }

  @ FSM state snapshot — carried by StateReportPort
  struct StateReportInfo { otaState: U8, otaError: U8 }

  @ Signals that all firmware chunks have been received and reassembled
  port ChunksDonePort(info: CubeSatOTA.ChunksDoneInfo)

  @ Carries the result of a cryptographic verification operation
  port VerifyResultPort(info: CubeSatOTA.VerifyResultInfo)

  @ Carries the result of a Bank B flash write operation
  port WriteResultPort(info: CubeSatOTA.WriteResultInfo)

  @ Carries the outcome of a post-reboot health-check cycle
  port HealthResultPort(info: CubeSatOTA.HealthResultInfo)

  @ Commands BootManager to select the active boot bank (0=A 1=B)
  port BootCommandPort(bank: U8)

  @ Reports FSM state transitions to TelemetryReporter
  port StateReportPort(info: CubeSatOTA.StateReportInfo)

}

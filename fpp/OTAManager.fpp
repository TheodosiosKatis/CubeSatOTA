# ============================================================
# OTAManager.fpp  —  Central OTA orchestrator component
# Owns the 10-state FSM. Coordinates IntegrityVerifier,
# AuthVerifier, StorageManager, BootManager, HealthMonitor,
# and TelemetryReporter via typed output ports.
# ============================================================

module CubeSatOTA {

  @ Central orchestrator of the OTA update pipeline.
  @ Owns the persistent 10-state FSM and drives all worker
  @ components in sequence. State is written to NVM so the
  @ FSM survives unplanned reboots mid-update.
  active component OTAManager {

    # ----------------------------------------------------------
    # Async input ports  (post messages to component queue)
    # ----------------------------------------------------------

    @ All firmware chunks received; image is ready for verification
    async input port chunksReady: CubeSatOTA.ChunksDonePort

    @ SHA-256 integrity check result from IntegrityVerifier
    async input port integrityResult: CubeSatOTA.VerifyResultPort

    @ Ed25519 signature verification result from AuthVerifier
    async input port authResult: CubeSatOTA.VerifyResultPort

    @ Bank B write result from StorageManager
    async input port writeResult: CubeSatOTA.WriteResultPort

    @ Post-reboot health check result from HealthMonitor
    async input port healthResult: CubeSatOTA.HealthResultPort

    # ----------------------------------------------------------
    # Output ports  (synchronous calls into passive workers)
    # ----------------------------------------------------------

    @ Trigger IntegrityVerifier to compute SHA-256 over staged image
    output port triggerIntegrity: Fw.Com

    @ Trigger AuthVerifier to verify Ed25519 signature
    output port triggerAuth: Fw.Com

    @ Trigger StorageManager to write image to Bank B
    output port triggerWrite: Fw.Com

    @ Set the active boot bank via BootManager
    output port bootCommand: CubeSatOTA.BootCommandPort

    @ Report FSM state transitions to TelemetryReporter
    output port stateReport: CubeSatOTA.StateReportPort

    # ----------------------------------------------------------
    # F' infrastructure ports
    # ----------------------------------------------------------

    @ Command receive port
    command recv port CmdDisp

    @ Command registration port
    command reg port CmdReg

    @ Command response port
    command resp port CmdStatus

    @ Event emission port
    event port Log

    @ Human-readable event text port
    text event port LogText

    @ Wallclock time port
    time get port Time

    @ Telemetry channel emission port
    telemetry port Tlm

    # ----------------------------------------------------------
    # Commands  (received from ground station via uplink)
    # ----------------------------------------------------------

    @ Begin an OTA update session.
    @ The session token is a per-session random value used to
    @ detect replay of old packets into a new session.
    @ The expected firmware version must be strictly greater
    @ than the currently running version (anti-downgrade).
    async command OTA_START(
      sessionToken:    U32 @< Per-session random anti-replay token
      expectedVersion: U32 @< Must exceed current firmware version
      chunkCount:      U16 @< Total CCSDS chunks to expect
      platformId:      U32 @< Must match the OBC platform identifier
    ) opcode 0x00

    @ Abort the current OTA session and return to IDLE.
    @ Any partially received image data is discarded and
    @ storage buffers are cleared.
    async command OTA_ABORT \
      opcode 0x01

    @ Explicitly commit a confirmed update.
    @ Normally the FSM transitions VALIDATING→ACTIVE automatically;
    @ this command is provided for ground override.
    async command OTA_COMMIT \
      opcode 0x02

    # ----------------------------------------------------------
    # Events
    # ----------------------------------------------------------

    @ Emitted when a valid OTA_START moves the FSM to RECEIVING
    event OTA_SESSION_STARTED(
      sessionToken:    U32 @< Session token value
      expectedVersion: U32 @< Target firmware version
      chunkCount:      U16 @< Number of chunks expected
    ) severity activity high \
      id 0x00 \
      format "OTA session started: token=0x{x} ver={} chunks={}"

    @ Emitted on every FSM state transition
    event OTA_STATE_TRANSITION(
      fromState: CubeSatOTA.OTAState @< State before transition
      toState:   CubeSatOTA.OTAState @< State after transition
    ) severity activity high \
      id 0x01 \
      format "OTA FSM: {} -> {}"

    @ Emitted when Bank B is confirmed stable and update is complete
    event OTA_UPDATE_CONFIRMED(
      newVersion: U32 @< Newly active firmware version
    ) severity activity high \
      id 0x02 \
      format "OTA update confirmed. Active firmware version: {}"

    @ Emitted when the FSM initiates automatic rollback to Bank A
    event OTA_ROLLBACK_INITIATED(
      reason: CubeSatOTA.OTAError @< Reason for rollback
    ) severity warning high \
      id 0x03 \
      format "OTA rollback initiated. Reason: {}"

    @ Emitted when the FSM enters ERROR state
    event OTA_ERROR_DETECTED(
      error: CubeSatOTA.OTAError @< Error code
      atState: CubeSatOTA.OTAState @< State in which error occurred
    ) severity warning high \
      id 0x04 \
      format "OTA error in state {}: {}"

    @ Emitted when OTA_ABORT is processed
    event OTA_ABORTED \
      severity activity high \
      id 0x05 \
      format "OTA session aborted by ground command"

    # ----------------------------------------------------------
    # Telemetry channels
    # ----------------------------------------------------------

    @ Current FSM state; updated on every transition
    telemetry OTA_CURRENT_STATE: CubeSatOTA.OTAState \
      id 0x00 \
      update on change

    @ Last error code; NONE (0) when no error is active
    telemetry OTA_LAST_ERROR: CubeSatOTA.OTAError \
      id 0x01 \
      update on change

    @ Firmware version currently executing on the OBC
    telemetry FIRMWARE_VERSION_ACTIVE: U32 \
      id 0x02 \
      update on change

    @ Cumulative count of successfully completed OTA updates
    telemetry OTA_UPDATE_COUNT: U32 \
      id 0x03 \
      update on change

  }

}

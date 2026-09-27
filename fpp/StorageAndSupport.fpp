# ============================================================
# StorageManager.fpp
# Passive component; manages dual-bank (A/B) NVM storage.
# Writes the verified firmware image to Bank B with block-level
# CRC-32 checking. Performs a post-write read-back to detect
# flash write failures before the update is committed.
# ============================================================

module CubeSatOTA {

  @ Passive component managing dual-bank NVM firmware storage.
  @ Bank A is the active golden image; it is never overwritten
  @ during a normal update cycle. All incoming updates target
  @ Bank B. After a successful write, a post-write SHA-256
  @ read-back is performed before signalling OTAManager.
  passive component StorageManager {

    @ Trigger from OTAManager to begin writing image to Bank B
    sync input port triggerWrite: Fw.Com

    @ Write result returned to OTAManager on completion
    output port writeResult: CubeSatOTA.WriteResultPort

    event port Log
    text event port LogText
    time get port Time
    telemetry port Tlm

    @ Emitted when the Bank B write operation begins
    event WRITE_STARTED(
      bank:      CubeSatOTA.Bank @< Target bank (always BANK_B in normal flow)
      imageSize: U32              @< Total bytes to write
    ) severity activity high \
      id 0x40 \
      format "Writing {} bytes to Bank {}"

    @ Emitted after each 512-byte block is written and read back
    event BLOCK_WRITE_OK(
      blockIndex:  U16 @< Zero-based block index
      totalBlocks: U16 @< Total blocks in the image
    ) severity diagnostic \
      id 0x41 \
      format "Block {}/{} written and verified"

    @ Emitted if a block write or read-back CRC fails
    event BLOCK_WRITE_FAIL(
      blockIndex: U16 @< Index of the failing block
    ) severity warning high \
      id 0x42 \
      format "Block {} write/readback failed"

    @ Emitted when the entire image has been written and
    @ the post-write SHA-256 integrity check has passed
    event WRITE_COMPLETE(
      bytesWritten: U32 @< Total bytes successfully written
    ) severity activity high \
      id 0x43 \
      format "Bank B write complete: {} bytes verified"

    @ Number of blocks written in the current session
    telemetry BLOCKS_WRITTEN: U16 id 0x40 update always

    @ Number of block write failures in the current session
    telemetry WRITE_ERRORS: U8 id 0x41 update on change

    @ Available space in Bank B (bytes)
    telemetry BANK_B_FREE_BYTES: U32 id 0x42 update on change

  }

}


# ============================================================
# BootManager.fpp
# Passive component; owns the two persistent boot-management
# variables: boot_target (selects Bank A or Bank B on the next
# reboot) and boot_try_count (counts consecutive Bank B boot
# attempts). Autonomously reverts to Bank A when boot_try_count
# reaches the configurable threshold T (default 3).
# ============================================================

module CubeSatOTA {

  @ Passive component managing the dual-bank boot selection
  @ and automatic rollback counter.
  @ Both variables are stored in protected NVM and restored
  @ on every boot. The automatic rollback mechanism ensures
  @ the satellite can always return to a known-good image
  @ without ground intervention.
  passive component BootManager {

    @ Command from OTAManager to change the active boot bank
    sync input port bootCommand: CubeSatOTA.BootCommandPort

    event port Log
    text event port LogText
    time get port Time
    telemetry port Tlm

    @ Emitted when the boot target is changed
    event BOOT_TARGET_SET(
      bank: CubeSatOTA.Bank @< New boot target bank
    ) severity activity high \
      id 0x50 \
      format "Boot target set to Bank {}"

    @ Emitted on each boot attempt from Bank B
    event BOOT_ATTEMPT(
      tryCount:  U8 @< Current value of boot_try_count
      threshold: U8 @< Rollback threshold T
    ) severity activity high \
      id 0x51 \
      format "Bank B boot attempt {}/{}"

    @ Emitted when boot_try_count reaches the rollback threshold
    event AUTO_ROLLBACK_TRIGGERED(
      tryCount: U8 @< Count at which rollback was triggered
    ) severity warning high \
      id 0x52 \
      format "Boot try-count {} reached threshold — auto-rollback to Bank A"

    @ Emitted when Bank B is confirmed stable and try-count is reset
    event BOOT_CONFIRMED \
      severity activity high \
      id 0x53 \
      format "Bank B confirmed stable; boot_try_count reset to 0"

    @ Currently selected boot bank (0=BANK_A, 1=BANK_B)
    telemetry BOOT_TARGET: CubeSatOTA.Bank id 0x50 update on change

    @ Current value of boot_try_count
    telemetry BOOT_TRY_COUNT: U8 id 0x51 update on change

  }

}


# ============================================================
# HealthMonitor.fpp
# Active component; evaluates post-reboot system health after
# the OBC boots into Bank B. Checks critical subsystems for K
# consecutive cycles. Reports to OTAManager after each cycle.
# ============================================================

module CubeSatOTA {

  @ Active component performing post-update health validation.
  @ Criteria evaluated each cycle:
  @   (1) All critical F' components initialised successfully.
  @   (2) Memory usage within expected bounds.
  @   (3) Communications subsystem responsive.
  @   (4) Telemetry flowing at the expected rate.
  @ K consecutive passing cycles (default K=2) are required
  @ before VALIDATING→ACTIVE is declared.
  active component HealthMonitor {

    @ Scheduler input driving the health-check evaluation cycle
    async input port schedIn: Svc.Sched

    @ Health-check result reported to OTAManager after each cycle
    output port healthResult: CubeSatOTA.HealthResultPort

    command recv port CmdDisp
    command reg port CmdReg
    command resp port CmdStatus
    event port Log
    text event port LogText
    time get port Time
    telemetry port Tlm

    @ Enable or disable health monitoring (called by OTAManager)
    async command HEALTH_ENABLE(
      enable:         bool @< True to begin monitoring, false to stop
      requiredCycles: U8   @< Consecutive passing cycles required for ACTIVE
    ) opcode 0x60

    @ Emitted at the start of each health-check evaluation cycle
    event HEALTH_CHECK_CYCLE(
      cycle:    U8 @< 1-based current cycle index
      required: U8 @< Total cycles required for confirmation
    ) severity activity high \
      id 0x60 \
      format "Health check cycle {}/{}"

    @ Emitted when all health criteria are met in a cycle
    event HEALTH_CYCLE_PASS(
      cycle: U8 @< Cycle index that passed
    ) severity activity high \
      id 0x61 \
      format "Health check cycle {} PASSED"

    @ Emitted when a health criterion fails
    event HEALTH_CRITERION_FAIL(
      criterion: string size 40 @< Name of the failing criterion
    ) severity warning high \
      id 0x62 \
      format "Health criterion failed: {}"

    @ Number of consecutive passing health-check cycles
    telemetry HEALTH_PASS_COUNT: U8 id 0x60 update always

    @ Overall health status this cycle (true = all criteria met)
    telemetry HEALTH_STATUS: bool id 0x61 update on change

  }

}


# ============================================================
# TelemetryReporter.fpp
# Passive component; aggregates OTA state information and
# exposes it as telemetry channels. Receives a state snapshot
# from OTAManager on every FSM transition.
# ============================================================

module CubeSatOTA {

  @ Passive component centralising OTA telemetry.
  @ Called by OTAManager on every state transition.
  @ Maintains a running count of transitions since boot.
  passive component TelemetryReporter {

    @ State snapshot input from OTAManager
    sync input port stateReport: CubeSatOTA.StateReportPort

    event port Log
    text event port LogText
    time get port Time
    telemetry port Tlm

    @ Emitted when a state transition is recorded
    event STATE_CHANGE_RECORDED(
      newState: CubeSatOTA.OTAState @< New FSM state
      error: CubeSatOTA.OTAError @< Current error code
    ) severity activity high \
      id 0x70 \
      format "OTA state recorded: state={} error={}"

    @ Current FSM state snapshot
    telemetry TLM_OTA_STATE: CubeSatOTA.OTAState id 0x70 update on change

    @ Current error code snapshot
    telemetry TLM_OTA_ERROR: CubeSatOTA.OTAError id 0x71 update on change

    @ Running count of FSM transitions recorded since boot
    telemetry TLM_TRANSITION_COUNT: U32 id 0x72 update always

  }

}

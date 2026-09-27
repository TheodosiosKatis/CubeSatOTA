# ============================================================
# OTATopology.fpp  —  System topology for CubeSatOTA
# Declares component instances, assigns base IDs, configures
# queue depths, stack sizes and priorities, then wires all
# typed port connections.
# ============================================================

module CubeSatOTA {

  # ----------------------------------------------------------
  # Component instances
  # ----------------------------------------------------------

  @ Central OTA orchestrator (active; priority 90)
  instance otaManager: CubeSatOTA.OTAManager base id 0x0100 \
    queue size 10 \
    stack size 4096 \
    priority 90

  @ Uplink chunk receiver (active; priority 80)
  instance uplinkReceiver: CubeSatOTA.UplinkReceiver base id 0x0200 \
    queue size 20 \
    stack size 4096 \
    priority 80

  @ SHA-256 integrity verifier (passive)
  instance integrityVerifier: CubeSatOTA.IntegrityVerifier base id 0x0300

  @ Ed25519 signature verifier (passive)
  instance authVerifier: CubeSatOTA.AuthVerifier base id 0x0400

  @ Dual-bank NVM storage manager (passive)
  instance storageManager: CubeSatOTA.StorageManager base id 0x0500

  @ Boot bank selector and rollback counter (passive)
  instance bootManager: CubeSatOTA.BootManager base id 0x0600

  @ Post-reboot health monitor (active; priority 70)
  instance healthMonitor: CubeSatOTA.HealthMonitor base id 0x0700 \
    queue size 5 \
    stack size 4096 \
    priority 70

  @ Telemetry aggregator (passive)
  instance telemetryReporter: CubeSatOTA.TelemetryReporter base id 0x0800

  # ----------------------------------------------------------
  # OTA pipeline port connections
  # ----------------------------------------------------------

  topology OTAPipeline {

    # UplinkReceiver → OTAManager: all chunks reassembled
    connections ChunksReady {
      uplinkReceiver.chunksDone -> otaManager.chunksReady
    }

    # OTAManager → IntegrityVerifier: trigger SHA-256 check
    connections TriggerIntegrity {
      otaManager.triggerIntegrity -> integrityVerifier.triggerVerify
    }

    # IntegrityVerifier → OTAManager: SHA-256 result
    connections IntegrityResult {
      integrityVerifier.result -> otaManager.integrityResult
    }

    # OTAManager → AuthVerifier: trigger Ed25519 verification
    connections TriggerAuth {
      otaManager.triggerAuth -> authVerifier.triggerVerify
    }

    # AuthVerifier → OTAManager: Ed25519 result
    connections AuthResult {
      authVerifier.result -> otaManager.authResult
    }

    # OTAManager → StorageManager: trigger Bank B write
    connections TriggerWrite {
      otaManager.triggerWrite -> storageManager.triggerWrite
    }

    # StorageManager → OTAManager: write result
    connections WriteResult {
      storageManager.writeResult -> otaManager.writeResult
    }

    # OTAManager → BootManager: set boot bank
    connections BootCommand {
      otaManager.bootCommand -> bootManager.bootCommand
    }

    # HealthMonitor → OTAManager: post-reboot health check result
    connections HealthResult {
      healthMonitor.healthResult -> otaManager.healthResult
    }

    # OTAManager → TelemetryReporter: state transition notifications
    connections StateReport {
      otaManager.stateReport -> telemetryReporter.stateReport
    }

  }

}

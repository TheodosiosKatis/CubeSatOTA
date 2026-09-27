#pragma once
// ============================================================
// OTAManager.hpp  —  Central OTA state machine orchestrator
//
// Models the OTAManager F' active component. Owns the 10-state
// FSM and drives all worker components in sequence via method
// calls that simulate typed port invocations.
// ============================================================

#include "OTAComponents.hpp"

namespace CubeSatOTA {

// Package metadata extracted from OTAUHeader for passing
// through the pipeline without copying the full image.
struct PackageMetadata {
    uint32_t firmwareVersion;
    uint32_t platformId;
    uint8_t  sha256Hash[SHA256_SIZE];
    uint8_t  ed25519Sig[ED25519_SIG_SIZE];
};

class OTAManager {
public:
    // ----------------------------------------------------------
    // Wired worker components  (set before calling runUpdate)
    // ----------------------------------------------------------
    TelemetryReporter* telemetryReporter = nullptr;
    IntegrityVerifier* integrityVerifier = nullptr;
    AuthVerifier*      authVerifier      = nullptr;
    StorageManager*    storageManager    = nullptr;
    BootManager*       bootManager       = nullptr;
    HealthMonitor*     healthMonitor     = nullptr;
    UplinkReceiver*    uplinkReceiver    = nullptr;

    // ----------------------------------------------------------
    // Persistent state (written to NVM in a real system)
    // ----------------------------------------------------------
    OTAState currentState          = OTAState::IDLE;
    OTAError lastError             = OTAError::NONE;
    uint32_t activeFirmwareVersion = 5;   // current running version
    uint32_t updateCount           = 0;

    // ----------------------------------------------------------
    // Run a complete OTA update from IDLE to ACTIVE (or error/
    // rollback). Returns the final state.
    // ----------------------------------------------------------
    OTAState runUpdate(const std::vector<uint8_t>& packageBytes,
                       uint32_t sessionToken,
                       bool injectCorruption     = false) {

        transition(OTAState::IDLE); // ensure clean start

        // ─── Parse OTAU header ───────────────────────────────
        if (packageBytes.size() < sizeof(OTAUHeader)) {
            return enterError(OTAError::INTEGRITY_FAIL);
        }
        OTAUHeader hdr;
        std::memcpy(&hdr, packageBytes.data(), sizeof(hdr));

        if (hdr.magic != OTAU_MAGIC) {
            LOG("[OTA]", "Bad magic 0x%08X", hdr.magic);
            return enterError(OTAError::INTEGRITY_FAIL);
        }
        if (hdr.platformId != THIS_PLATFORM_ID) {
            LOG("[OTA]", "Platform mismatch: 0x%08X ≠ 0x%08X",
                hdr.platformId, THIS_PLATFORM_ID);
            return enterError(OTAError::PLATFORM_MISMATCH);
        }
        if (hdr.firmwareVersion <= activeFirmwareVersion) {
            LOG("[OTA]", "Version rejected: %u ≤ %u (anti-downgrade)",
                hdr.firmwareVersion, activeFirmwareVersion);
            return enterError(OTAError::VERSION_REJECTED);
        }

        // Extract firmware image payload
        const uint8_t* imgPtr = packageBytes.data() + sizeof(OTAUHeader);
        size_t imgLen = packageBytes.size() - sizeof(OTAUHeader);
        std::vector<uint8_t> firmwareImage(imgPtr, imgPtr + imgLen);

        PackageMetadata meta;
        meta.firmwareVersion = hdr.firmwareVersion;
        meta.platformId      = hdr.platformId;
        std::memcpy(meta.sha256Hash,  hdr.sha256Hash,  SHA256_SIZE);
        std::memcpy(meta.ed25519Sig,  hdr.ed25519Sig,  ED25519_SIG_SIZE);

        LOG("[OTA]", "OTAU header: version=%u  size=%u B  chunks=%u",
            hdr.firmwareVersion, hdr.imageSize, hdr.chunkCount);

        // ─── IDLE → RECEIVING ────────────────────────────────
        transition(OTAState::RECEIVING);
        LOG("[OTA]", "Session token 0x%08X  chunks expected: %u",
            sessionToken, hdr.chunkCount);

        // Simulate uplink via UplinkReceiver
        std::vector<uint8_t> reassembled;
        ChunksDoneInfo chunksDone = uplinkReceiver->transmit(
            firmwareImage, sessionToken, reassembled,
            injectCorruption, 0); // corrupt chunk 0 if injecting

        if (chunksDone.totalBytes == 0) {
            // CRC failure during reception
            LOG("[OTA]", "Uplink reception failed (CRC error)");
            return enterError(OTAError::INTEGRITY_FAIL);
        }

        LOG("[OTA]", "Reception complete: %u bytes in %u chunks",
            chunksDone.totalBytes, chunksDone.chunkCount);

        // ─── RECEIVING → VERIFYING_INTEGRITY ─────────────────
        transition(OTAState::VERIFYING_INTEGRITY);
        integrityVerifier->setExpectedHash(meta.sha256Hash);
        VerifyResultInfo intResult = integrityVerifier->onTriggerVerify(reassembled);

        if (intResult.opResult != OpResult::OK) {
            return enterError(OTAError::INTEGRITY_FAIL);
        }

        // ─── VERIFYING_INTEGRITY → VERIFYING_AUTH ────────────
        transition(OTAState::VERIFYING_AUTH);
        VerifyResultInfo authResult = authVerifier->onTriggerVerify(
            meta.ed25519Sig, meta.sha256Hash,
            meta.firmwareVersion, meta.platformId);

        if (authResult.opResult != OpResult::OK) {
            return enterError(OTAError::AUTH_FAIL);
        }

        // ─── VERIFYING_AUTH → WRITING ─────────────────────────
        transition(OTAState::WRITING);
        WriteResultInfo writeResult = storageManager->onTriggerWrite(reassembled);

        if (writeResult.opResult != OpResult::OK) {
            return enterError(OTAError::WRITE_FAIL);
        }

        // ─── WRITING → COMMIT_PENDING ─────────────────────────
        transition(OTAState::COMMIT_PENDING);
        bootManager->onBootCommand(static_cast<uint8_t>(Bank::BANK_B));
        LOG("[OTA]", "Reboot scheduled. Handing off to bootloader...");

        // ─── Simulated reboot ─────────────────────────────────
        printf("\n%s ━━━  SIMULATED REBOOT  ━━━\n\n", timestamp().c_str());

        bool needRollback = bootManager->onBootAttempt();
        if (needRollback) {
            return doRollback(OTAError::SESSION_TIMEOUT);
        }

        // ─── COMMIT_PENDING → VALIDATING ──────────────────────
        transition(OTAState::VALIDATING);
        LOG("[OTA]", "Running Bank B. Health validation begins...");

        HealthResultInfo health = healthMonitor->runCycles();

        if (!health.healthy) {
            return doRollback(OTAError::INTEGRITY_FAIL);
        }

        // ─── VALIDATING → ACTIVE ──────────────────────────────
        transition(OTAState::ACTIVE);
        bootManager->confirmStable();
        storageManager->promoteB();

        activeFirmwareVersion = meta.firmwareVersion;
        ++updateCount;

        LOG("[TLM]", "FIRMWARE_VERSION: %u → %u",
            activeFirmwareVersion - 1, activeFirmwareVersion);
        LOG("[TLM]", "OTA_UPDATE_COUNT: %u", updateCount);

        return currentState;
    }

private:
    void transition(OTAState next) {
        OTAState prev = currentState;
        currentState  = next;
        lastError     = OTAError::NONE;

        if (prev != next)
            LOG("[OTA]", "%-20s → %s", to_str(prev), to_str(next));

        if (telemetryReporter)
            telemetryReporter->onStateReport({ next, lastError });
    }

    OTAState enterError(OTAError err) {
        lastError    = err;
        currentState = OTAState::ERROR;
        LOG("[OTA]", "ERROR state — %s", to_str(err));
        if (telemetryReporter)
            telemetryReporter->onStateReport({ currentState, lastError });

        LOG("[OTA]", "ERROR → IDLE  (cleanup complete)");
        LOG("[TLM]", "OTA_LAST_ERROR: %s", to_str(lastError));
        currentState = OTAState::IDLE;
        return OTAState::ERROR; // return the error state, not IDLE
    }

    OTAState doRollback(OTAError reason) {
        transition(OTAState::ROLLBACK);
        LOG("[OTA]", "Rollback reason: %s", to_str(reason));
        bootManager->onBootCommand(static_cast<uint8_t>(Bank::BANK_A));
        printf("\n%s ━━━  SIMULATED REBOOT (Bank A)  ━━━\n\n",
               timestamp().c_str());
        LOG("[TLM]", "OTA_STATE: ROLLBACK");
        LOG("[TLM]", "OTA_LAST_ERROR: %s", to_str(reason));
        currentState = OTAState::IDLE;
        return OTAState::ROLLBACK;
    }
};

} // namespace CubeSatOTA

#pragma once
// ============================================================
// OTAComponents.hpp  —  C++ component class declarations
//
// Each class models one F' component from the FPP topology.
// The class names, port method names, and state machine
// directly correspond to their FPP counterparts. Method calls
// simulate typed port invocations; return values simulate
// the data carried by output ports back to the caller.
// ============================================================

#include "OTATypes.hpp"
#include "OTACrypto.hpp"
#include <vector>
#include <string>
#include <cstdio>
#include <ctime>

namespace CubeSatOTA {

// ----------------------------------------------------------
// Logging helpers  (simulate F' event ports + telemetry)
// ----------------------------------------------------------
inline std::string timestamp() {
    auto now = std::chrono::steady_clock::now();
    auto ms  = std::chrono::duration_cast<std::chrono::milliseconds>(
                   now.time_since_epoch()).count() % 100000;
    char buf[16]; snprintf(buf, sizeof(buf), "[%05lld]", (long long)ms);
    return buf;
}

#define LOG(tag, fmt, ...) \
    printf("%s %-5s " fmt "\n", timestamp().c_str(), tag, ##__VA_ARGS__)

// ----------------------------------------------------------
// TelemetryReporter  (passive — mirrors TelemetryReporter.fpp)
// Called by OTAManager on every FSM state transition via the
// stateReport output port.
// ----------------------------------------------------------
class TelemetryReporter {
public:
    uint32_t transitionCount = 0;
    OTAState lastState       = OTAState::IDLE;
    OTAError lastError       = OTAError::NONE;

    // Port handler: stateReport input port
    void onStateReport(const StateReportInfo& info) {
        lastState = info.otaState;
        lastError = info.otaError;
        ++transitionCount;
        LOG("[TLM]", "OTA_STATE=%-20s  OTA_ERROR=%s  transitions=%u",
            to_str(lastState), to_str(lastError), transitionCount);
    }
};

// ----------------------------------------------------------
// BootManager  (passive — mirrors BootManager.fpp)
// Owns boot_target and boot_try_count in persistent storage.
// ----------------------------------------------------------
class BootManager {
public:
    Bank     bootTarget    = Bank::BANK_A;
    uint8_t  bootTryCount  = 0;
    uint8_t  threshold     = 3;   // rollback after 3 failed boots

    // Port handler: bootCommand input port
    void onBootCommand(uint8_t bankVal) {
        bootTarget = static_cast<Bank>(bankVal);
        LOG("[BOT]", "boot_target → %s", to_str(bootTarget));
        // [TLM] BOOT_TARGET channel
        LOG("[TLM]", "BOOT_TARGET=%s  BOOT_TRY_COUNT=%u",
            to_str(bootTarget), bootTryCount);
    }

    // Called on each reboot into Bank B; returns true if rollback needed
    bool onBootAttempt() {
        if (bootTarget == Bank::BANK_B) {
            ++bootTryCount;
            LOG("[BOT]", "Boot from BANK_B (try %u/%u)", bootTryCount, threshold);
            if (bootTryCount >= threshold) {
                LOG("[BOT]", "⚠  Auto-rollback threshold reached!");
                bootTarget   = Bank::BANK_A;
                bootTryCount = 0;
                return true; // rollback!
            }
        }
        return false;
    }

    void confirmStable() {
        bootTryCount = 0;
        LOG("[BOT]", "BANK_B confirmed stable; boot_try_count reset to 0");
        LOG("[TLM]", "BOOT_TRY_COUNT=0");
    }
};

// ----------------------------------------------------------
// StorageManager  (passive — mirrors StorageManager.fpp)
// Manages dual-bank NVM. Writes to Bank B only.
// ----------------------------------------------------------
class StorageManager {
public:
    std::vector<uint8_t> bankA;  // active golden image
    std::vector<uint8_t> bankB;  // staging bank (written during update)

    // Port handler: triggerWrite input port
    // Returns WriteResultInfo (mirrors writeResult output port)
    WriteResultInfo onTriggerWrite(const std::vector<uint8_t>& image) {
        LOG("[STG]", "Writing Bank B: %zu bytes in %zu blocks",
            image.size(), (image.size() + 511) / 512);

        bankB.resize(image.size());
        size_t totalBlocks = (image.size() + 511) / 512;

        for (size_t blk = 0; blk < totalBlocks; ++blk) {
            size_t offset = blk * 512;
            size_t blklen = std::min<size_t>(512, image.size() - offset);

            // Write block
            std::memcpy(bankB.data() + offset, image.data() + offset, blklen);

            // Verify block via CRC-16 readback
            uint16_t written  = CRC16::compute(image.data() + offset, blklen);
            uint16_t readback = CRC16::compute(bankB.data() + offset, blklen);

            if (written != readback) {
                LOG("[STG]", "✗ Block %zu write/readback CRC mismatch!", blk);
                return { OpResult::FAIL, 0 };
            }
            // Print progress every 4 blocks to keep output readable
            if (blk % 4 == 0 || blk == totalBlocks - 1)
                LOG("[STG]", "  Block %3zu/%3zu written  CRC-16=0x%04X ✓",
                    blk, totalBlocks - 1, written);
        }

        // Post-write SHA-256 integrity check
        uint8_t writtenHash[SHA256_SIZE], sourceHash[SHA256_SIZE];
        SHA256::compute(bankB.data(), bankB.size(), writtenHash);
        SHA256::compute(image.data(), image.size(), sourceHash);

        if (!SHA256::equal(writtenHash, sourceHash)) {
            LOG("[STG]", "✗ Post-write SHA-256 mismatch!");
            return { OpResult::FAIL, 0 };
        }
        LOG("[STG]", "Post-write SHA-256 read-back: MATCH ✓");
        return { OpResult::OK, static_cast<uint32_t>(bankB.size()) };
    }

    // Swap: Bank B becomes the running image after confirmed update
    void promoteB() {
        bankA = bankB;
        LOG("[STG]", "Bank B promoted to active; Bank A updated");
    }
};

// ----------------------------------------------------------
// IntegrityVerifier  (passive — mirrors IntegrityVerifier.fpp)
// ----------------------------------------------------------
class IntegrityVerifier {
public:
    uint8_t expectedHash[SHA256_SIZE] = {};

    void setExpectedHash(const uint8_t hash[SHA256_SIZE]) {
        std::memcpy(expectedHash, hash, SHA256_SIZE);
    }

    // Port handler: triggerVerify input port
    // Returns VerifyResultInfo (mirrors result output port)
    VerifyResultInfo onTriggerVerify(const std::vector<uint8_t>& image) {
        LOG("[INT]", "SHA-256 computation started (%zu bytes)...", image.size());

        uint8_t  computed[SHA256_SIZE];
        uint32_t ms = SHA256::compute(image.data(), image.size(), computed);

        // Print first 16 hex chars for visual confirmation
        char hexComp[33] = {}, hexExp[33] = {};
        for (int i = 0; i < 16; ++i) {
            snprintf(hexComp + i*2, 3, "%02x", computed[i]);
            snprintf(hexExp  + i*2, 3, "%02x", expectedHash[i]);
        }
        LOG("[INT]", "  Computed : %s...", hexComp);
        LOG("[INT]", "  Expected : %s...", hexExp);

        bool ok = SHA256::equal(computed, expectedHash);
        LOG("[INT]", "SHA-256 %s  (%u ms)", ok ? "MATCH ✓" : "MISMATCH ✗", ms);

        return { ok ? OpResult::OK : OpResult::FAIL, ms };
    }
};

// ----------------------------------------------------------
// AuthVerifier  (passive — mirrors AuthVerifier.fpp)
// ----------------------------------------------------------
class AuthVerifier {
public:
    uint8_t gsPublicKey[ED25519_KEY_SIZE] = {};

    void setPublicKey(const uint8_t key[ED25519_KEY_SIZE]) {
        std::memcpy(gsPublicKey, key, ED25519_KEY_SIZE);
    }

    // Port handler: triggerVerify input port
    // Verifies Ed25519 signature over (sha256Hash || firmwareVersion || platformId)
    VerifyResultInfo onTriggerVerify(const uint8_t  sig[ED25519_SIG_SIZE],
                                     const uint8_t  hash[SHA256_SIZE],
                                     uint32_t       firmwareVersion,
                                     uint32_t       platformId) {
        LOG("[AUT]", "Ed25519 signature verification started...");

        // Build signed message: hash(32) || version(4) || platformId(4)
        uint8_t msg[SHA256_SIZE + 4 + 4];
        std::memcpy(msg,                hash,             SHA256_SIZE);
        std::memcpy(msg + SHA256_SIZE,  &firmwareVersion, 4);
        std::memcpy(msg + SHA256_SIZE + 4, &platformId,   4);

        char hexSig[17] = {};
        for (int i = 0; i < 8; ++i) snprintf(hexSig + i*2, 3, "%02x", sig[i]);
        LOG("[AUT]", "  Signature : %s...", hexSig);

        VerifyResultInfo result = Ed25519::verify(gsPublicKey, msg, sizeof(msg), sig);
        LOG("[AUT]", "Ed25519 %s  (%u ms)",
            result.opResult == OpResult::OK ? "VALID ✓" : "INVALID ✗",
            result.durationMs);

        return result;
    }
};

// ----------------------------------------------------------
// UplinkReceiver  (active — mirrors UplinkReceiver.fpp)
// Simulates CCSDS chunk transmission with CRC-16 verification.
// ----------------------------------------------------------
class UplinkReceiver {
public:
    struct Session {
        uint32_t token;
        uint16_t totalChunks;
        std::vector<bool> received;
        std::vector<uint8_t> buffer;
    };

    // Simulate transmission + reception of a firmware image.
    // Returns the reassembled image and reception statistics.
    ChunksDoneInfo transmit(const std::vector<uint8_t>& image,
                            uint32_t sessionToken,
                            std::vector<uint8_t>& outBuffer,
                            bool injectCorruption = false,
                            int corruptChunkIdx = -1) {
        uint16_t numChunks = static_cast<uint16_t>(
            (image.size() + CHUNK_PAYLOAD_SIZE - 1) / CHUNK_PAYLOAD_SIZE);

        LOG("[UPL]", "Session 0x%08X  %u chunks × %zu B",
            sessionToken, numChunks, CHUNK_PAYLOAD_SIZE);

        outBuffer.clear();
        outBuffer.reserve(image.size());

        uint16_t crcErrors = 0;

        for (uint16_t i = 0; i < numChunks; ++i) {
            size_t offset = i * CHUNK_PAYLOAD_SIZE;
            size_t plen   = std::min<size_t>(CHUNK_PAYLOAD_SIZE,
                                             image.size() - offset);

            // Build CCSDS chunk
            CCSChunk chunk{};
            chunk.packetId     = 0x0042u;
            chunk.seqControl   = static_cast<uint16_t>(0xC000u | i);
            chunk.dataLength   = static_cast<uint16_t>(6 + plen - 1);
            chunk.sessionToken = sessionToken;
            chunk.chunkSeqNo   = i;
            std::memcpy(chunk.payload, image.data() + offset, plen);

            // Compute CRC over everything except the CRC field itself
            chunk.crc16 = CRC16::compute(
                reinterpret_cast<uint8_t*>(&chunk),
                sizeof(chunk) - sizeof(uint16_t));

            // Simulate corruption if requested (scenario 2)
            if (injectCorruption && static_cast<int>(i) == corruptChunkIdx) {
                LOG("[UPL]", "⚠  Injecting corruption into chunk %u", i);
                chunk.payload[0] ^= 0xFFu; // flip all bits in first byte
                // Deliberately leave CRC unchanged → CRC fail
            }

            // OBC side: verify CRC-16
            uint16_t rxCRC = CRC16::compute(
                reinterpret_cast<uint8_t*>(&chunk),
                sizeof(chunk) - sizeof(uint16_t));

            if (rxCRC != chunk.crc16) {
                LOG("[UPL]", "  Chunk %3u/%u  CRC-16 FAIL ✗  (0x%04X≠0x%04X)",
                    i, numChunks - 1, rxCRC, chunk.crc16);
                ++crcErrors;
                // In a real system: send NACK, request retransmission.
                // For simulation: abort immediately.
                return { 0, 0 };
            }

            // Accept chunk
            for (size_t b = 0; b < plen; ++b)
                outBuffer.push_back(chunk.payload[b]);

            if (i % 4 == 0 || i == (uint16_t)(numChunks - 1))
                LOG("[UPL]", "  Chunk %3u/%u  CRC-16=0x%04X ✓",
                    i, numChunks - 1, chunk.crc16);
        }

        LOG("[UPL]", "All %u chunks received  (%zu bytes reassembled)",
            numChunks, outBuffer.size());
        return { static_cast<uint32_t>(outBuffer.size()), numChunks };
    }
};

// ----------------------------------------------------------
// HealthMonitor  (active — mirrors HealthMonitor.fpp)
// ----------------------------------------------------------
class HealthMonitor {
public:
    uint8_t requiredCycles  = 2;
    bool    simulateFailure = false; // set true for scenario 3

    // Run K health-check cycles and return result.
    // Returns HealthResultInfo after each cycle (here we batch all K).
    HealthResultInfo runCycles() {
        for (uint8_t cycle = 1; cycle <= requiredCycles; ++cycle) {
            LOG("[HLT]", "Health check cycle %u/%u", cycle, requiredCycles);

            // Criterion 1: component initialisation
            LOG("[HLT]", "  Component init ............. ✓");
            // Criterion 2: memory integrity
            LOG("[HLT]", "  Memory integrity ........... ✓");
            // Criterion 3: comms subsystem
            if (simulateFailure && cycle == 1) {
                LOG("[HLT]", "  Comms subsystem ............ ✗  (not responding)");
                return { false, cycle };
            }
            LOG("[HLT]", "  Comms subsystem ............ ✓");
            // Criterion 4: telemetry flow
            LOG("[HLT]", "  Telemetry flow ............. ✓");
            LOG("[HLT]", "Health cycle %u PASSED ✓", cycle);
        }
        return { true, requiredCycles };
    }
};

} // namespace CubeSatOTA

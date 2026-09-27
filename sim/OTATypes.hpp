#pragma once
// ============================================================
// OTATypes.hpp  —  C++ types mirroring the FPP component model
// Every enum, constant, and struct here corresponds directly
// to a definition in the CubeSatOTA FPP module.
// ============================================================

#include <cstdint>
#include <cstring>
#include <string>

namespace CubeSatOTA {

// ----------------------------------------------------------
// Enumerations  (mirror OTATypes.fpp)
// ----------------------------------------------------------

enum class OTAState : uint8_t {
    IDLE                = 0,
    RECEIVING           = 1,
    VERIFYING_INTEGRITY = 2,
    VERIFYING_AUTH      = 3,
    WRITING             = 4,
    COMMIT_PENDING      = 5,
    VALIDATING          = 6,
    ACTIVE              = 7,
    ROLLBACK            = 8,
    ERROR               = 9
};

enum class OpResult : uint8_t { OK = 0, FAIL = 1 };
enum class Bank     : uint8_t { BANK_A = 0, BANK_B = 1 };

enum class OTAError : uint8_t {
    NONE              = 0,
    INTEGRITY_FAIL    = 1,
    AUTH_FAIL         = 2,
    WRITE_FAIL        = 3,
    SESSION_TIMEOUT   = 4,
    VERSION_REJECTED  = 5,
    PLATFORM_MISMATCH = 6
};

// ----------------------------------------------------------
// String helpers for logging
// ----------------------------------------------------------

inline const char* to_str(OTAState s) {
    switch (s) {
        case OTAState::IDLE:                return "IDLE";
        case OTAState::RECEIVING:           return "RECEIVING";
        case OTAState::VERIFYING_INTEGRITY: return "VERIFYING_INTEGRITY";
        case OTAState::VERIFYING_AUTH:      return "VERIFYING_AUTH";
        case OTAState::WRITING:             return "WRITING";
        case OTAState::COMMIT_PENDING:      return "COMMIT_PENDING";
        case OTAState::VALIDATING:          return "VALIDATING";
        case OTAState::ACTIVE:              return "ACTIVE";
        case OTAState::ROLLBACK:            return "ROLLBACK";
        case OTAState::ERROR:               return "ERROR";
        default:                            return "UNKNOWN";
    }
}

inline const char* to_str(OTAError e) {
    switch (e) {
        case OTAError::NONE:              return "NONE";
        case OTAError::INTEGRITY_FAIL:    return "INTEGRITY_FAIL";
        case OTAError::AUTH_FAIL:         return "AUTH_FAIL";
        case OTAError::WRITE_FAIL:        return "WRITE_FAIL";
        case OTAError::SESSION_TIMEOUT:   return "SESSION_TIMEOUT";
        case OTAError::VERSION_REJECTED:  return "VERSION_REJECTED";
        case OTAError::PLATFORM_MISMATCH: return "PLATFORM_MISMATCH";
        default:                          return "UNKNOWN";
    }
}

inline const char* to_str(Bank b) {
    return b == Bank::BANK_A ? "BANK_A" : "BANK_B";
}

inline const char* to_str(OpResult r) {
    return r == OpResult::OK ? "OK" : "FAIL";
}

// ----------------------------------------------------------
// OTAU package constants
// ----------------------------------------------------------

constexpr uint32_t OTAU_MAGIC         = 0x4F544155u; // "OTAU"
constexpr uint16_t OTAU_FORMAT_VER    = 0x0001u;
constexpr uint32_t THIS_PLATFORM_ID   = 0xC5A7E001u; // CubeSat platform A
constexpr size_t   CHUNK_PAYLOAD_SIZE = 512u;
constexpr size_t   SHA256_SIZE        = 32u;
constexpr size_t   ED25519_SIG_SIZE   = 64u;
constexpr size_t   ED25519_KEY_SIZE   = 32u;

// ----------------------------------------------------------
// OTAU package header  (112 bytes, matches architecture spec)
// ----------------------------------------------------------
#pragma pack(push, 1)
struct OTAUHeader {
    uint32_t magic;           // 4  bytes — must equal OTAU_MAGIC
    uint16_t packageVersion;  // 2  bytes — format version
    uint32_t platformId;      // 4  bytes — target platform identifier
    uint32_t firmwareVersion; // 4  bytes — monotonically increasing
    uint32_t imageSize;       // 4  bytes — firmware image size in bytes
    uint16_t chunkCount;      // 2  bytes — number of CCSDS chunks
    uint8_t  sha256Hash[32];  // 32 bytes — SHA-256 of firmware image
    uint8_t  ed25519Sig[64];  // 64 bytes — Ed25519 over (hash||version||platformId)
};
#pragma pack(pop)
static_assert(sizeof(OTAUHeader) == 116, "OTAUHeader must be 116 bytes");

// ----------------------------------------------------------
// CCSDS Space Packet  (per architecture spec §7)
// ----------------------------------------------------------
#pragma pack(push, 1)
struct CCSChunk {
    // CCSDS primary header (6 bytes)
    uint16_t packetId;     // APID = 0x0042 (OTA uplink)
    uint16_t seqControl;   // sequence flags (0b11) + sequence count
    uint16_t dataLength;   // packet data length − 1
    // OTA secondary header
    uint32_t sessionToken; // per-session anti-replay token
    uint16_t chunkSeqNo;   // 0-indexed chunk sequence number
    // Payload
    uint8_t  payload[CHUNK_PAYLOAD_SIZE];
    uint16_t crc16;        // CRC-16/CCITT over all preceding bytes
};
#pragma pack(pop)

// ----------------------------------------------------------
// Port payload structs  (mirror OTATypes.fpp structs)
// ----------------------------------------------------------

struct ChunksDoneInfo  { uint32_t totalBytes; uint16_t chunkCount; };
struct VerifyResultInfo{ OpResult opResult;   uint32_t durationMs; };
struct WriteResultInfo { OpResult opResult;   uint32_t bytesWritten;};
struct HealthResultInfo{ bool     healthy;    uint8_t  cycleNum;   };
struct StateReportInfo { OTAState otaState;   OTAError otaError;   };

} // namespace CubeSatOTA

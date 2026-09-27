# ============================================================
# UplinkReceiver.fpp
# Active component; receives CCSDS Space Packets on the uplink
# port, verifies per-chunk CRC-16/CCITT, maintains a reception
# bitmap, and notifies OTAManager when all chunks are in.
# ============================================================

module CubeSatOTA {

  @ Active component that receives CCSDS-framed firmware chunks.
  @ Each incoming packet carries a 6-byte CCSDS primary header,
  @ a 4-byte session token, a 2-byte sequence number, up to
  @ 512 bytes of firmware payload, and a 2-byte CRC-16/CCITT.
  @ A reception bitmap detects missing chunks, which may be
  @ re-requested via NACK. A configurable session timeout
  @ (default 300 s) aborts reception if the uplink stalls.
  active component UplinkReceiver {

    @ Raw incoming CCSDS Space Packet from the radio driver
    async input port packetIn: Fw.Com

    @ Scheduler tick for decrementing the session timeout counter
    async input port schedIn: Svc.Sched

    @ Notify OTAManager when all expected chunks have been received
    output port chunksDone: CubeSatOTA.ChunksDonePort

    command recv port CmdDisp
    command reg port CmdReg
    command resp port CmdStatus
    event port Log
    text event port LogText
    time get port Time
    telemetry port Tlm

    @ Initialise a new reception session (called by OTAManager)
    async command UPLINK_SESSION_INIT(
      sessionToken: U32 @< Must match the token from OTA_START
      chunkCount:   U16 @< Expected number of chunks
      timeoutSecs:  U16 @< Session timeout in seconds (0 = use default)
    ) opcode 0x10

    @ Clear the reception buffer and reset to idle
    async command UPLINK_RESET \
      opcode 0x11

    @ Emitted when a chunk passes CRC-16 verification
    event CHUNK_RECEIVED(
      seqNo:     U16 @< Zero-based sequence number of this chunk
      numChunks: U16 @< Total chunks expected in this session
    ) severity diagnostic \
      id 0x10 \
      format "Chunk {}/{} received OK"

    @ Emitted when a chunk fails CRC-16 (retransmission requested)
    event CHUNK_CRC_FAIL(
      seqNo: U16 @< Sequence number of the failing chunk
    ) severity warning low \
      id 0x11 \
      format "CRC-16 fail on chunk {} — requesting retransmission"

    @ Emitted when the session timeout expires before completion
    event SESSION_TIMEOUT \
      severity warning high \
      id 0x12 \
      format "OTA uplink session timed out; aborting"

    @ Emitted when all chunks have been received successfully
    event RECEPTION_COMPLETE(
      totalBytes: U32 @< Total bytes in the reassembled image
    ) severity activity high \
      id 0x13 \
      format "All chunks received: {} bytes reassembled"

    @ Chunks successfully received in the current session
    telemetry CHUNKS_RECEIVED: U16 id 0x10 update always

    @ CRC-16 failures in the current session
    telemetry CHUNK_CRC_ERRORS: U16 id 0x11 update on change

    @ Session timeout countdown in seconds
    telemetry SESSION_TIMEOUT_REMAINING: U16 id 0x12 update always

  }

}


# ============================================================
# IntegrityVerifier.fpp
# Passive component; computes SHA-256 over the reassembled
# firmware image and compares against the expected hash
# embedded in the OTAU package header.
# ============================================================

module CubeSatOTA {

  @ Passive component for SHA-256 firmware integrity verification.
  @ Triggered synchronously by OTAManager in VERIFYING_INTEGRITY.
  @ The expected hash is provisioned via the EXPECTED_SHA256
  @ parameter before the trigger arrives.
  passive component IntegrityVerifier {

    @ Trigger from OTAManager to begin SHA-256 computation
    sync input port triggerVerify: Fw.Com

    @ Result returned to OTAManager after verification completes
    output port result: CubeSatOTA.VerifyResultPort

    param get port prmGetOut
    param set port prmSetIn
    command recv port CmdDisp
    command reg port CmdReg
    command resp port CmdStatus
    event port Log
    text event port LogText
    time get port Time
    telemetry port Tlm

    @ Expected SHA-256 hash of the incoming firmware image.
    @ Set from the OTAU package header before triggering.
    param EXPECTED_SHA256: CubeSatOTA.Sha256Hash \
      id 0x20

    @ Emitted when SHA-256 computation begins
    event INTEGRITY_CHECK_START(
      imageSize: U32 @< Image size in bytes being hashed
    ) severity activity high \
      id 0x20 \
      format "SHA-256 integrity check started on {} bytes"

    @ Emitted when computed hash matches the expected value
    event INTEGRITY_CHECK_PASS \
      severity activity high \
      id 0x21 \
      format "SHA-256 integrity check PASSED"

    @ Emitted when computed hash does not match the expected value
    event INTEGRITY_CHECK_FAIL \
      severity warning high \
      id 0x22 \
      format "SHA-256 integrity check FAILED — image rejected"

    @ Result of the last integrity check: 0=OK, 1=FAIL
    telemetry INTEGRITY_RESULT: CubeSatOTA.OpResult id 0x20 update on change

    @ Duration of the last SHA-256 computation in milliseconds
    telemetry SHA256_COMPUTE_MS: U32 id 0x21 update on change

  }

}


# ============================================================
# AuthVerifier.fpp
# Passive component; verifies the Ed25519 signature over the
# concatenation (SHA-256 hash ‖ firmwareVersion ‖ platformId).
# This binding prevents both image tampering and downgrade/
# cross-platform replay attacks in a single verification step.
# ============================================================

module CubeSatOTA {

  @ Passive component for Ed25519 firmware authentication.
  @ The OBC stores only the ground-station public key,
  @ provisioned at manufacturing time via the GS_PUBLIC_KEY
  @ parameter. The private key never leaves the ground HSM.
  passive component AuthVerifier {

    @ Trigger from OTAManager in VERIFYING_AUTH state
    sync input port triggerVerify: Fw.Com

    @ Verification result returned to OTAManager
    output port result: CubeSatOTA.VerifyResultPort

    param get port prmGetOut
    param set port prmSetIn
    command recv port CmdDisp
    command reg port CmdReg
    command resp port CmdStatus
    event port Log
    text event port LogText
    time get port Time
    telemetry port Tlm

    @ Ed25519 public key of the authorised ground station.
    @ Provisioned at manufacturing time; rotation requires a
    @ separate authenticated key-rotation update procedure.
    param GS_PUBLIC_KEY: CubeSatOTA.Ed25519PublicKey \
      id 0x30

    @ Emitted when Ed25519 verification begins
    event AUTH_CHECK_START \
      severity activity high \
      id 0x30 \
      format "Ed25519 signature verification started"

    @ Emitted when the signature is valid
    event AUTH_CHECK_PASS \
      severity activity high \
      id 0x31 \
      format "Ed25519 signature verification PASSED"

    @ Emitted when the signature is invalid
    event AUTH_CHECK_FAIL \
      severity warning high \
      id 0x32 \
      format "Ed25519 signature verification FAILED — update rejected"

    @ Result of the last authentication check: 0=OK, 1=FAIL
    telemetry AUTH_RESULT: CubeSatOTA.OpResult id 0x30 update on change

    @ Duration of the last Ed25519 verification in milliseconds
    telemetry ED25519_VERIFY_MS: U32 id 0x31 update on change

  }

}

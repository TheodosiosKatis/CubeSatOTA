# CubeSatOTA

Simulation code for the MSc thesis **"Secure and Dependable Over-the-Air (OTA)
Software Updates for CubeSats using JPL F′"**.

Theodosios Katis. MSc programme *Space Technologies, Applications and Services (STAR)*,
Department of Informatics and Telecommunications, National and Kapodistrian
University of Athens (NKUA), 2026.
Supervisor: Christos Tsigkanos, Assistant Professor, NKUA.

The repository contains:

- the **F′ (FPP) component model** of the proposed OTA architecture (thesis Ch. 4, App. C)
- a **host-based C++ simulation** of the OTA state machine and its failure paths (thesis Ch. 6, App. B)
- a **ground-station tool** that builds and signs OTA update packages

> This is a source-level / host-level validation of the update logic. It is **not**
> flight software and has not been run on flight hardware, real flash memory, or a
> real radio link.

---

## Architecture in brief

The update is delivered as an **OTAU package**: a 116-byte header followed by the
firmware image. The header carries a magic number, format version, target platform ID,
firmware version, image size, chunk count, the SHA-256 hash of the image, and an
Ed25519 signature over `SHA-256 || firmwareVersion || platformId`.

On board, eight F′ components cooperate, orchestrated by `OTAManager`:

| Component | Kind | Responsibility |
|---|---|---|
| `OTAManager` | active | Owns the state machine, sequences the update, emits events/telemetry |
| `UplinkReceiver` | active | Receives chunks, checks CRC-16 per chunk, reassembles the image |
| `IntegrityVerifier` | passive | Computes SHA-256 and compares it with the header |
| `AuthVerifier` | passive | Verifies the Ed25519 signature |
| `StorageManager` | passive | Writes the image to bank B and reads it back |
| `BootManager` | passive | Selects the boot bank, keeps the boot-retry counter, performs rollback |
| `HealthMonitor` | active | Post-boot health check of the new image |
| `TelemetryReporter` | passive | Reports state transitions, error codes and progress |

State machine: `IDLE → RECEIVING → VERIFYING_INTEGRITY → VERIFYING_AUTH → WRITING →
COMMIT_PENDING → VALIDATING → ACTIVE`, with `ROLLBACK` (return to bank A) and `ERROR`
as the failure exits.

| Layer | Mechanism | Purpose |
|---|---|---|
| Transfer | CRC-16/CCITT per 512-byte chunk | Detect random channel errors early |
| Integrity | SHA-256 over the whole image | Detect corruption or tampering |
| Authenticity | Ed25519 | Accept only images signed by the ground station |
| Activation | A/B banks + health check | Never commit an image that fails after boot |

Confidentiality (e.g. AES-128-GCM) is intentionally out of scope for this profile; see
thesis Ch. 5.

---

## Repository layout

```
CubeSatOTA/
├── fpp/                        F′ FPP model
│   ├── OTATypes.fpp            Enums, arrays, structs, port types
│   ├── OTAManager.fpp          Active FSM orchestrator
│   ├── UplinkAndVerifiers.fpp  UplinkReceiver, IntegrityVerifier, AuthVerifier
│   ├── StorageAndSupport.fpp   StorageManager, BootManager, HealthMonitor, TelemetryReporter
│   └── OTATopology.fpp         Component instances and port connections
├── sim/                        Host C++17 simulation
│   ├── OTATypes.hpp            C++ types mirroring the FPP model
│   ├── OTACrypto.hpp           SHA-256, Ed25519, CRC-16 (OpenSSL)
│   ├── OTAComponents.hpp       The eight components
│   ├── OTAManager.hpp          State machine / orchestration
│   └── main.cpp                Scenario driver
├── tools/
│   └── gs_tool.py              Ground station: build and sign OTAU packages
├── Simulation Output           Captured output of a full simulation run
├── fpp_check.sh                Helper to validate the FPP files with fpp-check
└── CMakeLists.txt
```

---

## Build and run the simulation

Requirements: CMake ≥ 3.16, a C++17 compiler, OpenSSL 3.x.

**macOS**

```bash
brew install cmake openssl
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DOPENSSL_ROOT_DIR="$(brew --prefix openssl)"
cmake --build build
./build/ota_sim
```

**Linux / WSL**

```bash
sudo apt-get install -y cmake build-essential libssl-dev
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
./build/ota_sim
```

**Windows (MSVC)**

```bat
cmake -S . -B build-win -DOPENSSL_ROOT_DIR="C:\Program Files\OpenSSL-Win64"
cmake --build build-win --config Release
build-win\Release\ota_sim.exe
```

The test image is a deterministic pseudo-random 8192-byte buffer (fixed seed),
sent as 16 chunks of 512 bytes, so every run is reproducible.

### Scenarios and expected results

| # | Scenario | Stimulus | Expected outcome |
|---|---|---|---|
| 1 | Normal update | Valid package, correct hash and signature, healthy image | `ACTIVE`, firmware v6 on bank B |
| 2 | Tampered image | Chunk corrupted in transit | Rejected (`INTEGRITY_FAIL`), active firmware unchanged |
| 3 | Forged signature | Consistent image/hash, signature from an unauthorised key | Rejected (`AUTH_FAIL`), active firmware unchanged |
| 4 | Health-check failure | Valid image that fails the post-boot health check | `ROLLBACK` to bank A, firmware v6 restored |

A reference run is stored in [`Simulation Output`](Simulation%20Output).

---

## Validate the FPP model

Requires [`fprime-tools`](https://pypi.org/project/fprime-tools/) (provides `fpp-check`)
and a checkout of the [F′ framework](https://github.com/nasa/fprime):

```bash
pip3 install fprime-tools
git clone --depth 1 https://github.com/nasa/fprime.git ../fprime

./fpp_check.sh fpp/OTATypes.fpp fpp/OTAManager.fpp \
               fpp/UplinkAndVerifiers.fpp fpp/StorageAndSupport.fpp
```

Set `FPRIME_ROOT=/path/to/fprime` if F′ is cloned elsewhere. The model was checked
with `fpp-check` v3.2.0.

---

## Ground-station tool

```bash
pip3 install pynacl

# Synthetic demo package (generates a fresh key pair)
python3 tools/gs_tool.py --demo

# Sign a real image
python3 tools/gs_tool.py --image firmware.bin --version 7 \
                         --key gs_private_key.bin --out update_v7.otau
```

The tool writes the private key to disk. Keys and `.otau` packages are excluded by
`.gitignore` and must never be committed.

---

## Citation

```
T. Katis, "Secure and Dependable Over-the-Air Software Updates for CubeSats
using JPL F′", MSc thesis, Dept. of Informatics and Telecommunications,
National and Kapodistrian University of Athens, 2026.
```

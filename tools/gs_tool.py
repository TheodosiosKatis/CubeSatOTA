#!/usr/bin/env python3
"""
gs_tool.py  —  CubeSat Ground Station OTA Package Generator
MSc Thesis: Secure and Dependable OTA Updates for CubeSats (F')
Theodosios Katis — NKUA 2026

Generates a signed OTAU package that the C++ simulation (ota_sim)
can consume. Uses the same binary format defined in OTATypes.hpp:
  - Ed25519 signature (PyNaCl / libsodium)
  - SHA-256 hash (hashlib)
  - OTAU header struct (116 bytes)

Usage:
  python3 gs_tool.py --image firmware.bin --version 6 --out update.otau
  python3 gs_tool.py --demo   # generate a synthetic demo package
"""

import argparse
import hashlib
import struct
import os
import sys

try:
    import nacl.signing
    import nacl.encoding
except ImportError:
    sys.exit("PyNaCl not installed. Run: pip install pynacl")

# ──────────────────────────────────────────────────────────────
# Constants (must match OTATypes.hpp)
# ──────────────────────────────────────────────────────────────
OTAU_MAGIC       = 0x4F544155   # "OTAU"
OTAU_FORMAT_VER  = 0x0001
THIS_PLATFORM_ID = 0xC5A7E001
CHUNK_SIZE       = 512

HEADER_FMT = '<IHIIIHx32s64s'   # see struct OTAUHeader (padded to 116 bytes)
# Actually: magic(4) + packageVersion(2) + platformId(4) + firmwareVersion(4)
#         + imageSize(4) + chunkCount(2) + sha256Hash(32) + ed25519Sig(64)
# = 4+2+4+4+4+2+32+64 = 116 bytes
HEADER_FMT  = '!IHIII H 32s 64s'  # big-endian for clarity; little-endian in C
HEADER_FMT  = '<I H I I I H 32s 64s'
HEADER_SIZE = struct.calcsize(HEADER_FMT)
assert HEADER_SIZE == 116, f"Header size mismatch: {HEADER_SIZE}"


def build_package(image: bytes, firmware_version: int,
                  signing_key: nacl.signing.SigningKey,
                  platform_id: int = THIS_PLATFORM_ID) -> bytes:
    """Build and sign a complete OTAU binary package."""

    # 1. SHA-256 over the raw firmware image
    sha256_hash = hashlib.sha256(image).digest()
    assert len(sha256_hash) == 32

    # 2. Build signed message: SHA-256(32) || firmwareVersion(4) || platformId(4)
    fw_ver_bytes  = struct.pack('<I', firmware_version)
    plat_bytes    = struct.pack('<I', platform_id)
    signed_msg    = sha256_hash + fw_ver_bytes + plat_bytes

    # 3. Ed25519 sign (deterministic — same key+msg always gives same signature)
    signed = signing_key.sign(signed_msg)
    ed25519_sig = signed.signature            # first 64 bytes
    assert len(ed25519_sig) == 64

    # 4. Assemble header
    chunk_count = (len(image) + CHUNK_SIZE - 1) // CHUNK_SIZE
    header = struct.pack(HEADER_FMT,
                         OTAU_MAGIC,
                         OTAU_FORMAT_VER,
                         platform_id,
                         firmware_version,
                         len(image),
                         chunk_count,
                         sha256_hash,
                         ed25519_sig)

    return header + image


def print_package_info(pkg: bytes, signing_key: nacl.signing.SigningKey):
    """Pretty-print package details for verification."""
    hdr_fields = struct.unpack(HEADER_FMT, pkg[:HEADER_SIZE])
    magic, fmt_ver, plat_id, fw_ver, img_size, chunks, sha256, sig = hdr_fields

    print("─" * 64)
    print("  OTAU Package Summary")
    print("─" * 64)
    print(f"  Magic          : 0x{magic:08X}  ({'OK' if magic == OTAU_MAGIC else 'BAD'})")
    print(f"  Format version : {fmt_ver}")
    print(f"  Platform ID    : 0x{plat_id:08X}")
    print(f"  FW version     : {fw_ver}")
    print(f"  Image size     : {img_size} bytes")
    print(f"  Chunk count    : {chunks} × {CHUNK_SIZE} B")
    print(f"  SHA-256        : {sha256.hex()[:32]}...")
    print(f"  Ed25519 sig    : {sig.hex()[:32]}...")
    print(f"  Public key     : {signing_key.verify_key.encode().hex()[:32]}...")
    print(f"  Total pkg size : {len(pkg)} bytes")
    print("─" * 64)

    # Self-verify
    sha256_check = hashlib.sha256(pkg[HEADER_SIZE:]).digest()
    if sha256_check == sha256:
        print("  SHA-256 self-check : ✓ PASS")
    else:
        print("  SHA-256 self-check : ✗ FAIL")

    try:
        verify_key = signing_key.verify_key
        fw_ver_bytes = struct.pack('<I', fw_ver)
        plat_bytes   = struct.pack('<I', plat_id)
        msg = sha256 + fw_ver_bytes + plat_bytes
        verify_key.verify(msg, sig)
        print("  Ed25519 self-check : ✓ PASS")
    except Exception as e:
        print(f"  Ed25519 self-check : ✗ FAIL ({e})")
    print("─" * 64)


def demo_mode():
    """Generate a synthetic demo package and print its details."""
    print("\n[GS] Generating Ed25519 key pair...")
    sk = nacl.signing.SigningKey.generate()

    print("[GS] Generating synthetic 8192-byte firmware image...")
    import random
    rng = random.Random(0xDEADBEEF)
    image = bytes([rng.randint(0, 255) for _ in range(8192)])

    fw_version = 6
    print(f"[GS] Building OTAU package (firmware v{fw_version})...")
    pkg = build_package(image, fw_version, sk)

    # Save files
    key_path = "gs_private_key.bin"
    pub_path = "gs_public_key.bin"
    pkg_path = "demo_v6.otau"

    with open(key_path, 'wb') as f:
        f.write(bytes(sk))
    with open(pub_path, 'wb') as f:
        f.write(bytes(sk.verify_key))
    with open(pkg_path, 'wb') as f:
        f.write(pkg)

    print(f"[GS] Private key  → {key_path}  (KEEP SECRET)")
    print(f"[GS] Public key   → {pub_path}  (provision on OBC at manufacturing)")
    print(f"[GS] Package      → {pkg_path}")
    print()
    print_package_info(pkg, sk)
    print()
    print("[GS] Demo package generation complete.")


def main():
    parser = argparse.ArgumentParser(description="CubeSat OTA Package Generator")
    parser.add_argument('--image',   help="Input firmware binary")
    parser.add_argument('--version', type=int, help="Firmware version number")
    parser.add_argument('--key',     help="Ed25519 private key file (32 bytes)")
    parser.add_argument('--out',     help="Output .otau package path")
    parser.add_argument('--demo',    action='store_true',
                        help="Generate a synthetic demo package")
    args = parser.parse_args()

    if args.demo:
        demo_mode()
        return

    if not all([args.image, args.version, args.out]):
        parser.print_help()
        sys.exit(1)

    # Load or generate signing key
    if args.key and os.path.exists(args.key):
        with open(args.key, 'rb') as f:
            sk = nacl.signing.SigningKey(f.read())
        print(f"[GS] Loaded private key from {args.key}")
    else:
        sk = nacl.signing.SigningKey.generate()
        key_path = args.out.replace('.otau', '') + '_private.bin'
        pub_path  = args.out.replace('.otau', '') + '_public.bin'
        with open(key_path, 'wb') as f: f.write(bytes(sk))
        with open(pub_path,  'wb') as f: f.write(bytes(sk.verify_key))
        print(f"[GS] Generated new key pair")
        print(f"[GS]   Private → {key_path}")
        print(f"[GS]   Public  → {pub_path}")

    with open(args.image, 'rb') as f:
        image = f.read()
    print(f"[GS] Firmware image: {len(image)} bytes  (v{args.version})")

    pkg = build_package(image, args.version, sk)
    with open(args.out, 'wb') as f:
        f.write(pkg)
    print(f"[GS] Package written: {args.out}  ({len(pkg)} bytes)")
    print()
    print_package_info(pkg, sk)


if __name__ == '__main__':
    main()

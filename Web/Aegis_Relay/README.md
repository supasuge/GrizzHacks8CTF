# Aegis Relay

- **Difficulty**: Hard - Requires understanding of OpenPGP packet structure, streaming parser behavior, and knowledge of CVE-2025-47934 vulnerability mechanics. Not solvable through crypto-breaking or brute force.
- **Author: [supasuge](https://github.com/supasuge) | [Evan Pardon](https://linkedin.com/in/evan-pardon)**
- **Category**: Web
- **Difficulty:** Hard
- **Flag:** `GRIZZ{p4ck3t_d3sync_auth_byp4ss_CVE_2025_47934}`

## Description

*"In the halls of cryptography, truth is what the verifier sees first. But what happens when the executor reads a different story?"*
They say packets are streams of truth, consumed in order. But what if order is merely... a suggestion? What if some packets can rewrite the narrative after verification has already looked away? 
**Your mission**: Make the cryptography tell the truth while the system acts on a lie. No keys to crack. No hashes to brute. Just a perfectly valid signature... on a message that was never meant to be.

> Hint: When streams diverge, compressed realities take precedence. 

## Tags

```
#OpenPGP #PacketMagic #StreamingParsing #TrustButVerify #ProtocolConfusion
```

## Objective

Craft a message that:
1. Passes cryptographic signature verification
2. Contains the authorization command to release the flag
3. Does NOT involve stealing or guessing Alice's private key

## What's NOT Allowed

This challenge is about understanding cryptographic protocols, not brute force or side channels.

The following approaches will NOT work:
- Brute forcing Alice's private key
- Timing attacks
- Guessing secrets
- SQL injection or XSS
- Weak cryptography or broken algorithms

The cryptography itself is sound. The signature verification works correctly.

So how do you bypass authentication without breaking the crypto? ... A CVE. KekW 

![alt text](image.png)

## Build Instructions

```bash
cd src/
docker compose up --build -d # builds and run container in detached mode (Port: 3000)
```

## Running

Visit `http://localhost:3000`

The web interface provides:
- Sample signed messages from Alice
- Alice's public key for download
- Message verification and execution system

Study the samples. Understand the format. Think about what the system verifies versus what it executes.

## Hints

1. When signature verification passes but you didn't sign the message, something interesting happened. What did the verifier see? What did the executor see? Are they the same?

2. OpenPGP messages are composed of packets. Signatures cover specific packet sequences. What happens if there are more packets than the signature covers?

3. OpenPGP supports compressed data packets. These packets contain other packets inside them. How does the parser decide which packets to read when there are multiple sources?

## Learning Objectives

After solving this challenge, you will understand:
- How OpenPGP packet structure works
- The difference between signature coverage and message parsing
- Why protocol-level vulnerabilities can bypass cryptographic guarantees
- That "signature verified" doesn't always mean "message authenticated"

---

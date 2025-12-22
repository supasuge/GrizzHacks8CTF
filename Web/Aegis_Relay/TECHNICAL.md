# Technical Documentation: Aegis Relay

**Difficulty**: Hard - Requires understanding of OpenPGP packet structure, streaming parser behavior, and knowledge of CVE-2025-47934 vulnerability mechanics. Not solvable through crypto-breaking or brute force.
**Author: [supasuge](https://github.com/supasuge) | [Evan Pardon](https://linkedin.com/in/evan-pardon)**

## Challenge Architecture

This document provides technical details for maintainers and organizers.

### Stack

- **Backend**: Node.js + Express
- **Crypto Library**: OpenPGP.js 5.11.2 (vulnerable version)
- **Frontend**: Vanilla HTML/CSS/JavaScript
- **Deployment**: Docker + Docker Compose

### Vulnerability Details

**CVE-2025-47934**: OpenPGP.js Packet Desynchronization

Affected versions:
- OpenPGP.js ≤ 5.11.2
- OpenPGP.js 6.0.0 - 6.1.0

The vulnerability allows an attacker to append compressed packets to a signed message. The verification phase processes the original signed packets, while the data extraction phase preferentially reads from the appended compressed packet, leading to authenticated execution of unsigned content.

### Critical Files

#### Backend (`server.js`)

The intentionally vulnerable verification logic:

```javascript
const message = await openpgp.readMessage({ armoredMessage });
const verificationResult = await openpgp.verify({
  message,
  verificationKeys: alicePublicKey
});

await verificationResult.signatures[0].verified;  // Verifies original
const executedData = verificationResult.data;     // Reads compressed packet
```

#### Remediation

- Update OpenPGP.js version.
- Add packet validation.
- Compare verified vs executed data.
- Normalize packet streams.

#### Frontend (`public/`)

- `index.html`: Challenge interface with three-panel desync visualization
- `style.css`: Dark crypto theme with desync animations
- `app.js`: Client-side verification submission

### File Structure

```
Aegis-Relay/
├── server.js              # Vulnerable backend
├── package.json           # Dependencies (OpenPGP.js 5.11.2)
├── Dockerfile             # Container build
├── docker-compose.yml     # Easy deployment
├── setup.sh               # Local setup script
├── public/                # Frontend assets
│   ├── index.html
│   ├── style.css
│   └── app.js
├── scripts/               # Key/sample generation
│   ├── generate-keys.js
│   └── generate-samples.js
├── data/                  # Generated runtime data
│   ├── alice-private.asc  # Alice's private key
│   ├── alice-public.asc   # Alice's public key
│   └── sample-*.asc       # Legitimate signed messages
├── solution/              # Exploit implementations
│   ├── README.md          # Detailed solution writeup
│   ├── exploit.js         # Node.js exploit
│   ├── solve.py           # Python exploit
│   └── requirements.txt   # Python dependencies
└── README.md              # Challenge description
```

### Deployment

#### Docker (Recommended)

```bash
docker-compose up --build
```

Access: `http://localhost:3000`

The Dockerfile automatically:
1. Installs dependencies
2. Generates Alice's keypair
3. Creates sample signed messages
4. Starts the server

#### Manual Setup

```bash
npm install
npm run generate-keys
npm run generate-samples
npm start
```

### Environment Variables

- `PORT`: Server port (default: 3000)
- `FLAG`: Challenge flag (default: `GRIZZ{p4ck3t_d3sync_auth_byp4ss_CVE_2025_47934}`)

### Testing the Exploit

#### Using Node.js:

```bash
cd solution
npm install
node exploit.js
```

#### Using Python:

```bash
cd solution
pip install -r requirements.txt
python3 solve.py
```

Both scripts will:
1. Fetch a legitimate signed message
2. Craft a malicious compressed packet
3. Submit the exploit
4. Display the captured flag

### Expected Behavior

**Legitimate Message Flow**:
1. User submits Alice's signed message
2. Signature verifies 
3. Executed content matches signed content
4. Authorization denied (no auth command)

**Exploit Flow**:
1. Attacker submits modified message
2. Signature verifies (original packets unchanged)
3. Executed content from compressed packet
4. Authorization granted -> Flag released

### Common Issues

**Issue**: "No sample messages available"
**Fix**: Run `npm run generate-samples`

**Issue**: "Public key not found"
**Fix**: Run `npm run generate-keys`

**Issue**: Signature verification fails
**Fix**: Ensure OpenPGP.js version is exactly 5.11.2

**Issue**: Exploit doesn't work
**Fix**: Verify server is running and vulnerable version is installed

### Hardening (Post-Event)

After the event, you can demonstrate the fix:

```javascript
// Upgrade OpenPGP.js
npm install openpgp@latest

// Add verification in server.js
const message = await openpgp.readMessage({ armoredMessage });

// Read full message first
const fullText = await message.getText();

const verificationResult = await openpgp.verify({
  message,
  verificationKeys: alicePublicKey
});

await verificationResult.signatures[0].verified;

// Compare verified to executed
if (fullText !== verificationResult.data) {
  throw new Error('Packet desynchronization detected');
}
```

### Learning Objectives Validation

After solving, participants should understand:

1. **OpenPGP Packet Structure**: One-Pass Signature → Literal Data → Signature
2. **Compressed Packets**: Can contain nested packet structures
3. **Parser State**: Verification vs execution may operate on different data
4. **Defense in Depth**: Cryptographic correctness ≠ protocol security

### References

- RFC 4880: OpenPGP Message Format
- OpenPGP.js Documentation
- CVE-2025-47934 (hypothetical for this challenge)

### Notes

This challenge is designed to:
- Teach protocol-level vulnerabilities
- Demonstrate that "signature verified" is insufficient
- Show real-world crypto implementation bugs
- Avoid requiring cryptographic math knowledge

It should NOT:
- Require brute force
- Involve weak cryptography
- Depend on implementation details beyond the documented CVE
- Be solvable without understanding packet structure


---

**Remember**: The goal is education, not frustration. The challenge should be hard but fair, teaching real vulnerability concepts applicable to production systems.

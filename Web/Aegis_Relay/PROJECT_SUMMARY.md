# SIGNED, SEALED, DECEIVED - Project Summary

## Complete Challenge Implementation

A production-ready CTF challenge exploiting CVE-2025-47934 (OpenPGP.js packet desynchronization).

### What's Been Built

#### Core Challenge
- ✅ Vulnerable Node.js backend (OpenPGP.js 5.11.2)
- ✅ Interactive web interface with "packet desync" visual theme
- ✅ Automated key generation (Ed25519)
- ✅ Sample signed messages (3 legitimate examples)
- ✅ Flag release mechanism on successful exploit

#### Deployment
- ✅ Dockerfile for containerized deployment
- ✅ docker-compose.yml for one-command setup
- ✅ Manual setup script (setup.sh)
- ✅ Environment variable configuration

#### Documentation
- ✅ README.md - Challenge description with progressive hints
- ✅ TECHNICAL.md - Maintainer documentation
- ✅ QUICKSTART.md - Fast setup guide
- ✅ solution/README.md - Detailed vulnerability explanation

#### Solution Scripts
- ✅ exploit.js - Node.js exploit with full packet crafting
- ✅ solve.py - Python exploit with manual packet construction
- ✅ Both scripts include detailed output and explanation

### Technical Highlights

**Vulnerability**: CVE-2025-47934
- Packet desynchronization in OpenPGP.js
- Signature verifies original packets
- Execution reads appended compressed packet
- Result: Authenticated bypass without private key

**Attack Vector**:
```
[One-Pass Sig] → [Literal Data] → [Signature]  ← Signed & Verified
                  ↓
[Compressed [Literal Data (malicious)]]  ← Executed!
```

**Exploit Requirements**:
- Understanding OpenPGP RFC 4880
- Binary packet construction
- Compressed data packet creation
- No cryptographic weaknesses exploited

### Project Structure

```
Key-Rot/
├── server.js                 # Vulnerable backend
├── package.json              # OpenPGP.js 5.11.2
├── Dockerfile                # Container build
├── docker-compose.yml        # Deployment config
├── setup.sh                  # Setup automation
├── public/                   # Frontend
│   ├── index.html           # Challenge UI
│   ├── style.css            # Desync theme
│   └── app.js               # Client logic
├── scripts/                  # Generation utilities
│   ├── generate-keys.js     # Ed25519 keypair
│   └── generate-samples.js  # Signed messages
├── data/                     # Runtime generated
│   ├── alice-*.asc          # PGP keys
│   └── sample-*.asc         # Signed samples
├── solution/                 # Exploits
│   ├── README.md            # Full explanation
│   ├── exploit.js           # Node.js exploit
│   └── solve.py             # Python exploit
└── docs/                     # Documentation
    ├── README.md
    ├── TECHNICAL.md
    ├── QUICKSTART.md
    └── CLAUDE.md            # Build spec
```

### Quick Deploy

```bash
docker-compose up --build
```

### Quick Test

```bash
npm install && npm run generate-keys && npm run generate-samples && npm start
cd solution && npm install && node exploit.js
```

### Success Criteria

- [x] Legitimate messages verify but don't release flag
- [x] Exploit messages verify AND release flag
- [x] Cryptography is sound (EdDSA, no weak keys)
- [x] No unintended solution paths
- [x] Clear learning progression
- [x] Professional presentation
- [x] Complete documentation
- [x] Working exploit scripts in 2 languages
- [x] Docker deployment ready

### Key Features

**Educational Value**:
- Real-world vulnerability (based on actual CVE pattern)
- Protocol-level exploitation
- Demonstrates crypto ≠ security
- Teaches OpenPGP internals

**Challenge Quality**:
- No guessing or brute force
- Clear but non-trivial solution path
- Progressive hints available
- Multiple solution approaches documented

**Production Ready**:
- Containerized deployment
- Environment variable configuration
- Comprehensive testing
- Clear setup instructions

### Flag

`GRIZZ{p4ck3t_d3sync_auth_byp4ss_CVE_2025_47934}`

### Difficulty

**Hard** - Requires understanding of:
- OpenPGP packet format (RFC 4880)
- Binary packet construction
- Compressed data structures
- Parser behavior differences

### Time to Solve

Expected: 2-4 hours for experienced CTF players
- 30min: Understanding the challenge
- 1hr: Researching OpenPGP packets
- 1hr: Crafting exploit packets
- 30min: Testing and refinement

### Post-Event Use

Can be converted to educational demo by:
1. Upgrading to patched OpenPGP.js
2. Showing why exploit no longer works
3. Demonstrating proper packet validation
4. Teaching defense-in-depth principles

---

## Maintenance Notes

### Updating the Flag

Edit `FLAG` environment variable in:
- `docker-compose.yml`
- `Dockerfile`
- Or set at runtime: `FLAG=GRIZZ{...} npm start`

### Regenerating Keys

```bash
rm data/*.asc
npm run generate-keys
npm run generate-samples
```

### Verifying Vulnerability

Ensure `package.json` has exactly:
```json
"openpgp": "5.11.2"
```

Any other version may not exhibit the vulnerability.

---

**Challenge Ready for Deployment** ✅

All specifications from CLAUDE.md have been implemented.
The challenge is production-ready and tested.

# Quick Start Guide

**Author**: [supasuge](https:/github.com/supasuge) | [Evan Pardon](https://linkedin.com/in/evan-pardon)
## For Challenge Organizers

**Handout for participants (Source code)**

```
/handout/AegisRelay.zip 
    -> app.js, index.html, style.css 
```

### Deploy with Docker (Fastest + Easiest)

```bash
docker-compose up --build
```

That's it! Challenge is live at `http://localhost:3000`

### Deploy Manually

```bash
./setup.sh
npm start
```

Challenge is live at `http://localhost:3000`

---

## For Participants

### Access the Challenge

Navigate to the challenge URL provided by organizers.

### Your Mission

Get the flag by:
1. Submitting a message that passes signature verification
2. Making the message contain the authorization command
3. NOT having Alice's private key

### What You'll Need

- Understanding of OpenPGP packet format
- Ability to craft binary packets
- Knowledge of how compression works in OpenPGP

### Resources Provided

- Alice's public key (download from challenge interface)
- Sample signed messages from Alice
- Message verification interface

### Hints

If stuck, check the README.md hints section. They progressively reveal the approach without spoiling the solution.

### Solution Verification

Run the provided exploits to verify your approach:

**Node.js**:
```bash
cd solution
npm install
node exploit.js
```

**Python**:
```bash
cd solution
pip install -r requirements.txt
python3 solve.py
```

---

## For Local Testing

Start the server:
```bash
npm start
```

In another terminal, run the exploit:
```bash
cd solution
node exploit.js
```

You should see the flag captured.

---

## Flag Format

`GRIZZ{...}`

## Difficulty

Hard - Requires protocol-level understanding

## Categories

- Protocol Exploitation
- Web
- OpenPGP/GNUPrivacy Guard

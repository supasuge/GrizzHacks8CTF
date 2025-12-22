/**
 * Generate Sample Signed Messages for CVE-2025-47934 Challenge
 *
 * This script generates properly formatted inline-signed PGP messages that are
 * vulnerable to the packet desynchronization attack described in CVE-2025-47934.
 *
 * Message Format:
 * - Uses createMessage() (NOT createCleartextMessage())
 * - Creates inline signatures (NOT detached signatures)
 * - Results in packet structure: One-Pass Signature -> Literal Data -> Signature
 *
 * This format allows attackers to append a Compressed Data packet containing
 * malicious content that will be executed instead of the signed content.
 */

const openpgp = require('openpgp');
const fs = require('fs');
const path = require('path');

const sampleMessages = [
  `STATUS: ALL SYSTEMS NOMINAL
TIMESTAMP: 2025-02-01T12:00:00Z
OPERATOR: Alice
MESSAGE: Routine security check completed successfully.`,

  `STATUS: MAINTENANCE SCHEDULED
TIMESTAMP: 2025-02-05T08:30:00Z
OPERATOR: Alice
MESSAGE: Vault integrity verification scheduled for tonight.`,

  `STATUS: AUDIT COMPLETE
TIMESTAMP: 2025-02-10T16:45:00Z
OPERATOR: Alice
MESSAGE: Quarterly access review shows no anomalies.`
];

async function generateSamples() {
  const privateKeyArmored = fs.readFileSync(
    path.join(__dirname, '..', 'data', 'alice-private.asc'),
    'utf8'
  );

  const privateKey = await openpgp.readPrivateKey({ armoredKey: privateKeyArmored });

  console.log('Generating legitimate signed messages (armored)...\n');

  for (let i = 0; i < sampleMessages.length; i++) {
    // Create a standard message (not cleartext) to generate proper packet structure:
    // One-Pass Signature -> Literal Data -> Signature
    const message = await openpgp.createMessage({ text: sampleMessages[i] });

    // Sign the message inline (not detached) to create the exploitable packet structure
    const signed = await openpgp.sign({
      message,
      signingKeys: privateKey,
      format: 'armored' // ASCII-armored output
    });

    const filename = path.join(__dirname, '..', 'data', `sample-${i + 1}.asc`);
    fs.writeFileSync(filename, signed, 'utf8');

    console.log(`✓ Generated sample-${i + 1}.asc`);
    console.log(`  Content preview: ${sampleMessages[i].split('\n')[0]}`);
    console.log(`  Format: Inline-signed PGP message (One-Pass Sig -> Literal Data -> Sig)\n`);
  }

  console.log('All sample messages generated successfully!');
  console.log('\nThese messages have the proper packet structure for CVE-2025-47934:');
  console.log('  - One-Pass Signature packet');
  console.log('  - Literal Data packet (contains the message text)');
  console.log('  - Signature packet');
  console.log('\nAttackers can append a Compressed Data packet after the Signature.');
}

generateSamples().catch(console.error);

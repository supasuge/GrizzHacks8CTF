const openpgp = require('openpgp');
const fs = require('fs');
const path = require('path');

async function generateAliceKeys() {
  console.log('Generating Alice\'s Ed25519 keypair...');

  const { privateKey, publicKey } = await openpgp.generateKey({
    type: 'ecc',
    curve: 'ed25519',
    userIDs: [{ name: 'Alice', email: 'alice@AegisRelay.internal' }],
    format: 'armored'
  });

  const dataDir = path.join(__dirname, '..', 'data');

  fs.writeFileSync(path.join(dataDir, 'alice-private.asc'), privateKey);
  fs.writeFileSync(path.join(dataDir, 'alice-public.asc'), publicKey);

  console.log('✓ Private key saved to data/alice-private.asc');
  console.log('✓ Public key saved to data/alice-public.asc');
  console.log('\n⚠️  WARNING: Keep alice-private.asc secure!');
}

generateAliceKeys().catch(console.error);

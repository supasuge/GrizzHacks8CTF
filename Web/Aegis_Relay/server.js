const express = require('express');
const openpgp = require('openpgp');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

const FLAG = process.env.FLAG || 'GRIZZ{fake_flag_for_testing}';

let alicePublicKey;

async function init() {
  const publicKeyArmored = fs.readFileSync(
    path.join(__dirname, 'data', 'alice-public.asc'),
    'utf8'
  );
  alicePublicKey = await openpgp.readKey({ armoredKey: publicKeyArmored });
  console.log('Alice\'s public key loaded successfully.');
}

app.use(express.json({ limit: '10mb' }));
app.use(express.text({ limit: '10mb' }));
app.use(express.static('public'));

app.get('/public-key', (req, res) => {
  const publicKeyArmored = fs.readFileSync(
    path.join(__dirname, 'data', 'alice-public.asc'),
    'utf8'
  );
  res.type('text/plain').send(publicKeyArmored);
});

app.get('/samples', (req, res) => {
  const samples = [];
  for (let i = 1; i <= 3; i++) {
    const filename = path.join(__dirname, 'data', `sample-${i}.asc`);
    if (fs.existsSync(filename)) {
      samples.push({
        id: i,
        content: fs.readFileSync(filename, 'utf8')
      });
    }
  }
  res.json(samples);
});

app.post('/verify', async (req, res) => {
  try {
    const armoredMessage = req.body.message || req.body;

    if (!armoredMessage || typeof armoredMessage !== 'string') {
      return res.status(400).json({
        success: false,
        error: 'Invalid message format'
      });
    }

    console.log('\n--- Verification Request ---');
    console.log('Message length:', armoredMessage.length);

    const message = await openpgp.readMessage({ armoredMessage });

    const verificationResult = await openpgp.verify({
      message,
      verificationKeys: alicePublicKey
    });

    const { verified, keyID } = verificationResult.signatures[0];

    await verified;

    const executedData = verificationResult.data;

    console.log('Signature verified successfully.');
    console.log('Validly Signed by:', keyID.toHex());
    console.log('Executed data:', executedData);

    const isAuthorized = executedData.includes('ACTION: RELEASE') &&
                        executedData.includes('TARGET: FLAG_VAULT');

    let response = {
      success: true,
      signatureValid: true,
      signedBy: 'Alice',
      keyID: keyID.toHex(),
      extractedData: executedData,
      authorized: isAuthorized
    };

    if (isAuthorized) {
      console.log('AUTHORIZATION GRANTED - FLAG RELEASED');
      response.flag = FLAG;
      response.message = 'Vault unlocked. Cryptography did its job. You trusted the wrong thing.';
    } else {
      response.message = 'Signature valid, but authorization denied.';
    }

    res.json(response);

  } catch (error) {
    console.error('Verification error:', error.message);
    res.status(400).json({
      success: false,
      error: 'Verification failed: ' + error.message
    });
  }
});

app.get('/health', (req, res) => {
  res.json({ status: 'operational', openpgp_version: require('openpgp/package.json').version });
});

init().then(() => {
  app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
  });
}).catch(console.error);

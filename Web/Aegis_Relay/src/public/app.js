const messageInput = document.getElementById('messageInput');
const verifyBtn = document.getElementById('verifyBtn');
const loadSampleBtn = document.getElementById('loadSampleBtn');
const downloadKeyBtn = document.getElementById('downloadKeyBtn');
const resultsSection = document.getElementById('resultsSection');
const loadingSpinner = document.getElementById('loadingSpinner');
const verificationResult = document.getElementById('verificationResult');
const extractedData = document.getElementById('extractedData');
const extractedContent = document.getElementById('extractedContent');
const actionStatus = document.getElementById('actionStatus');
const flagContainer = document.getElementById('flagContainer');
const flagText = document.getElementById('flagText');
const flagMessage = document.getElementById('flagMessage');
const keyID = document.getElementById('keyID');
const sampleModal = document.getElementById('sampleModal');
const sampleList = document.getElementById('sampleList');
const closeSampleModal = document.getElementById('closeSampleModal');

verifyBtn.addEventListener('click', verifyMessage);
loadSampleBtn.addEventListener('click', showSampleModal);
downloadKeyBtn.addEventListener('click', downloadPublicKey);
closeSampleModal.addEventListener('click', () => sampleModal.classList.add('hidden'));

async function verifyMessage() {
  const message = messageInput.value.trim();

  if (!message) {
    alert('Please enter a signed message');
    return;
  }

  resultsSection.classList.remove('hidden');
  loadingSpinner.classList.remove('hidden');
  verificationResult.classList.add('hidden');
  extractedData.classList.add('hidden');
  flagContainer.classList.add('hidden');

  const statusText = actionStatus.querySelector('.status-text');
  statusText.textContent = 'Verifying...';
  statusText.className = 'status-text';

  try {
    const response = await fetch('/verify', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ message })
    });

    const result = await response.json();

    loadingSpinner.classList.add('hidden');

    if (result.success && result.signatureValid) {
      verificationResult.classList.remove('hidden');
      keyID.textContent = result.keyID;

      await new Promise(resolve => setTimeout(resolve, 300));

      document.getElementById('executionPanel').classList.add('desync-effect');

      await new Promise(resolve => setTimeout(resolve, 300));

      extractedData.classList.remove('hidden');
      extractedContent.textContent = result.extractedData;

      if (result.authorized && result.flag) {
        statusText.textContent = 'Authorization Accepted';
        statusText.className = 'status-text approved';

        await new Promise(resolve => setTimeout(resolve, 500));

        flagContainer.classList.remove('hidden');
        flagText.textContent = result.flag;
        flagMessage.textContent = result.message;

        document.getElementById('actionPanel').classList.add('desync-effect');
      } else {
        statusText.textContent = 'Authorization Denied';
        statusText.className = 'status-text rejected';
      }
    } else {
      statusText.textContent = 'Verification Failed';
      statusText.className = 'status-text rejected';
      alert('Signature verification failed: ' + (result.error || 'Unknown error'));
    }
  } catch (error) {
    loadingSpinner.classList.add('hidden');
    statusText.textContent = 'Error';
    statusText.className = 'status-text rejected';
    alert('Error: ' + error.message);
  }
}

async function showSampleModal() {
  try {
    const response = await fetch('/samples');
    const samples = await response.json();

    sampleList.innerHTML = '';

    samples.forEach(sample => {
      const div = document.createElement('div');
      div.className = 'sample-item';

      const preview = sample.content.split('\n').slice(2, 6).join('\n');

      div.innerHTML = `
        <h4>Sample Message ${sample.id}</h4>
        <div class="sample-preview">${preview}</div>
      `;

      div.addEventListener('click', () => {
        messageInput.value = sample.content;
        sampleModal.classList.add('hidden');
      });

      sampleList.appendChild(div);
    });

    sampleModal.classList.remove('hidden');
  } catch (error) {
    alert('Error loading samples: ' + error.message);
  }
}

async function downloadPublicKey() {
  try {
    const response = await fetch('/public-key');
    const publicKey = await response.text();

    const blob = new Blob([publicKey], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);

    const a = document.createElement('a');
    a.href = url;
    a.download = 'alice-public.asc';
    a.click();

    URL.revokeObjectURL(url);
  } catch (error) {
    alert('Error downloading public key: ' + error.message);
  }
}

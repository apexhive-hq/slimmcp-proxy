(function () {
  const tierSelect = document.getElementById('tier-select');
  const payToEl = document.getElementById('pay-to-address');
  const usdcEl = document.getElementById('usdc-contract');
  const warningEl = document.getElementById('self-custody-warning');
  const copyBtn = document.getElementById('copy-address-btn');
  const walletPayBtn = document.getElementById('wallet-pay-btn');
  const walletPayStatus = document.getElementById('wallet-pay-status');
  const txInput = document.getElementById('tx-hash-input');
  const challengeBtn = document.getElementById('challenge-btn');
  const walletSignBtn = document.getElementById('wallet-sign-btn');
  const challengeBox = document.getElementById('challenge-box');
  const challengeText = document.getElementById('challenge-text');
  const challengeNonce = document.getElementById('challenge-nonce');
  const sigInput = document.getElementById('signature-input');
  const verifyForm = document.getElementById('verify-form');
  const errorBox = document.getElementById('status-error');
  const resultBox = document.getElementById('license-result');
  const activationCmdEl = document.getElementById('activation-cmd');
  const rawTokenEl = document.getElementById('raw-token');
  const playgroundInput = document.getElementById('playground-input');
  const loadSampleBtn = document.getElementById('load-sample-btn');
  const compressBtn = document.getElementById('compress-btn');
  const playgroundError = document.getElementById('playground-error');
  const playgroundResult = document.getElementById('playground-result');
  const playgroundSummary = document.getElementById('playground-summary');
  const playgroundOutput = document.getElementById('playground-output');

  let activeNonce = '';
  let cachedTiers = {
    indie: { usdc: '5', atomic: '5000000', batchName: 'Founding Batch' },
    team: { usdc: '49', atomic: '49000000' }
  };

  const batchBadgeEl = document.getElementById('batch-badge');
  const indiePriceEl = document.getElementById('indie-price');
  const tierIndieLabelEl = document.getElementById('tier-indie-label');

  function updateWalletPayLabel() {
    if (!walletPayBtn) return;
    const t = cachedTiers[tierSelect.value] || cachedTiers.indie;
    walletPayBtn.textContent = `Pay ${t.usdc} USDC with Wallet`;
  }

  function updateBatchUI() {
    const t = cachedTiers.indie;
    if (indiePriceEl) {
      indiePriceEl.textContent = `${t.usdc} USDC`;
    }
    if (tierIndieLabelEl) {
      tierIndieLabelEl.textContent = `Pro Indie — ${t.usdc} USDC${t.batchName ? ' (' + t.batchName + ')' : ''} (reg. 19 USDC)`;
    }
    if (batchBadgeEl && t.batchName) {
      batchBadgeEl.textContent = t.batchName;
      batchBadgeEl.hidden = false;
    }
  }

  function revealWalletButtonsIfInjected() {
    if (typeof window.ethereum !== 'undefined') {
      if (walletPayBtn) {
        updateWalletPayLabel();
        walletPayBtn.hidden = false;
      }
      if (walletSignBtn) walletSignBtn.hidden = false;
    }
  }

  function encodeErc20Transfer(recipient, atomicAmount) {
    const cleanAddr = recipient.toLowerCase().replace(/^0x/, '').padStart(64, '0');
    const amountHex = BigInt(atomicAmount).toString(16).padStart(64, '0');
    return `0xa9059cbb${cleanAddr}${amountHex}`;
  }

  function showError(msg) {
    errorBox.textContent = msg;
    errorBox.hidden = false;
    resultBox.hidden = true;
  }

  function clearError() {
    errorBox.hidden = true;
    errorBox.textContent = '';
  }

  async function loadConfig() {
    try {
      const res = await fetch('/api/config');
      if (!res.ok) return;
      const cfg = await res.json();
      if (cfg.payToAddress) payToEl.textContent = cfg.payToAddress;
      if (cfg.usdcContract) usdcEl.textContent = cfg.usdcContract;
      if (cfg.tiers) {
        cachedTiers = cfg.tiers;
        updateWalletPayLabel();
        updateBatchUI();
      }
      if (cfg.selfCustodyWarning) warningEl.textContent = cfg.selfCustodyWarning;
      if (cfg.optionalRails) {
        const sol = document.getElementById('sol-address');
        const btc = document.getElementById('btc-address');
        const tron = document.getElementById('tron-address');
        if (sol && cfg.optionalRails.solanaUsdc) sol.textContent = cfg.optionalRails.solanaUsdc;
        if (btc && cfg.optionalRails.bitcoin) btc.textContent = cfg.optionalRails.bitcoin;
        if (tron && cfg.optionalRails.tronTrxUsdt) tron.textContent = cfg.optionalRails.tronTrxUsdt;
      }
    } catch {
      // Static defaults remain visible
    }
  }

  tierSelect.addEventListener('change', updateWalletPayLabel);

  if (walletPayBtn) {
    walletPayBtn.addEventListener('click', async () => {
      clearError();
      if (!window.ethereum) {
        showError('No browser wallet detected. Send Base USDC manually and paste your txHash.');
        return;
      }
      try {
        const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
        const from = accounts[0];
        const chainId = await window.ethereum.request({ method: 'eth_chainId' });
        if (String(chainId).toLowerCase() !== '0x2105') {
          try {
            await window.ethereum.request({
              method: 'wallet_switchEthereumChain',
              params: [{ chainId: '0x2105' }]
            });
          } catch (switchErr) {
            if (switchErr && switchErr.code === 4902) {
              await window.ethereum.request({
                method: 'wallet_addEthereumChain',
                params: [
                  {
                    chainId: '0x2105',
                    chainName: 'Base',
                    nativeCurrency: { name: 'Ether', symbol: 'ETH', decimals: 18 },
                    rpcUrls: ['https://mainnet.base.org'],
                    blockExplorerUrls: ['https://basescan.org']
                  }
                ]
              });
            } else {
              throw switchErr;
            }
          }
        }

        const t = cachedTiers[tierSelect.value] || cachedTiers.indie;
        const payTo = payToEl.textContent.trim();
        const usdcAddr = usdcEl.textContent.trim();
        const data = encodeErc20Transfer(payTo, t.atomic);
        const txHash = await window.ethereum.request({
          method: 'eth_sendTransaction',
          params: [{ from, to: usdcAddr, data, value: '0x0' }]
        });
        txInput.value = txHash;
        if (walletPayStatus) {
          walletPayStatus.textContent = `Submitted ${txHash}. Wait for confirmations, then click "1. Generate EIP-191 Challenge".`;
          walletPayStatus.hidden = false;
        }
      } catch (err) {
        showError('Wallet payment failed: ' + (err.message || String(err)));
      }
    });
  }

  copyBtn.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(payToEl.textContent.trim());
      copyBtn.textContent = 'Copied';
      setTimeout(() => {
        copyBtn.textContent = 'Copy';
      }, 1500);
    } catch {
      copyBtn.textContent = 'Copy manually';
    }
  });

  challengeBtn.addEventListener('click', async () => {
    clearError();
    const txHash = txInput.value.trim();
    const tier = tierSelect.value;
    if (!/^0x[0-9a-fA-F]{64}$/.test(txHash)) {
      showError('Enter a valid 0x-prefixed 64-character Base transaction hash first.');
      return;
    }

    try {
      const res = await fetch('/api/challenge', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ txHash, tier })
      });
      const data = await res.json();
      if (!res.ok) {
        showError(data.message || data.error || 'Failed to generate challenge.');
        return;
      }
      activeNonce = data.nonce;
      challengeNonce.textContent = data.nonce;
      challengeText.value = data.message;
      challengeBox.hidden = false;
      if (typeof window.ethereum !== 'undefined') {
        walletSignBtn.hidden = false;
      }
    } catch (err) {
      showError('Network error generating challenge: ' + (err.message || String(err)));
    }
  });

  walletSignBtn.addEventListener('click', async () => {
    clearError();
    if (!window.ethereum || !challengeText.value) return;
    try {
      const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
      const account = accounts[0];
      const signature = await window.ethereum.request({
        method: 'personal_sign',
        params: [challengeText.value, account]
      });
      sigInput.value = signature;
    } catch (err) {
      showError('Wallet signature rejected: ' + (err.message || String(err)));
    }
  });

  verifyForm.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    clearError();

    const txHash = txInput.value.trim();
    const signature = sigInput.value.trim();
    const tier = tierSelect.value;

    if (!activeNonce) {
      showError('Generate an EIP-191 challenge first.');
      return;
    }

    try {
      const res = await fetch('/api/verify', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ txHash, nonce: activeNonce, signature, tier })
      });
      const data = await res.json();
      if (!res.ok) {
        showError((data.error ? data.error + ': ' : '') + (data.message || 'Verification failed.'));
        return;
      }
      activationCmdEl.textContent = data.activationCommand;
      rawTokenEl.textContent = data.licenseToken;
      resultBox.hidden = false;
    } catch (err) {
      showError('Network error verifying payment: ' + (err.message || String(err)));
    }
  });

  function buildSampleToolsPayload(count) {
    const domains = ['github', 'postgres', 'stripe'];
    const tools = [];
    for (let i = 0; i < count; i += 1) {
      const domain = domains[i % domains.length];
      tools.push({
        name: `${domain}:tool_${i + 1}`,
        description: `Execute ${domain} operation #${i + 1} with validated JSON schema parameters, pagination cursors, and structured error reporting.`,
        inputSchema: {
          type: 'object',
          properties: {
            targetId: { type: 'string', description: 'Primary resource identifier or repository slug' },
            filterQuery: { type: 'string', description: 'Optional structured search predicate' },
            limit: { type: 'number', description: 'Maximum page size between 1 and 100' },
            dryRun: { type: 'boolean', description: 'Validate permissions without mutating state' }
          },
          required: ['targetId']
        }
      });
    }
    return JSON.stringify({ tools }, null, 2);
  }

  if (loadSampleBtn && playgroundInput) {
    loadSampleBtn.addEventListener('click', () => {
      if (playgroundError) playgroundError.hidden = true;
      playgroundInput.value = buildSampleToolsPayload(60);
    });
  }

  if (compressBtn && playgroundInput) {
    compressBtn.addEventListener('click', async () => {
      if (playgroundError) {
        playgroundError.hidden = true;
        playgroundError.textContent = '';
      }
      if (playgroundResult) playgroundResult.hidden = true;

      const rawText = playgroundInput.value.trim();
      if (!rawText) {
        if (playgroundError) {
          playgroundError.textContent = 'Paste a tools/list JSON payload or click "Load 60-Tool Sample" first.';
          playgroundError.hidden = false;
        }
        return;
      }

      try {
        const res = await fetch('/api/playground/compress', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: rawText
        });
        const data = await res.json();
        if (!res.ok) {
          if (playgroundError) {
            playgroundError.textContent = data.message || data.error || 'Compression failed.';
            playgroundError.hidden = false;
          }
          return;
        }
        if (playgroundSummary) {
          playgroundSummary.textContent =
            `${data.toolCount} tools: ${data.rawBytes.toLocaleString('en-US')} bytes (~${data.rawTokensEst.toLocaleString('en-US')} tokens) -> ${data.compressedBytes.toLocaleString('en-US')} bytes (~${data.compressedTokensEst.toLocaleString('en-US')} tokens) — ${data.reductionPct}% reduction (${data.tokensSaved.toLocaleString('en-US')} tokens saved)`;
        }
        if (playgroundOutput) {
          playgroundOutput.textContent = JSON.stringify(
            { metaTools: data.metaTools, indexedTools: data.indexedTools },
            null,
            2
          );
        }
        if (playgroundResult) playgroundResult.hidden = false;
      } catch (err) {
        if (playgroundError) {
          playgroundError.textContent = 'Playground request failed: ' + (err.message || String(err));
          playgroundError.hidden = false;
        }
      }
    });
  }

  revealWalletButtonsIfInjected();
  loadConfig();
})();

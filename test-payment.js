#!/usr/bin/env node
/**
 * x402 Payment Flow Test
 *
 * Uses official @x402/fetch wrapper for automatic payment handling.
 * Tests the complete cycle: 402 → sign → pay → 200 + data
 */

import { wrapFetchWithPayment } from '@x402/fetch';
import { x402Client } from '@x402/core/client';
import { registerExactEvmScheme } from '@x402/evm/exact/client';
import { privateKeyToAccount } from 'viem/accounts';
import { createPublicClient, http, formatUnits } from 'viem';
import { baseSepolia } from 'viem/chains';
import dotenv from 'dotenv';

dotenv.config();

const PRIVATE_KEY = process.env.WALLET_PRIVATE_KEY;
const SERVER_URL = process.env.TEST_SERVER_URL || 'http://localhost:4021';

async function main() {
  console.log('🧪 x402 Full Payment Flow Test');
  console.log('='.repeat(60));

  // Setup signer
  const signer = privateKeyToAccount(PRIVATE_KEY);
  console.log(`Wallet: ${signer.address}`);
  console.log(`Server: ${SERVER_URL}`);

  // Setup x402 client (official way)
  const client = new x402Client();
  registerExactEvmScheme(client, { signer });

  // Fix: CDP facilitator requires 'network' at top level of paymentPayload
  // The client library (v2.3.1) only puts it inside 'accepted', not at the top level
  client.onAfterPaymentCreation(({ paymentPayload }) => {
    if (paymentPayload.accepted?.network && !paymentPayload.network) {
      paymentPayload.network = paymentPayload.accepted.network;
    }
  });

  // Wrap fetch with payment handling
  const fetchWithPayment = wrapFetchWithPayment(fetch, client);

  console.log('✅ x402 client configured with @x402/fetch\n');

  // Check balance
  const publicClient = createPublicClient({ chain: baseSepolia, transport: http() });
  const USDC_SEPOLIA = '0x036CbD53842c5426634e7929541eC2318f3dCF7e';
  const ethBal = await publicClient.getBalance({ address: signer.address });
  let usdcBal = 0n;
  try {
    usdcBal = await publicClient.readContract({
      address: USDC_SEPOLIA,
      abi: [{ name: 'balanceOf', type: 'function', stateMutability: 'view', inputs: [{ name: 'account', type: 'address' }], outputs: [{ name: '', type: 'uint256' }] }],
      functionName: 'balanceOf',
      args: [signer.address],
    });
  } catch(e) {}
  console.log(`💳 ETH: ${formatUnits(ethBal, 18)} | USDC: ${formatUnits(usdcBal, 6)}\n`);

  // Test ALL endpoints
  const endpoints = [
    // GET endpoints
    { path: '/api/dns-lookup?domain=google.com', method: 'GET', name: 'DNS Lookup ($0.001)' },
    { path: '/api/text-stats?text=Hello+world', method: 'GET', name: 'Text Stats ($0.001)' },
    { path: '/api/ip-info?ip=8.8.8.8', method: 'GET', name: 'IP Info ($0.001)' },
    { path: '/api/qr-code?text=x402rocks', method: 'GET', name: 'QR Code ($0.002)' },
    { path: '/api/password-strength?password=MyP4ss!2026', method: 'GET', name: 'Password Strength ($0.001)' },
    { path: '/api/http-headers?url=https://example.com', method: 'GET', name: 'HTTP Headers ($0.001)' },
    { path: '/api/ssl-check?domain=google.com', method: 'GET', name: 'SSL Check ($0.003)' },
    { path: '/api/whois?domain=google.com', method: 'GET', name: 'WHOIS ($0.005)' },
    { path: '/api/url-meta?url=https://example.com', method: 'GET', name: 'URL Meta ($0.003)' },
    { path: '/api/html-to-markdown?url=https://example.com', method: 'GET', name: 'HTML→MD ($0.002)' },
    { path: '/api/scrape?url=https://example.com', method: 'GET', name: 'Scrape ($0.01)' },
    // POST endpoints
    { path: '/api/json-format', method: 'POST', name: 'JSON Format ($0.001)', body: { json: '{"a":1,"b":2}' } },
    { path: '/api/base64', method: 'POST', name: 'Base64 ($0.001)', body: { text: 'x402 payment test', action: 'encode' } },
    { path: '/api/verify-email', method: 'POST', name: 'Email Verify ($0.01)', body: { email: 'test@google.com' } },
    { path: '/api/domain-health', method: 'POST', name: 'Domain Health ($0.01)', body: { domain: 'google.com' } },
    { path: '/api/ai-generate', method: 'POST', name: 'AI Generate ($0.05)', body: { topic: 'benefits of micropayments', type: 'social_media' } },
  ];

  let successCount = 0;
  let failCount = 0;

  for (const ep of endpoints) {
    console.log(`${'─'.repeat(60)}`);
    console.log(`📡 ${ep.name}: ${ep.method} ${ep.path}`);

    try {
      const fetchOpts = { method: ep.method };
      if (ep.body) {
        fetchOpts.headers = { 'Content-Type': 'application/json' };
        fetchOpts.body = JSON.stringify(ep.body);
      }

      // Step 1: Verify 402 response first (plain fetch)
      const check = await fetch(`${SERVER_URL}${ep.path}`, fetchOpts);
      if (check.status !== 402) {
        console.log(`   ⚠️  Expected 402, got ${check.status}`);
        failCount++;
        continue;
      }
      console.log('   ✅ Step 1: Got 402 Payment Required');

      // Step 2: Make paid request (fetchWithPayment handles everything)
      console.log('   🔐 Step 2: Making paid request (auto-sign + pay)...');
      const response = await fetchWithPayment(`${SERVER_URL}${ep.path}`, fetchOpts);

      console.log(`   📬 Response: ${response.status}`);

      if (response.status === 200) {
        const data = await response.json();
        console.log(`   ✅ PAYMENT SUCCESSFUL!`);
        console.log(`   📊 Data: ${JSON.stringify(data).substring(0, 200)}`);
        successCount++;
      } else {
        const body = await response.text();
        console.log(`   ❌ Failed: ${body.substring(0, 200)}`);

        // Decode payment-required header if present
        const prHeader = response.headers.get('payment-required');
        if (prHeader) {
          try {
            const decoded = JSON.parse(Buffer.from(prHeader, 'base64').toString());
            console.log(`   Error reason: ${decoded.error}`);
          } catch(e) {}
        }
        failCount++;
      }
    } catch (err) {
      console.log(`   ❌ Error: ${err.message}`);
      if (err.stack) console.log(`   Stack: ${err.stack.split('\n').slice(1, 4).join('\n   ')}`);
      failCount++;
    }
  }

  // Test free endpoints
  console.log(`\n${'─'.repeat(60)}`);
  console.log('🆓 Free endpoints:');
  for (const path of ['/', '/health', '/.well-known/x402', '/llms.txt']) {
    const r = await fetch(`${SERVER_URL}${path}`);
    console.log(`   ${path}: ${r.status} ${r.status === 200 ? '✅' : '❌'}`);
  }

  // Summary
  console.log(`\n${'='.repeat(60)}`);
  console.log(`📊 Results: ${successCount} paid ✅ | ${failCount} failed ❌`);

  // Final balance
  let usdcAfter = 0n;
  try {
    usdcAfter = await publicClient.readContract({
      address: USDC_SEPOLIA,
      abi: [{ name: 'balanceOf', type: 'function', stateMutability: 'view', inputs: [{ name: 'account', type: 'address' }], outputs: [{ name: '', type: 'uint256' }] }],
      functionName: 'balanceOf',
      args: [signer.address],
    });
  } catch(e) {}
  const spent = usdcBal - usdcAfter;
  console.log(`💰 USDC: ${formatUnits(usdcBal, 6)} → ${formatUnits(usdcAfter, 6)} (spent: ${formatUnits(spent, 6)})`);
  console.log('='.repeat(60));
}

main().catch(err => { console.error('Fatal:', err.message); process.exit(1); });

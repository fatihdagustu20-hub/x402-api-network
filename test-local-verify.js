#!/usr/bin/env node
/**
 * Local x402 Verification Test
 *
 * Runs the exact same verification logic as the CDP facilitator
 * but locally, with detailed error messages for debugging.
 */

import { createPublicClient, http, getAddress, verifyTypedData } from 'viem';
import { baseSepolia } from 'viem/chains';
import { x402Client, x402HTTPClient } from '@x402/core/client';
import { registerExactEvmScheme } from '@x402/evm/exact/client';
import { privateKeyToAccount } from 'viem/accounts';
import dotenv from 'dotenv';

dotenv.config();

const authorizationTypes = {
  TransferWithAuthorization: [
    { name: "from", type: "address" },
    { name: "to", type: "address" },
    { name: "value", type: "uint256" },
    { name: "validAfter", type: "uint256" },
    { name: "validBefore", type: "uint256" },
    { name: "nonce", type: "bytes32" }
  ]
};

async function localVerify(payload, requirements) {
  const eip3009Payload = payload.payload;
  const payer = eip3009Payload.authorization.from;

  console.log('\n🔍 Local Verification:');

  // Check 1: scheme match
  if (payload.accepted?.scheme !== 'exact' || requirements.scheme !== 'exact') {
    return { isValid: false, reason: 'scheme_mismatch', detail: `${payload.accepted?.scheme} vs ${requirements.scheme}` };
  }
  console.log('  ✅ Scheme match: exact');

  // Check 2: network match
  if (payload.accepted?.network !== requirements.network) {
    return { isValid: false, reason: 'network_mismatch', detail: `${payload.accepted?.network} vs ${requirements.network}` };
  }
  console.log(`  ✅ Network match: ${requirements.network}`);

  // Check 3: extra fields
  if (!requirements.extra?.name || !requirements.extra?.version) {
    return { isValid: false, reason: 'missing_eip712_domain' };
  }
  console.log(`  ✅ EIP-712 domain: ${requirements.extra.name} v${requirements.extra.version}`);

  // Check 4: verify signature
  const chainId = parseInt(requirements.network.split(':')[1]);
  const erc20Address = getAddress(requirements.asset);

  const domain = {
    name: requirements.extra.name,
    version: requirements.extra.version,
    chainId,
    verifyingContract: erc20Address,
  };

  const message = {
    from: eip3009Payload.authorization.from,
    to: eip3009Payload.authorization.to,
    value: BigInt(eip3009Payload.authorization.value),
    validAfter: BigInt(eip3009Payload.authorization.validAfter),
    validBefore: BigInt(eip3009Payload.authorization.validBefore),
    nonce: eip3009Payload.authorization.nonce,
  };

  try {
    const valid = await verifyTypedData({
      address: getAddress(payer),
      domain,
      types: authorizationTypes,
      primaryType: 'TransferWithAuthorization',
      message,
      signature: eip3009Payload.signature,
    });
    if (!valid) {
      return { isValid: false, reason: 'invalid_signature', detail: 'verifyTypedData returned false' };
    }
    console.log('  ✅ Signature valid');
  } catch(e) {
    return { isValid: false, reason: 'signature_verify_error', detail: e.message };
  }

  // Check 5: recipient match
  if (getAddress(eip3009Payload.authorization.to) !== getAddress(requirements.payTo)) {
    return { isValid: false, reason: 'recipient_mismatch', detail: `${eip3009Payload.authorization.to} vs ${requirements.payTo}` };
  }
  console.log('  ✅ Recipient match');

  // Check 6: timing
  const now = Math.floor(Date.now() / 1000);
  if (BigInt(eip3009Payload.authorization.validBefore) < BigInt(now + 6)) {
    return { isValid: false, reason: 'expired', detail: `validBefore ${eip3009Payload.authorization.validBefore} < now+6 ${now + 6}` };
  }
  if (BigInt(eip3009Payload.authorization.validAfter) > BigInt(now)) {
    return { isValid: false, reason: 'not_yet_valid', detail: `validAfter ${eip3009Payload.authorization.validAfter} > now ${now}` };
  }
  console.log('  ✅ Timing valid');

  // Check 7: balance
  const publicClient = createPublicClient({ chain: baseSepolia, transport: http() });
  const balance = await publicClient.readContract({
    address: erc20Address,
    abi: [{ name: 'balanceOf', type: 'function', inputs: [{ name: 'account', type: 'address' }], outputs: [{ type: 'uint256' }] }],
    functionName: 'balanceOf',
    args: [getAddress(payer)],
  });
  if (balance < BigInt(requirements.amount)) {
    return { isValid: false, reason: 'insufficient_funds', detail: `balance ${balance} < required ${requirements.amount}` };
  }
  console.log(`  ✅ Balance sufficient: ${balance} >= ${requirements.amount}`);

  // Check 8: amount
  if (BigInt(eip3009Payload.authorization.value) < BigInt(requirements.amount)) {
    return { isValid: false, reason: 'amount_too_low', detail: `authorized ${eip3009Payload.authorization.value} < required ${requirements.amount}` };
  }
  console.log('  ✅ Amount sufficient');

  return { isValid: true };
}

async function main() {
  console.log('🧪 Local x402 Verification Test\n');

  const signer = privateKeyToAccount(process.env.WALLET_PRIVATE_KEY);
  const client = new x402Client();
  registerExactEvmScheme(client, { signer });

  client.onAfterPaymentCreation(({ paymentPayload }) => {
    if (paymentPayload.accepted?.network && !paymentPayload.network) {
      paymentPayload.network = paymentPayload.accepted.network;
    }
  });

  const httpClient = new x402HTTPClient(client);

  // Get 402
  const res = await fetch('http://localhost:4021/api/text-stats?text=hello');
  const pr = httpClient.getPaymentRequiredResponse((n) => res.headers.get(n), null);

  // Create payment payload
  const paymentPayload = await client.createPaymentPayload(pr);

  console.log('Payload:', JSON.stringify(paymentPayload, null, 2).substring(0, 500));

  // Run local verification (same logic as facilitator)
  const result = await localVerify(paymentPayload, pr.accepts[0]);

  if (result.isValid) {
    console.log('\n✅ LOCAL VERIFICATION PASSED! The payment is valid.');
    console.log('The CDP facilitator should also accept this payload.');
    console.log('\nIf CDP still rejects, the issue is with CDP, not our code.');
  } else {
    console.log(`\n❌ LOCAL VERIFICATION FAILED: ${result.reason}`);
    if (result.detail) console.log(`   Detail: ${result.detail}`);
  }
}

main().catch(err => { console.error('Fatal:', err.message); process.exit(1); });

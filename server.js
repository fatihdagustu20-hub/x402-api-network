import express from 'express';
import dotenv from 'dotenv';
import dns from 'dns/promises';
import { URL } from 'url';
import QRCode from 'qrcode';
import { NodeHtmlMarkdown } from 'node-html-markdown';

dotenv.config();

const app = express();
app.use(express.json());

// Dynamic payment middleware wrapper — must be BEFORE route definitions
// so x402 can intercept requests and require payment
app.use((req, res, next) => {
  if (paymentMiddleware) {
    return paymentMiddleware(req, res, next);
  }
  next();
});

const PORT = process.env.PORT || 4021;
const WALLET = process.env.WALLET_ADDRESS;
const PRIVATE_KEY = process.env.WALLET_PRIVATE_KEY;
const NETWORK = process.env.NETWORK || 'eip155:8453';

// ============================================================
// x402 PAYMENT MIDDLEWARE
// ============================================================

let paymentMiddleware = null;

async function setupX402() {
  try {
    const { paymentMiddleware: pm, x402ResourceServer } = await import('@x402/express');
    const { ExactEvmScheme } = await import('@x402/evm/exact/server');
    const { bazaarResourceServerExtension, declareDiscoveryExtension } = await import('@x402/extensions');

    let facilitatorClient;
    const isTestnet = NETWORK.includes('84532') || NETWORK.includes('sepolia');

    if (isTestnet) {
      // Local facilitator for testnet — verifies and settles directly
      const { x402Facilitator } = await import('@x402/core/facilitator');
      const { registerExactEvmScheme: registerFacilitatorScheme } = await import('@x402/evm/exact/facilitator');
      const { createWalletClient, createPublicClient, http } = await import('viem');
      const { baseSepolia } = await import('viem/chains');
      const { privateKeyToAccount } = await import('viem/accounts');

      const account = privateKeyToAccount(PRIVATE_KEY);
      const walletClient = createWalletClient({ account, chain: baseSepolia, transport: http() });
      const publicClient = createPublicClient({ chain: baseSepolia, transport: http() });

      // Create a combined signer that has both wallet and public client methods
      const signer = {
        ...publicClient,
        ...walletClient,
        getAddresses: () => [account.address],
        verifyTypedData: (params) => publicClient.verifyTypedData(params),
        writeContract: (params) => walletClient.writeContract(params),
        sendTransaction: (params) => walletClient.sendTransaction(params),
        waitForTransactionReceipt: (params) => publicClient.waitForTransactionReceipt(params),
        readContract: (params) => publicClient.readContract(params),
        getCode: (params) => publicClient.getCode(params),
      };

      facilitatorClient = new x402Facilitator();
      registerFacilitatorScheme(facilitatorClient, {
        signer,
        networks: [NETWORK],
      });
      console.log('  🧪 Using LOCAL facilitator (testnet mode)');
    } else {
      // Remote CDP facilitator for mainnet
      const { HTTPFacilitatorClient } = await import('@x402/core/server');
      const { facilitator } = await import('@coinbase/x402');
      facilitatorClient = new HTTPFacilitatorClient(facilitator);
      console.log('  🏦 Using CDP facilitator (mainnet mode)');
    }

    const server = new x402ResourceServer(facilitatorClient)
      .register(NETWORK, new ExactEvmScheme())
      .registerExtension(bazaarResourceServerExtension);

    const routes = {};
    for (const [path, config] of Object.entries(API_ENDPOINTS)) {
      const bazaar = config.bazaar || {};
      routes[`GET ${path}`] = {
        accepts: [{
          scheme: 'exact',
          price: config.price,
          network: NETWORK,
          payTo: WALLET,
        }],
        description: config.description,
        mimeType: 'application/json',
        extensions: declareDiscoveryExtension({
          method: 'GET',
          input: bazaar.input || {},
          inputSchema: bazaar.inputSchema || { properties: {} },
          output: bazaar.output,
        }),
      };
    }
    for (const [path, config] of Object.entries(POST_ENDPOINTS)) {
      const bazaar = config.bazaar || {};
      routes[`POST ${path}`] = {
        accepts: [{
          scheme: 'exact',
          price: config.price,
          network: NETWORK,
          payTo: WALLET,
        }],
        description: config.description,
        mimeType: 'application/json',
        extensions: declareDiscoveryExtension({
          method: 'POST',
          bodyType: 'json',
          input: bazaar.input || {},
          inputSchema: bazaar.inputSchema || { properties: {} },
          output: bazaar.output,
        }),
      };
    }

    paymentMiddleware = pm(routes, server);
    console.log('✅ x402 payment middleware active (Bazaar discoverable)');
    return true;
  } catch (err) {
    console.warn('⚠️  x402 middleware not loaded (running in FREE mode):', err.message);
    return false;
  }
}

// ============================================================
// API ENDPOINT DEFINITIONS
// ============================================================

const BASE_URL = 'https://x402.fatihai.app';

const API_ENDPOINTS = {
  '/api/dns-lookup': {
    price: '$0.001',
    description: 'DNS record lookup for any domain. Returns A, AAAA, MX, TXT, NS records.',
    bazaar: {
      input: { domain: 'example.com' },
      inputSchema: { properties: { domain: { type: 'string', description: 'Domain name to lookup' } }, required: ['domain'] },
      output: { example: { domain: 'example.com', A: ['93.184.216.34'], MX: [{ exchange: 'mail.example.com', priority: 10 }] } },
    },
  },
  '/api/whois': {
    price: '$0.005',
    description: 'WHOIS domain information lookup. Returns registrar, creation date, expiry, nameservers.',
    bazaar: {
      input: { domain: 'example.com' },
      inputSchema: { properties: { domain: { type: 'string', description: 'Domain to query WHOIS' } }, required: ['domain'] },
      output: { example: { domain: 'example.com', whois: { registrar: 'IANA', creationDate: '1995-08-14' } } },
    },
  },
  '/api/ip-info': {
    price: '$0.001',
    description: 'IP reverse DNS lookup and type detection.',
    bazaar: {
      input: { ip: '8.8.8.8' },
      inputSchema: { properties: { ip: { type: 'string', description: 'IPv4 or IPv6 address' } }, required: ['ip'] },
      output: { example: { ip: '8.8.8.8', reverse_dns: ['dns.google'], type: 'IPv4' } },
    },
  },
  '/api/qr-code': {
    price: '$0.002',
    description: 'Generate QR code as base64 PNG for any text or URL.',
    bazaar: {
      input: { text: 'https://example.com', size: '256' },
      inputSchema: { properties: { text: { type: 'string', description: 'Text or URL to encode' }, size: { type: 'string', description: 'Image size in pixels (default 256)' } }, required: ['text'] },
      output: { example: { text: 'https://example.com', qr_base64: 'data:image/png;base64,...', size: 256 } },
    },
  },
  '/api/url-meta': {
    price: '$0.003',
    description: 'Extract metadata from any URL: title, description, og:image, favicon.',
    bazaar: {
      input: { url: 'https://example.com' },
      inputSchema: { properties: { url: { type: 'string', description: 'URL to extract metadata from' } }, required: ['url'] },
      output: { example: { url: 'https://example.com', title: 'Example Domain', description: 'An example website', og_image: null } },
    },
  },
  '/api/html-to-markdown': {
    price: '$0.002',
    description: 'Fetch any URL and convert its HTML content to clean Markdown.',
    bazaar: {
      input: { url: 'https://example.com' },
      inputSchema: { properties: { url: { type: 'string', description: 'URL to convert to Markdown' } }, required: ['url'] },
      output: { example: { url: 'https://example.com', markdown: '# Example Domain\n...', length: 150 } },
    },
  },
  '/api/ssl-check': {
    price: '$0.003',
    description: 'Check SSL/TLS certificate details for any domain.',
    bazaar: {
      input: { domain: 'example.com' },
      inputSchema: { properties: { domain: { type: 'string', description: 'Domain to check SSL cert' } }, required: ['domain'] },
      output: { example: { domain: 'example.com', valid: true, issuer: { O: 'DigiCert' }, valid_to: 'Mar 14 2026' } },
    },
  },
  '/api/http-headers': {
    price: '$0.001',
    description: 'Fetch and return HTTP response headers for any URL.',
    bazaar: {
      input: { url: 'https://example.com' },
      inputSchema: { properties: { url: { type: 'string', description: 'URL to fetch headers from' } }, required: ['url'] },
      output: { example: { url: 'https://example.com', status: 200, headers: { 'content-type': 'text/html' } } },
    },
  },
  '/api/password-strength': {
    price: '$0.001',
    description: 'Analyze password strength: score 0-8, level, and improvement suggestions.',
    bazaar: {
      input: { password: 'MyP@ssw0rd!' },
      inputSchema: { properties: { password: { type: 'string', description: 'Password to analyze' } }, required: ['password'] },
      output: { example: { score: 7, max_score: 8, level: 'strong', suggestions: [] } },
    },
  },
  '/api/text-stats': {
    price: '$0.001',
    description: 'Text analysis: word count, character count, reading time, sentence count.',
    bazaar: {
      input: { text: 'Hello world. This is a test.' },
      inputSchema: { properties: { text: { type: 'string', description: 'Text to analyze' } }, required: ['text'] },
      output: { example: { characters: 28, words: 6, sentences: 2, reading_time_minutes: 1 } },
    },
  },
  '/api/scrape': {
    price: '$0.01',
    description: 'Web scraping: fetch any URL and extract clean text, links, images, headings, and structured data.',
    bazaar: {
      input: { url: 'https://example.com' },
      inputSchema: { properties: { url: { type: 'string', description: 'URL to scrape' } }, required: ['url'] },
      output: { example: { url: 'https://example.com', title: 'Example', text: 'Clean text...', links_count: 5, images_count: 3 } },
    },
  },
};

const POST_ENDPOINTS = {
  '/api/json-format': {
    price: '$0.001',
    description: 'Format, validate, and minify JSON data.',
    bazaar: {
      input: { json: '{"key":"value"}', minify: false },
      inputSchema: { properties: { json: { type: 'string', description: 'JSON string or object to format' }, minify: { type: 'boolean', description: 'If true, minify instead of prettify' } }, required: ['json'] },
      output: { example: { valid: true, formatted: '{\n  "key": "value"\n}', size_bytes: 20 } },
    },
  },
  '/api/base64': {
    price: '$0.001',
    description: 'Encode or decode base64 strings.',
    bazaar: {
      input: { text: 'Hello World', action: 'encode' },
      inputSchema: { properties: { text: { type: 'string', description: 'Text to encode' }, encoded: { type: 'string', description: 'Base64 string to decode' }, action: { type: 'string', description: '"encode" or "decode"' } } },
      output: { example: { action: 'encode', result: 'SGVsbG8gV29ybGQ=' } },
    },
  },
  '/api/verify-email': {
    price: '$0.01',
    description: 'Email verification: syntax, MX records, disposable detection, role-based check, free provider detection. Returns score 0-100.',
    bazaar: {
      input: { email: 'user@example.com' },
      inputSchema: { properties: { email: { type: 'string', description: 'Email address to verify' } }, required: ['email'] },
      output: { example: { email: 'user@example.com', overall: 'valid', score: 100, checks: { syntax: { pass: true }, mx: { pass: true }, disposable: { pass: true } } } },
    },
  },
  '/api/domain-health': {
    price: '$0.01',
    description: 'Domain email health analysis: MX, SPF, DKIM, DMARC checks with score and actionable improvement tips.',
    bazaar: {
      input: { domain: 'example.com' },
      inputSchema: { properties: { domain: { type: 'string', description: 'Domain to check email health' } }, required: ['domain'] },
      output: { example: { domain: 'example.com', score: 85, overall: 'healthy', checks: [{ name: 'SPF', status: 'pass' }] } },
    },
  },
  '/api/ai-generate': {
    price: '$0.05',
    description: 'AI content generation powered by Llama 3.3 70B. Types: blog_post, product_description, email_copy, social_media, landing_page, seo_article.',
    bazaar: {
      input: { topic: 'AI in healthcare', type: 'blog_post', tone: 'professional', language: 'english', max_length: 1000 },
      inputSchema: { properties: { topic: { type: 'string', description: 'Content topic (required)' }, type: { type: 'string', description: 'blog_post|product_description|email_copy|social_media|landing_page|seo_article' }, tone: { type: 'string', description: 'Writing tone: professional, casual, exciting, formal' }, language: { type: 'string', description: 'Output language (default: english)' }, max_length: { type: 'number', description: 'Max word count (default 1000, max 4000)' } }, required: ['topic'] },
      output: { example: { type: 'blog_post', content: 'Generated content here...', word_count: 850, model: 'llama-3.3-70b' } },
    },
  },
};

// ============================================================
// FREE DISCOVERY ENDPOINTS (no payment needed)
// ============================================================

app.get('/', (req, res) => {
  const endpoints = {};
  for (const [path, config] of Object.entries(API_ENDPOINTS)) {
    endpoints[path] = { method: 'GET', price: config.price, description: config.description };
  }
  for (const [path, config] of Object.entries(POST_ENDPOINTS)) {
    endpoints[path] = { method: 'POST', price: config.price, description: config.description };
  }

  res.json({
    name: 'x402 API Network',
    version: '2.0.0',
    protocol: 'x402',
    network: NETWORK,
    wallet: WALLET,
    totalEndpoints: Object.keys(endpoints).length,
    endpoints,
    discovery: {
      well_known: `${BASE_URL}/.well-known/x402`,
      llms_txt: `${BASE_URL}/llms.txt`,
      bazaar: 'Discoverable via x402 Bazaar (CDP facilitator)',
    },
    docs: 'Send a request to any endpoint with x402 payment. Discovery via /.well-known/x402 or /llms.txt',
  });
});

// .well-known/x402 manifest — machine-readable API discovery for AI agents
app.get('/.well-known/x402', (req, res) => {
  const resources = [];

  for (const [path, config] of Object.entries(API_ENDPOINTS)) {
    const bazaar = config.bazaar || {};
    resources.push({
      url: `${BASE_URL}${path}`,
      method: 'GET',
      price: config.price,
      currency: 'USDC',
      network: NETWORK,
      payTo: WALLET,
      description: config.description,
      inputSchema: bazaar.inputSchema || null,
      outputExample: bazaar.output?.example || null,
    });
  }
  for (const [path, config] of Object.entries(POST_ENDPOINTS)) {
    const bazaar = config.bazaar || {};
    resources.push({
      url: `${BASE_URL}${path}`,
      method: 'POST',
      contentType: 'application/json',
      price: config.price,
      currency: 'USDC',
      network: NETWORK,
      payTo: WALLET,
      description: config.description,
      inputSchema: bazaar.inputSchema || null,
      outputExample: bazaar.output?.example || null,
    });
  }

  res.json({
    version: '1.0',
    protocol: 'x402',
    name: 'x402 API Network',
    description: 'Micropayment-powered API network for AI agents. Email verification, web scraping, AI content generation, DNS/SSL tools, and more. Pay per call with USDC on Base.',
    baseUrl: BASE_URL,
    network: NETWORK,
    payTo: WALLET,
    facilitator: 'https://api.cdp.coinbase.com/platform/v2/x402',
    totalResources: resources.length,
    resources,
  });
});

// llms.txt — AI crawler discovery
app.get('/llms.txt', (req, res) => {
  let txt = `# x402 API Network
> Micropayment-powered API network for AI agents. Pay per API call with USDC on Base L2.

## Base URL
${BASE_URL}

## Protocol
x402 (HTTP 402 Payment Required) — USDC micropayments on Base (eip155:8453)

## Discovery
- Machine-readable manifest: ${BASE_URL}/.well-known/x402
- Free discovery endpoint: ${BASE_URL}/
- Health check: ${BASE_URL}/health

## Available APIs

### High-Value APIs (Recommended)
`;

  const highValue = ['/api/verify-email', '/api/domain-health', '/api/scrape', '/api/ai-generate'];
  for (const path of highValue) {
    const config = POST_ENDPOINTS[path] || API_ENDPOINTS[path];
    if (config) {
      const method = POST_ENDPOINTS[path] ? 'POST' : 'GET';
      txt += `- [${method} ${path}](${BASE_URL}${path}): ${config.description} (${config.price}/call)\n`;
    }
  }

  txt += `\n### Utility APIs\n`;
  for (const [path, config] of Object.entries(API_ENDPOINTS)) {
    if (!highValue.includes(path)) {
      txt += `- [GET ${path}](${BASE_URL}${path}): ${config.description} (${config.price}/call)\n`;
    }
  }
  for (const [path, config] of Object.entries(POST_ENDPOINTS)) {
    if (!highValue.includes(path)) {
      txt += `- [POST ${path}](${BASE_URL}${path}): ${config.description} (${config.price}/call)\n`;
    }
  }

  txt += `\n## Payment
Wallet: ${WALLET}
Network: Base Mainnet (eip155:8453)
Currency: USDC
Facilitator: Coinbase CDP (https://api.cdp.coinbase.com/platform/v2/x402)

## How to Use
1. Send request to any endpoint
2. Receive HTTP 402 with payment requirements
3. Sign USDC payment with your wallet
4. Resend request with PAYMENT-SIGNATURE header
5. Receive API response
`;

  res.type('text/plain').send(txt);
});

// ============================================================
// API IMPLEMENTATIONS
// ============================================================

// 1. DNS Lookup
app.get('/api/dns-lookup', async (req, res) => {
  const { domain } = req.query;
  if (!domain) return res.status(400).json({ error: 'Missing ?domain= parameter' });

  try {
    const [a, aaaa, mx, txt, ns] = await Promise.allSettled([
      dns.resolve4(domain),
      dns.resolve6(domain),
      dns.resolveMx(domain),
      dns.resolveTxt(domain),
      dns.resolveNs(domain),
    ]);

    res.json({
      domain,
      A: a.status === 'fulfilled' ? a.value : [],
      AAAA: aaaa.status === 'fulfilled' ? aaaa.value : [],
      MX: mx.status === 'fulfilled' ? mx.value : [],
      TXT: txt.status === 'fulfilled' ? txt.value : [],
      NS: ns.status === 'fulfilled' ? ns.value : [],
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 2. WHOIS
app.get('/api/whois', async (req, res) => {
  const { domain } = req.query;
  if (!domain) return res.status(400).json({ error: 'Missing ?domain= parameter' });

  try {
    const whois = await import('whois-json');
    const result = await whois.default(domain);
    res.json({ domain, whois: result });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 3. IP Info
app.get('/api/ip-info', async (req, res) => {
  const { ip } = req.query;
  if (!ip) return res.status(400).json({ error: 'Missing ?ip= parameter' });

  try {
    const [reverse] = await Promise.allSettled([dns.reverse(ip)]);
    const hostnames = reverse.status === 'fulfilled' ? reverse.value : [];

    res.json({
      ip,
      reverse_dns: hostnames,
      type: ip.includes(':') ? 'IPv6' : 'IPv4',
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 4. QR Code
app.get('/api/qr-code', async (req, res) => {
  const { text, size } = req.query;
  if (!text) return res.status(400).json({ error: 'Missing ?text= parameter' });

  try {
    const qr = await QRCode.toDataURL(text, {
      width: parseInt(size) || 256,
      margin: 2,
    });
    res.json({ text, qr_base64: qr, size: parseInt(size) || 256 });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 5. URL Metadata
app.get('/api/url-meta', async (req, res) => {
  const { url } = req.query;
  if (!url) return res.status(400).json({ error: 'Missing ?url= parameter' });

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);

    const response = await fetch(url, {
      headers: { 'User-Agent': 'x402-api-bot/1.0' },
      signal: controller.signal,
    });
    clearTimeout(timeout);

    const html = await response.text();

    const getTag = (name, attr = 'content') => {
      const match = html.match(new RegExp(`<meta[^>]*(?:name|property)=["']${name}["'][^>]*${attr}=["']([^"']*)["']`, 'i'))
        || html.match(new RegExp(`<meta[^>]*${attr}=["']([^"']*)["'][^>]*(?:name|property)=["']${name}["']`, 'i'));
      return match ? match[1] : null;
    };

    const titleMatch = html.match(/<title[^>]*>([^<]*)<\/title>/i);

    res.json({
      url,
      status: response.status,
      title: titleMatch ? titleMatch[1].trim() : null,
      description: getTag('description') || getTag('og:description'),
      og_image: getTag('og:image'),
      og_title: getTag('og:title'),
      og_type: getTag('og:type'),
      favicon: new URL('/favicon.ico', url).href,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 6. HTML to Markdown
app.get('/api/html-to-markdown', async (req, res) => {
  const { url } = req.query;
  if (!url) return res.status(400).json({ error: 'Missing ?url= parameter' });

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);

    const response = await fetch(url, {
      headers: { 'User-Agent': 'x402-api-bot/1.0' },
      signal: controller.signal,
    });
    clearTimeout(timeout);

    const html = await response.text();
    const markdown = NodeHtmlMarkdown.translate(html);

    res.json({
      url,
      markdown: markdown.substring(0, 50000),
      length: markdown.length,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 7. SSL Check
app.get('/api/ssl-check', async (req, res) => {
  const { domain } = req.query;
  if (!domain) return res.status(400).json({ error: 'Missing ?domain= parameter' });

  try {
    const tls = await import('tls');
    const result = await new Promise((resolve, reject) => {
      const socket = tls.connect(443, domain, { servername: domain }, () => {
        const cert = socket.getPeerCertificate();
        socket.destroy();
        resolve({
          domain,
          valid: socket.authorized,
          issuer: cert.issuer,
          subject: cert.subject,
          valid_from: cert.valid_from,
          valid_to: cert.valid_to,
          serialNumber: cert.serialNumber,
          fingerprint: cert.fingerprint256,
        });
      });
      socket.on('error', reject);
      socket.setTimeout(10000, () => { socket.destroy(); reject(new Error('Timeout')); });
    });
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 8. HTTP Headers
app.get('/api/http-headers', async (req, res) => {
  const { url } = req.query;
  if (!url) return res.status(400).json({ error: 'Missing ?url= parameter' });

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);

    const response = await fetch(url, {
      method: 'HEAD',
      headers: { 'User-Agent': 'x402-api-bot/1.0' },
      signal: controller.signal,
    });
    clearTimeout(timeout);

    const headers = {};
    response.headers.forEach((value, key) => { headers[key] = value; });

    res.json({ url, status: response.status, headers });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 9. Password Strength
app.get('/api/password-strength', async (req, res) => {
  const { password } = req.query;
  if (!password) return res.status(400).json({ error: 'Missing ?password= parameter' });

  let score = 0;
  const suggestions = [];

  if (password.length >= 8) score++; else suggestions.push('Use at least 8 characters');
  if (password.length >= 12) score++; else suggestions.push('Use at least 12 characters');
  if (password.length >= 16) score++;
  if (/[a-z]/.test(password)) score++; else suggestions.push('Add lowercase letters');
  if (/[A-Z]/.test(password)) score++; else suggestions.push('Add uppercase letters');
  if (/[0-9]/.test(password)) score++; else suggestions.push('Add numbers');
  if (/[^a-zA-Z0-9]/.test(password)) score++; else suggestions.push('Add special characters');
  if (!/(.)\1{2,}/.test(password)) score++; else suggestions.push('Avoid repeated characters');

  const levels = ['very_weak', 'weak', 'fair', 'good', 'strong', 'very_strong'];
  const level = levels[Math.min(Math.floor(score / 1.5), 5)];

  res.json({
    score,
    max_score: 8,
    level,
    length: password.length,
    suggestions,
  });
});

// 10. Text Stats
app.get('/api/text-stats', async (req, res) => {
  const { text } = req.query;
  if (!text) return res.status(400).json({ error: 'Missing ?text= parameter' });

  const words = text.trim().split(/\s+/).filter(w => w.length > 0);
  const sentences = text.split(/[.!?]+/).filter(s => s.trim().length > 0);
  const paragraphs = text.split(/\n\n+/).filter(p => p.trim().length > 0);

  res.json({
    characters: text.length,
    characters_no_spaces: text.replace(/\s/g, '').length,
    words: words.length,
    sentences: sentences.length,
    paragraphs: paragraphs.length,
    reading_time_minutes: Math.ceil(words.length / 200),
    speaking_time_minutes: Math.ceil(words.length / 130),
  });
});

// 11. JSON Format (POST)
app.post('/api/json-format', (req, res) => {
  const { json, minify } = req.body;
  if (!json) return res.status(400).json({ error: 'Missing "json" in body' });

  try {
    const parsed = typeof json === 'string' ? JSON.parse(json) : json;
    const formatted = minify
      ? JSON.stringify(parsed)
      : JSON.stringify(parsed, null, 2);

    res.json({
      valid: true,
      formatted,
      size_bytes: Buffer.byteLength(formatted),
    });
  } catch (err) {
    res.json({ valid: false, error: err.message });
  }
});

// 12. Base64 Encode/Decode (POST)
app.post('/api/base64', (req, res) => {
  const { text, encoded, action } = req.body;

  if (action === 'decode' && encoded) {
    try {
      const decoded = Buffer.from(encoded, 'base64').toString('utf-8');
      res.json({ action: 'decode', result: decoded });
    } catch (err) {
      res.status(400).json({ error: 'Invalid base64' });
    }
  } else if (text) {
    const result = Buffer.from(text).toString('base64');
    res.json({ action: 'encode', result });
  } else {
    res.status(400).json({ error: 'Provide "text" to encode or "encoded"+"action":"decode" to decode' });
  }
});

// 13. Email Verification (POST)
const DISPOSABLE_DOMAINS = new Set([
  'mailinator.com', 'guerrillamail.com', 'tempmail.com', 'throwaway.email',
  'yopmail.com', 'sharklasers.com', 'guerrillamailblock.com', 'grr.la',
  'dispostable.com', 'mailnesia.com', 'maildrop.cc', 'discard.email',
  'trashmail.com', 'trashmail.net', 'temp-mail.org', 'fakeinbox.com',
  'tempail.com', 'tempr.email', 'emailondeck.com', 'mintemail.com',
  'mohmal.com', 'mailcatch.com', 'nada.email', 'getnada.com',
  'tmpmail.net', 'mailsac.com', 'harakirimail.com', 'jetable.org',
  'spam4.me', 'trash-mail.com', 'mailexpire.com', 'tempinbox.com',
  'getairmail.com', 'mailnull.com', 'tmail.ws', 'crazymailing.com',
  'armyspy.com', 'dayrep.com', 'guerrillamail.info', 'guerrillamail.net',
]);

const ROLE_ADDRESSES = new Set([
  'info', 'admin', 'support', 'sales', 'contact', 'help', 'service',
  'billing', 'abuse', 'postmaster', 'webmaster', 'hostmaster', 'noreply',
  'no-reply', 'mailer-daemon', 'marketing', 'office', 'team', 'hr',
  'jobs', 'careers', 'press', 'media', 'security', 'legal', 'feedback',
]);

const FREE_PROVIDERS = new Set([
  'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 'aol.com',
  'icloud.com', 'mail.com', 'protonmail.com', 'zoho.com', 'yandex.com',
  'gmx.com', 'gmx.net', 'live.com', 'msn.com', 'me.com', 'mac.com',
  'fastmail.com', 'tutanota.com', 'pm.me', 'hey.com', 'proton.me',
  'yandex.ru', 'mail.ru', 'web.de', 'laposte.net', 'orange.fr',
]);

app.post('/api/verify-email', async (req, res) => {
  const { email: rawEmail } = req.body;
  if (!rawEmail) return res.status(400).json({ error: 'Missing "email" in body' });

  const email = rawEmail.trim().toLowerCase();
  const regex = /^[a-z0-9!#$%&'*+/=?^_`{|}~.-]+@[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/;

  if (!regex.test(email) || email.length > 254) {
    return res.json({
      email, overall: 'invalid', score: 0,
      checks: { syntax: { pass: false, message: 'Invalid email format' }, mx: { pass: false }, disposable: { pass: true }, roleBased: { pass: true }, freeProvider: { value: false } },
    });
  }

  const [local, domain] = email.split('@');

  let hasMx = false;
  let mxRecords = [];
  try {
    const records = await dns.resolveMx(domain);
    hasMx = records.length > 0;
    mxRecords = records.sort((a, b) => a.priority - b.priority).map(r => `${r.exchange} (priority: ${r.priority})`);
  } catch {}

  const isDisposable = DISPOSABLE_DOMAINS.has(domain);
  const isRoleBased = ROLE_ADDRESSES.has(local);
  const isFreeProvider = FREE_PROVIDERS.has(domain);

  let score = 0;
  let overall = 'valid';
  if (regex.test(email)) score += 25;
  if (hasMx) score += 35;
  if (!isDisposable) score += 20;
  if (!isRoleBased) score += 10;
  if (!isFreeProvider) score += 10;
  if (!hasMx) { overall = 'invalid'; score = Math.min(score, 25); }
  else if (isDisposable) { overall = 'invalid'; score = Math.min(score, 20); }
  else if (isRoleBased || isFreeProvider) overall = 'risky';

  res.json({
    email, overall, score,
    checks: {
      syntax: { pass: true, message: 'Valid email format' },
      mx: { pass: hasMx, message: hasMx ? `MX records found for ${domain}` : `No MX records for ${domain}`, records: mxRecords },
      disposable: { pass: !isDisposable, message: isDisposable ? 'Disposable email detected' : 'Not a disposable email' },
      roleBased: { pass: !isRoleBased, message: isRoleBased ? `"${local}@" is a role-based address` : 'Not a role-based address' },
      freeProvider: { value: isFreeProvider, message: isFreeProvider ? `${domain} is a free email provider` : `${domain} is a business/custom domain` },
    },
  });
});

// 14. Domain Health Check (POST)
app.post('/api/domain-health', async (req, res) => {
  let { domain } = req.body;
  if (!domain) return res.status(400).json({ error: 'Missing "domain" in body' });

  domain = domain.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/^www\./, '');
  if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(domain)) {
    return res.status(400).json({ error: 'Invalid domain format' });
  }

  const resolve = async (type) => {
    try {
      switch (type) {
        case 'MX': return (await dns.resolveMx(domain)).sort((a, b) => a.priority - b.priority).map(r => `${r.exchange} (priority: ${r.priority})`);
        case 'TXT': return (await dns.resolveTxt(domain)).map(r => r.join(''));
        case 'A': return await dns.resolve4(domain);
        case 'AAAA': return await dns.resolve6(domain);
        case 'NS': return await dns.resolveNs(domain);
        default: return [];
      }
    } catch { return []; }
  };

  const [mxRecords, txtRecords, aRecords, aaaaRecords, nsRecords] = await Promise.all([
    resolve('MX'), resolve('TXT'), resolve('A'), resolve('AAAA'), resolve('NS'),
  ]);

  const checks = [];
  let score = 0;

  // MX
  if (mxRecords.length > 0) { score += 25; checks.push({ name: 'MX Records', status: 'pass', message: `${mxRecords.length} MX record(s) found`, details: mxRecords }); }
  else checks.push({ name: 'MX Records', status: 'fail', message: 'No MX records found', details: [], tip: 'Add MX records to receive email.' });

  // SPF
  const spfRecord = txtRecords.find(r => r.startsWith('v=spf1'));
  if (spfRecord) {
    if (spfRecord.includes('-all')) { score += 20; checks.push({ name: 'SPF', status: 'pass', message: 'SPF with hard fail (-all)', details: [spfRecord] }); }
    else if (spfRecord.includes('~all')) { score += 15; checks.push({ name: 'SPF', status: 'warning', message: 'SPF with soft fail (~all)', details: [spfRecord], tip: 'Consider -all for stricter enforcement.' }); }
    else { score += 10; checks.push({ name: 'SPF', status: 'warning', message: 'SPF found but weak policy', details: [spfRecord] }); }
  } else checks.push({ name: 'SPF', status: 'fail', message: 'No SPF record', details: [], tip: 'Add TXT: v=spf1 include:your-esp.com -all' });

  // DKIM
  const dkimSelectors = ['google', 'default', 'selector1', 'selector2', 'k1', 's1', 'mail', 'dkim'];
  const foundDkim = [];
  for (const sel of dkimSelectors) {
    try {
      const recs = await dns.resolveTxt(`${sel}._domainkey.${domain}`);
      if (recs.length > 0) foundDkim.push(`${sel}._domainkey.${domain}`);
    } catch {}
  }
  if (foundDkim.length > 0) { score += 20; checks.push({ name: 'DKIM', status: 'pass', message: `${foundDkim.length} DKIM selector(s) found`, details: foundDkim }); }
  else checks.push({ name: 'DKIM', status: 'warning', message: 'No common DKIM selectors found', details: [], tip: 'Set up DKIM with your email provider.' });

  // DMARC
  let dmarcRecords = [];
  try { dmarcRecords = (await dns.resolveTxt(`_dmarc.${domain}`)).map(r => r.join('')); } catch {}
  const dmarcRecord = dmarcRecords.find(r => r.startsWith('v=DMARC1'));
  if (dmarcRecord) {
    if (dmarcRecord.includes('p=reject')) { score += 20; checks.push({ name: 'DMARC', status: 'pass', message: 'DMARC with reject policy', details: [dmarcRecord] }); }
    else if (dmarcRecord.includes('p=quarantine')) { score += 15; checks.push({ name: 'DMARC', status: 'warning', message: 'DMARC with quarantine policy', details: [dmarcRecord] }); }
    else { score += 8; checks.push({ name: 'DMARC', status: 'warning', message: 'DMARC monitoring only (p=none)', details: [dmarcRecord] }); }
  } else checks.push({ name: 'DMARC', status: 'fail', message: 'No DMARC record', details: [], tip: 'Add TXT at _dmarc.domain: v=DMARC1; p=quarantine' });

  // DNS Resolution
  if (aRecords.length > 0 || aaaaRecords.length > 0) { score += 10; checks.push({ name: 'DNS', status: 'pass', message: 'Domain resolves', details: [...aRecords.map(r => `A: ${r}`), ...aaaaRecords.map(r => `AAAA: ${r}`)] }); }
  else checks.push({ name: 'DNS', status: 'fail', message: 'Domain does not resolve', details: [] });

  if (nsRecords.length > 0) { score += 5; checks.push({ name: 'Nameservers', status: 'pass', message: `${nsRecords.length} NS`, details: nsRecords }); }

  score = Math.min(100, score);
  let overall = 'healthy';
  if (score < 40) overall = 'critical';
  else if (score < 70) overall = 'needs-work';

  res.json({ domain, score, overall, checks });
});

// 15. Web Scraping (GET)
app.get('/api/scrape', async (req, res) => {
  const { url, selector } = req.query;
  if (!url) return res.status(400).json({ error: 'Missing ?url= parameter' });

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15000);

    const response = await fetch(url, {
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; x402-scraper/1.0)' },
      signal: controller.signal,
      redirect: 'follow',
    });
    clearTimeout(timeout);

    const html = await response.text();

    // Title
    const titleMatch = html.match(/<title[^>]*>([^<]*)<\/title>/i);
    const title = titleMatch ? titleMatch[1].trim() : null;

    // Meta description
    const descMatch = html.match(/<meta[^>]*name=["']description["'][^>]*content=["']([^"']*)["']/i)
      || html.match(/<meta[^>]*content=["']([^"']*)["'][^>]*name=["']description["']/i);
    const description = descMatch ? descMatch[1] : null;

    // Extract all links
    const linkRegex = /<a[^>]+href=["']([^"'#][^"']*)["'][^>]*>([^<]*)</gi;
    const links = [];
    let linkMatch;
    while ((linkMatch = linkRegex.exec(html)) !== null && links.length < 100) {
      const href = linkMatch[1];
      const text = linkMatch[2].trim();
      if (href && !href.startsWith('javascript:')) {
        try { links.push({ url: new URL(href, url).href, text }); } catch {}
      }
    }

    // Extract images
    const imgRegex = /<img[^>]+src=["']([^"']+)["'][^>]*(?:alt=["']([^"']*)["'])?/gi;
    const images = [];
    let imgMatch;
    while ((imgMatch = imgRegex.exec(html)) !== null && images.length < 50) {
      try { images.push({ url: new URL(imgMatch[1], url).href, alt: imgMatch[2] || '' }); } catch {}
    }

    // Clean text extraction
    const cleanHtml = html
      .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '')
      .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '')
      .replace(/<nav[^>]*>[\s\S]*?<\/nav>/gi, '')
      .replace(/<footer[^>]*>[\s\S]*?<\/footer>/gi, '')
      .replace(/<header[^>]*>[\s\S]*?<\/header>/gi, '')
      .replace(/<[^>]+>/g, ' ')
      .replace(/&nbsp;/g, ' ')
      .replace(/&amp;/g, '&')
      .replace(/&lt;/g, '<')
      .replace(/&gt;/g, '>')
      .replace(/\s+/g, ' ')
      .trim();

    // H1-H6 headings
    const headingRegex = /<h([1-6])[^>]*>([^<]*)<\/h\1>/gi;
    const headings = [];
    let headMatch;
    while ((headMatch = headingRegex.exec(html)) !== null && headings.length < 30) {
      headings.push({ level: parseInt(headMatch[1]), text: headMatch[2].trim() });
    }

    res.json({
      url,
      status: response.status,
      title,
      description,
      text: cleanHtml.substring(0, 50000),
      text_length: cleanHtml.length,
      headings,
      links_count: links.length,
      links: links.slice(0, 50),
      images_count: images.length,
      images: images.slice(0, 20),
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 16. AI Content Generation (POST)
const GROQ_API_KEY = process.env.GROQ_API_KEY;

app.post('/api/ai-generate', async (req, res) => {
  const { type, topic, tone, language, max_length } = req.body;
  if (!topic) return res.status(400).json({ error: 'Missing "topic" in body' });
  if (!GROQ_API_KEY) return res.status(503).json({ error: 'AI provider not configured' });

  const contentType = type || 'blog_post';
  const contentTone = tone || 'professional';
  const contentLang = language || 'english';
  const maxLen = Math.min(max_length || 1000, 4000);

  const prompts = {
    blog_post: `Write a blog post about: ${topic}\nTone: ${contentTone}\nLanguage: ${contentLang}\nLength: approximately ${maxLen} words.\nInclude a compelling title, introduction, 3-5 sections with subheadings, and a conclusion.`,
    product_description: `Write a product description for: ${topic}\nTone: ${contentTone}\nLanguage: ${contentLang}\nLength: approximately ${maxLen} words.\nInclude key features, benefits, and a call to action.`,
    email_copy: `Write a marketing email about: ${topic}\nTone: ${contentTone}\nLanguage: ${contentLang}\nLength: approximately ${maxLen} words.\nInclude a subject line, preview text, body with clear CTA.`,
    social_media: `Write 5 social media posts about: ${topic}\nTone: ${contentTone}\nLanguage: ${contentLang}\nInclude hashtags and emojis. Format for Twitter/LinkedIn.`,
    landing_page: `Write landing page copy for: ${topic}\nTone: ${contentTone}\nLanguage: ${contentLang}\nLength: approximately ${maxLen} words.\nInclude headline, subheadline, benefits, social proof section, and CTA.`,
    seo_article: `Write an SEO-optimized article about: ${topic}\nTone: ${contentTone}\nLanguage: ${contentLang}\nLength: approximately ${maxLen} words.\nInclude meta title, meta description, headers with keywords, and natural keyword placement.`,
  };

  const prompt = prompts[contentType] || prompts.blog_post;

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 60000);

    const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${GROQ_API_KEY}`,
      },
      body: JSON.stringify({
        model: 'llama-3.3-70b-versatile',
        messages: [
          { role: 'system', content: 'You are a professional content writer. Write high-quality, engaging content. Output only the content, no meta-commentary.' },
          { role: 'user', content: prompt },
        ],
        max_tokens: Math.min(maxLen * 2, 8000),
        temperature: 0.7,
      }),
      signal: controller.signal,
    });
    clearTimeout(timeout);

    if (!response.ok) {
      const errBody = await response.text();
      return res.status(502).json({ error: `AI provider error: ${response.status}`, details: errBody });
    }

    const data = await response.json();
    const content = data.choices?.[0]?.message?.content || '';
    const words = content.trim().split(/\s+/).length;

    res.json({
      type: contentType,
      topic,
      tone: contentTone,
      language: contentLang,
      content,
      word_count: words,
      model: 'llama-3.3-70b',
      tokens_used: data.usage?.total_tokens || 0,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// HEALTH CHECK
// ============================================================

app.get('/health', (req, res) => {
  res.json({ status: 'ok', uptime: process.uptime(), endpoints: Object.keys(API_ENDPOINTS).length + Object.keys(POST_ENDPOINTS).length });
});

// ============================================================
// START SERVER
// ============================================================

async function main() {
  // Try to load x402 payment middleware
  const x402Active = await setupX402();

  if (x402Active && paymentMiddleware) {
    console.log(`💰 x402 payments active on ${NETWORK}`);
    console.log(`💳 Payments go to: ${WALLET}`);
  } else {
    console.log('🆓 Running in FREE mode (x402 middleware not loaded)');
  }

  app.listen(PORT, () => {
    console.log(`\n🚀 x402 API Network running on port ${PORT}`);
    console.log(`📡 ${Object.keys(API_ENDPOINTS).length + Object.keys(POST_ENDPOINTS).length} API endpoints available`);
    console.log(`🌐 Discovery: http://localhost:${PORT}/`);
    console.log(`❤️  Health: http://localhost:${PORT}/health\n`);
  });
}

main();

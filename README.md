# x402 API Network

Micropayment-powered API network for AI agents. Pay per API call with USDC on Base L2.

Built with the [x402 protocol](https://www.x402.org/) — HTTP 402 Payment Required.

## Live API

**Base URL:** `https://x402.fatihai.app`

**Discovery:**
- `GET /` — Free endpoint listing
- `GET /.well-known/x402` — Machine-readable manifest
- `GET /llms.txt` — AI crawler discovery
- `GET /health` — Health check

## Available APIs (16 endpoints)

### High-Value APIs

| Endpoint | Method | Price | Description |
|----------|--------|-------|-------------|
| `/api/verify-email` | POST | $0.01 | Email verification: syntax, MX, disposable, role-based, scoring 0-100 |
| `/api/domain-health` | POST | $0.01 | Domain email health: MX, SPF, DKIM, DMARC analysis |
| `/api/scrape` | GET | $0.01 | Web scraping: text, links, images, headings extraction |
| `/api/ai-generate` | POST | $0.05 | AI content generation (Llama 3.3 70B): blog, email, social, SEO |

### Utility APIs

| Endpoint | Method | Price | Description |
|----------|--------|-------|-------------|
| `/api/dns-lookup` | GET | $0.001 | DNS records (A, AAAA, MX, TXT, NS) |
| `/api/whois` | GET | $0.005 | WHOIS domain information |
| `/api/ip-info` | GET | $0.001 | IP reverse DNS and type detection |
| `/api/qr-code` | GET | $0.002 | QR code generation (base64 PNG) |
| `/api/url-meta` | GET | $0.003 | URL metadata extraction (title, OG tags) |
| `/api/html-to-markdown` | GET | $0.002 | HTML to Markdown conversion |
| `/api/ssl-check` | GET | $0.003 | SSL/TLS certificate details |
| `/api/http-headers` | GET | $0.001 | HTTP response headers |
| `/api/password-strength` | GET | $0.001 | Password strength analysis |
| `/api/text-stats` | GET | $0.001 | Text word/sentence/reading time stats |
| `/api/json-format` | POST | $0.001 | JSON formatting and validation |
| `/api/base64` | POST | $0.001 | Base64 encode/decode |

## How It Works

1. Send a request to any API endpoint
2. Receive HTTP 402 with payment requirements in headers
3. Sign a USDC micropayment with your wallet (Base L2)
4. Resend request with `PAYMENT-SIGNATURE` header
5. Receive API response

## Payment Details

- **Network:** Base Mainnet (EIP-155:8453)
- **Currency:** USDC
- **Facilitator:** Coinbase CDP
- **Gas fees:** ~$0.0001 per transaction

## Quick Start

### For AI Agents (x402 client)

```javascript
import { x402Client } from '@x402/core/client';

const client = new x402Client({
  privateKey: '0xYourPrivateKey',
  network: 'eip155:8453',
});

const result = await client.get('https://x402.fatihai.app/api/dns-lookup?domain=google.com');
console.log(result);
```

### MCP Integration (Claude Desktop)

See `claude-desktop-config.example.json` for Claude Desktop MCP integration.

### Direct curl (free mode / development)

```bash
# Email verification
curl -X POST https://x402.fatihai.app/api/verify-email \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com"}'

# AI content generation
curl -X POST https://x402.fatihai.app/api/ai-generate \
  -H "Content-Type: application/json" \
  -d '{"topic":"AI micropayments","type":"blog_post"}'

# Web scraping
curl "https://x402.fatihai.app/api/scrape?url=https://example.com"
```

## Self-Hosting

```bash
git clone https://github.com/user/x402-api-network.git
cd x402-api-network
npm install
cp .env.example .env  # Configure wallet and CDP keys
npm start
```

### Environment Variables

| Variable | Description |
|----------|-------------|
| `PORT` | Server port (default: 4021) |
| `WALLET_ADDRESS` | Your EVM wallet address (receives payments) |
| `WALLET_PRIVATE_KEY` | Wallet private key |
| `CDP_API_KEY_ID` | Coinbase Developer Platform API key ID |
| `CDP_API_KEY_SECRET` | CDP API key secret |
| `NETWORK` | Chain ID (default: eip155:8453 for Base) |
| `GROQ_API_KEY` | Groq API key for AI content generation |

## Architecture

```
x402 API Network
├── server.js            # Express server + x402 middleware + 16 API handlers
├── mcp-server.js        # MCP server for Claude Desktop integration
├── .well-known/x402     # Machine-readable discovery manifest
├── /llms.txt            # AI crawler discovery
└── /health              # Health check endpoint
```

## Discovery

This API is discoverable via:
- **x402 Bazaar** — CDP facilitator's `/discovery/resources` endpoint
- **`.well-known/x402`** — Standard machine-readable manifest
- **`llms.txt`** — AI search engine optimization
- **DNS TXT** — `_x402.x402.fatihai.app` discovery record
- **MCP** — Model Context Protocol server for Claude/ChatGPT

## License

MIT

#!/usr/bin/env node

/**
 * x402 API Network — MCP Server
 *
 * Exposes all x402 API endpoints as MCP tools for AI agents.
 * Uses stdio transport for Claude Desktop / ChatGPT MCP integration.
 *
 * Usage:  node mcp-server.js
 *
 * The server calls the local x402 API at http://localhost:4021
 * (bypassing x402 payment for local/internal use).
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const API_BASE = process.env.X402_API_BASE || 'http://localhost:4021';
const PUBLIC_BASE = 'https://x402.fatihai.app';
const REQUEST_TIMEOUT_MS = 30_000;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Makes an HTTP request to the local x402 API server.
 * GET endpoints pass params as query string; POST endpoints send JSON body.
 */
async function callApi(method, path, params) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  try {
    let url = `${API_BASE}${path}`;
    const options = {
      method,
      headers: { 'User-Agent': 'x402-mcp-server/1.0' },
      signal: controller.signal,
    };

    if (method === 'GET' && params) {
      const qs = new URLSearchParams();
      for (const [k, v] of Object.entries(params)) {
        if (v !== undefined && v !== null && v !== '') {
          qs.set(k, String(v));
        }
      }
      const qsStr = qs.toString();
      if (qsStr) url += `?${qsStr}`;
    }

    if (method === 'POST' && params) {
      options.headers['Content-Type'] = 'application/json';
      options.body = JSON.stringify(params);
    }

    const response = await fetch(url, options);
    const data = await response.json();

    if (!response.ok) {
      return { isError: true, content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    }

    return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
  } catch (err) {
    return {
      isError: true,
      content: [{ type: 'text', text: `Error calling ${method} ${path}: ${err.message}` }],
    };
  } finally {
    clearTimeout(timeout);
  }
}

// ---------------------------------------------------------------------------
// Create MCP Server
// ---------------------------------------------------------------------------

const server = new McpServer(
  {
    name: 'x402-api-network',
    version: '1.0.0',
  },
  {
    capabilities: {
      tools: {},
    },
    instructions: [
      'x402 API Network MCP Server — provides 16 utility and AI tools.',
      'All tools call the x402 API at ' + PUBLIC_BASE,
      '',
      'Available tool categories:',
      '  DNS & Domain: dns_lookup, whois, ssl_check, domain_health',
      '  Web: url_meta, html_to_markdown, http_headers, scrape',
      '  IP & Network: ip_info',
      '  Utilities: qr_code, password_strength, text_stats, json_format, base64',
      '  Email: verify_email',
      '  AI: ai_generate',
    ].join('\n'),
  },
);

// =====================================================================
// GET ENDPOINT TOOLS
// =====================================================================

// 1. DNS Lookup
server.tool(
  'dns_lookup',
  'Look up DNS records (A, AAAA, MX, TXT, NS) for a domain. Returns all available record types.',
  { domain: z.string().describe('Domain name to look up, e.g. "example.com"') },
  async ({ domain }) => callApi('GET', '/api/dns-lookup', { domain }),
);

// 2. WHOIS
server.tool(
  'whois',
  'Perform a WHOIS lookup for a domain. Returns registrar, creation date, expiry, nameservers, and other registration details.',
  { domain: z.string().describe('Domain name to query, e.g. "example.com"') },
  async ({ domain }) => callApi('GET', '/api/whois', { domain }),
);

// 3. IP Info
server.tool(
  'ip_info',
  'Get information about an IP address: reverse DNS hostnames and IPv4/IPv6 type detection.',
  { ip: z.string().describe('IPv4 or IPv6 address, e.g. "8.8.8.8"') },
  async ({ ip }) => callApi('GET', '/api/ip-info', { ip }),
);

// 4. QR Code
server.tool(
  'qr_code',
  'Generate a QR code as a base64-encoded PNG image. Accepts any text or URL.',
  {
    text: z.string().describe('Text or URL to encode into a QR code'),
    size: z.number().optional().default(256).describe('Image size in pixels (default 256)'),
  },
  async ({ text, size }) => callApi('GET', '/api/qr-code', { text, size }),
);

// 5. URL Metadata
server.tool(
  'url_meta',
  'Extract metadata from a URL: page title, meta description, Open Graph image, OG title, OG type, and favicon URL.',
  { url: z.string().describe('Full URL to extract metadata from, e.g. "https://example.com"') },
  async ({ url }) => callApi('GET', '/api/url-meta', { url }),
);

// 6. HTML to Markdown
server.tool(
  'html_to_markdown',
  'Fetch a web page and convert its HTML content to clean Markdown text. Useful for reading web pages in a text-friendly format.',
  { url: z.string().describe('URL of the web page to convert, e.g. "https://example.com"') },
  async ({ url }) => callApi('GET', '/api/html-to-markdown', { url }),
);

// 7. SSL Check
server.tool(
  'ssl_check',
  'Check SSL/TLS certificate details for a domain: validity, issuer, subject, expiry dates, serial number, and fingerprint.',
  { domain: z.string().describe('Domain to check SSL certificate for, e.g. "example.com"') },
  async ({ domain }) => callApi('GET', '/api/ssl-check', { domain }),
);

// 8. HTTP Headers
server.tool(
  'http_headers',
  'Fetch and return the HTTP response headers for any URL. Useful for debugging CORS, caching, security headers, and content types.',
  { url: z.string().describe('URL to fetch headers from, e.g. "https://example.com"') },
  async ({ url }) => callApi('GET', '/api/http-headers', { url }),
);

// 9. Password Strength
server.tool(
  'password_strength',
  'Analyze the strength of a password. Returns a score (0-8), strength level, length, and improvement suggestions.',
  { password: z.string().describe('Password string to analyze') },
  async ({ password }) => callApi('GET', '/api/password-strength', { password }),
);

// 10. Text Stats
server.tool(
  'text_stats',
  'Analyze text and return statistics: character count, word count, sentence count, paragraph count, estimated reading time, and speaking time.',
  { text: z.string().describe('Text to analyze') },
  async ({ text }) => callApi('GET', '/api/text-stats', { text }),
);

// 11. Web Scrape
server.tool(
  'scrape',
  'Scrape a web page and extract structured data: clean text content, page title, meta description, headings, links, and images.',
  { url: z.string().describe('URL of the web page to scrape, e.g. "https://example.com"') },
  async ({ url }) => callApi('GET', '/api/scrape', { url }),
);

// =====================================================================
// POST ENDPOINT TOOLS
// =====================================================================

// 12. JSON Format
server.tool(
  'json_format',
  'Format, validate, and optionally minify JSON data. Accepts a JSON string or object and returns prettified (or minified) output with byte size.',
  {
    json: z.string().describe('JSON string to format and validate'),
    minify: z.boolean().optional().default(false).describe('If true, minify instead of prettify'),
  },
  async ({ json, minify }) => callApi('POST', '/api/json-format', { json, minify }),
);

// 13. Base64 Encode/Decode
server.tool(
  'base64',
  'Encode text to base64, or decode a base64 string back to text.',
  {
    action: z.enum(['encode', 'decode']).describe('"encode" to convert text to base64, or "decode" to convert base64 back to text'),
    text: z.string().optional().describe('Text to encode (required when action is "encode")'),
    encoded: z.string().optional().describe('Base64 string to decode (required when action is "decode")'),
  },
  async ({ action, text, encoded }) => callApi('POST', '/api/base64', { action, text, encoded }),
);

// 14. Email Verification
server.tool(
  'verify_email',
  'Verify an email address: syntax validation, MX record check, disposable email detection, role-based address check, and free provider detection. Returns a score from 0-100.',
  { email: z.string().describe('Email address to verify, e.g. "user@example.com"') },
  async ({ email }) => callApi('POST', '/api/verify-email', { email }),
);

// 15. Domain Health
server.tool(
  'domain_health',
  'Comprehensive domain email health analysis: checks MX records, SPF, DKIM, DMARC, and DNS resolution. Returns a score (0-100) with actionable improvement tips.',
  { domain: z.string().describe('Domain to check email health for, e.g. "example.com"') },
  async ({ domain }) => callApi('POST', '/api/domain-health', { domain }),
);

// 16. AI Content Generation
server.tool(
  'ai_generate',
  'Generate AI-powered content using Llama 3.3 70B. Supports blog posts, product descriptions, email copy, social media posts, landing page copy, and SEO articles.',
  {
    topic: z.string().describe('The content topic (required). Be specific for best results.'),
    type: z.enum([
      'blog_post',
      'product_description',
      'email_copy',
      'social_media',
      'landing_page',
      'seo_article',
    ]).optional().default('blog_post').describe('Content type to generate'),
    tone: z.string().optional().default('professional').describe('Writing tone: professional, casual, exciting, formal, etc.'),
    language: z.string().optional().default('english').describe('Output language (e.g. "english", "turkish", "spanish")'),
    max_length: z.number().optional().default(1000).describe('Maximum word count (default 1000, max 4000)'),
  },
  async ({ topic, type, tone, language, max_length }) =>
    callApi('POST', '/api/ai-generate', { topic, type, tone, language, max_length }),
);

// =====================================================================
// Start Server
// =====================================================================

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);

  // Log to stderr so it does not interfere with the stdio JSON-RPC protocol on stdout
  console.error('x402 API Network MCP server started (stdio transport)');
  console.error(`API base: ${API_BASE}`);
  console.error('16 tools registered');
}

main().catch((err) => {
  console.error('Fatal error starting MCP server:', err);
  process.exit(1);
});

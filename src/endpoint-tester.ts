import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ErrorCode,
  ListToolsRequestSchema,
  McpError,
} from '@modelcontextprotocol/sdk/types.js';
import {
  analyzeJavaScript,
  discoverHistoricalEndpoints,
  discoverSubdomains,
  extractJavaScriptFiles,
  fuzzEndpoint,
} from './utils.js';
import { TestOptions, TestResult, SensitiveDataFinding, SecurityFlaw } from './types.js';
import fetch, { Response as FetchResponse } from 'node-fetch';
import * as tls from 'tls';
import * as fs from 'fs';
import * as path from 'path';
import { parse } from 'csv-parse/sync';
import * as XLSX from 'xlsx';
import { Parser as XmlParser } from 'xml2js';

async function parseDocument(filePath: string): Promise<string> {
  const ext = path.extname(filePath).toLowerCase();
  const content = await fs.promises.readFile(filePath);

  switch (ext) {
    case '.csv': {
      const parsedRecords = parse(content.toString(), {
        delimiter: ',',
        trim: true,
        columns: true
      });
      
      const formattedRecords = (parsedRecords as any[]).map(record => 
        Object.values(record).join(' ')
      );
      
      return formattedRecords.join('\n');
    }

    case '.xlsx':
    case '.xls':
      const workbook = XLSX.read(content);
      return workbook.SheetNames
        .map((name: string) => XLSX.utils.sheet_to_csv(workbook.Sheets[name]))
        .join('\n');

    case '.xml':
      const parser = new XmlParser();
      const result = await parser.parseStringPromise(content);
      return JSON.stringify(result, null, 2);

    case '.pdf':
      return '[PDF Document]';

    case '.log':
      return content.toString();

    default:
      return content.toString();
  }
}

async function checkTlsConfiguration(hostname: string): Promise<TestResult> {
  try {
    const socket = tls.connect({
      host: hostname,
      port: 443,
      rejectUnauthorized: false
    });

    return new Promise((resolve) => {
      socket.on('secureConnect', () => {
        const cert = socket.getPeerCertificate();
        const protocol = socket.getProtocol() || undefined;
        const ciphers = socket.getCipher();

        socket.end();

        const result: TestResult = {
          test: 'TLS Configuration',
          details: protocol ? `Protocol: ${protocol}` : undefined,
          warning: protocol && ['TLSv1', 'TLSv1.1'].includes(protocol) ? 
            `Weak TLS protocol detected: ${protocol}` : undefined
        };

        if (cert && cert.valid_to) {
          const validTo = new Date(cert.valid_to);
          const daysUntilExpiry = Math.floor((validTo.getTime() - Date.now()) / (1000 * 60 * 60 * 24));
          if (daysUntilExpiry < 30) {
            result.warning = `Certificate expires in ${daysUntilExpiry} days`;
          }
        }

        resolve(result);
      });

      socket.on('error', (error) => {
        resolve({
          test: 'TLS Configuration',
          error: error.message
        });
      });
    });
  } catch (error) {
    return {
      test: 'TLS Configuration',
      error: error instanceof Error ? error.message : 'Unknown error'
    };
  }
}

async function testRateLimiting(url: string, headers?: Record<string, string>): Promise<TestResult[]> {
  const results: TestResult[] = [];
  const requests = 50;
  const concurrency = 10;
  const batches = Math.ceil(requests / concurrency);
  let rateLimited = false;

  for (let i = 0; i < batches && !rateLimited; i++) {
    const batchPromises = Array(Math.min(concurrency, requests - i * concurrency))
      .fill(0)
      .map(() => fetch(url, { headers }));

    const batchResponses = await Promise.all(batchPromises.map(p => p.catch(e => e)));
    
    for (const response of batchResponses) {
      if (response instanceof Error) continue;
      
      if (response.status === 429) {
        rateLimited = true;
        const retryAfter = response.headers.get('Retry-After');
        
        results.push({
          test: 'Rate Limiting',
          status: 'pass',
          details: `Rate limiting detected after ${i * concurrency + batchResponses.indexOf(response)} requests`,
          headers: {
            'Retry-After': retryAfter || 'Not specified'
          }
        });
        
        break;
      }
    }
  }

  if (!rateLimited) {
    results.push({
      test: 'Rate Limiting',
      status: 'warning',
      details: `No rate limiting detected after ${requests} requests`
    });
  }

  return results;
}

async function testJWTToken(token: string): Promise<TestResult> {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) {
      return {
        test: 'JWT Analysis',
        valid: false,
        error: 'Invalid JWT format'
      };
    }

    interface JWTHeader {
      alg: string;
      typ?: string;
    }

    interface JWTPayload {
      exp?: number;
      [key: string]: any;
    }

    const [header, payload] = parts.slice(0, 2).map(part => 
      JSON.parse(Buffer.from(part, 'base64').toString())
    ) as [JWTHeader, JWTPayload];

    const warnings: string[] = [];

    // Check algorithm
    if (header.alg === 'none' || header.alg === 'HS256') {
      warnings.push(`Weak algorithm detected: ${header.alg}`);
    }

    // Check expiration
    if (payload.exp) {
      const expiryDate = new Date(payload.exp * 1000);
      if (expiryDate < new Date()) {
        warnings.push('Token has expired');
      }
    } else {
      warnings.push('No expiration claim (exp) found');
    }

    // Check for sensitive information in payload
    const sensitiveFields = ['password', 'secret', 'key', 'token'];
    const foundSensitive = sensitiveFields.filter(field => 
      Object.keys(payload).some(key => 
        key.toLowerCase().includes(field)
      )
    );

    if (foundSensitive.length > 0) {
      warnings.push(`Potentially sensitive data in claims: ${foundSensitive.join(', ')}`);
    }

    return {
      test: 'JWT Analysis',
      valid: true,
      details: `Algorithm: ${header.alg}`,
      warning: warnings.length > 0 ? warnings.join('; ') : undefined
    };
  } catch (error) {
    return {
      test: 'JWT Analysis',
      valid: false,
      error: error instanceof Error ? error.message : 'Unknown error'
    };
  }
}

async function testGraphQLEndpoint(url: string, headers?: Record<string, string>): Promise<TestResult[]> {
  const results: TestResult[] = [];

  // Test 1: Introspection Query
  const introspectionQuery = `
    query {
      __schema {
        types {
          name
          fields {
            name
            type {
              name
            }
          }
        }
      }
    }
  `;

  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        ...headers,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ query: introspectionQuery })
    });

    const data = await response.json() as any;
    
    results.push({
      test: "GraphQL Introspection",
      enabled: !!data.data?.__schema,
      warning: data.data?.__schema ? 
        "GraphQL introspection is enabled - consider disabling in production" : 
        undefined
    });
  } catch (error) {
    results.push({
      test: "GraphQL Introspection",
      error: error instanceof Error ? error.message : "Unknown error"
    });
  }

  // Test 2: Batch Query Attack
  const batchQuery = Array(100).fill({ query: '{ __typename }' });
  
  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        ...headers,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(batchQuery)
    });

    results.push({
      test: "GraphQL Batch Query Protection",
      status: response.status,
      warning: response.status === 200 ? 
        "Batch queries are allowed - consider limiting or disabling" : 
        undefined
    });
  } catch (error) {
    results.push({
      test: "GraphQL Batch Query Protection",
      error: error instanceof Error ? error.message : "Unknown error"
    });
  }

  return results;
}

async function detectSensitiveData(responseBody: string): Promise<SensitiveDataFinding[]> {
  const findings: SensitiveDataFinding[] = [];
  
  const patterns = [
    {
      type: 'Email',
      pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
      severity: 'medium' as const
    },
    {
      type: 'API Key',
      pattern: /(['"]?(?:api[_-]?key|token|secret)['"]\s*[:=]\s*['"])[a-zA-Z0-9_\-\.]+(['"]\s*[,}])/gi,
      severity: 'high' as const
    },
    {
      type: 'Credit Card',
      pattern: /\b(?:\d[ -]*?){13,16}\b/g,
      severity: 'high' as const
    },
    {
      type: 'Password',
      pattern: /(['"]?password['"]?\s*[:=]\s*['"])[^'"]+(['"])/gi,
      severity: 'high' as const
    },
    {
      type: 'Private Key',
      pattern: /-----BEGIN [A-Z ]+ PRIVATE KEY-----[^-]+-----END [A-Z ]+ PRIVATE KEY-----/g,
      severity: 'high' as const
    }
  ];

  for (const { type, pattern, severity } of patterns) {
    const matches = responseBody.matchAll(pattern);
    for (const match of matches) {
      findings.push({
        type,
        location: `offset ${match.index}`,
        preview: match[0].substring(0, 50) + (match[0].length > 50 ? '...' : ''),
        severity
      });
    }
  }

  return findings;
}

async function detectSecurityFlaws(response: FetchResponse, url: string): Promise<SecurityFlaw[]> {
  const flaws: SecurityFlaw[] = [];

  // Check for sensitive headers exposure
  const sensitiveHeaders = ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-Runtime'];
  for (const header of sensitiveHeaders) {
    if (response.headers.has(header)) {
      flaws.push({
        type: 'Information Disclosure',
        description: `Sensitive header '${header}' exposed`,
        severity: 'medium',
        recommendation: `Remove or mask the ${header} header`,
        evidence: `${header}: ${response.headers.get(header)}`
      });
    }
  }

  // Check for missing security headers
  const requiredHeaders = [
    'Content-Security-Policy',
    'X-Content-Type-Options',
    'X-Frame-Options',
    'Strict-Transport-Security'
  ];
  
  for (const header of requiredHeaders) {
    if (!response.headers.has(header)) {
      flaws.push({
        type: 'Missing Security Header',
        description: `Required security header '${header}' is missing`,
        severity: 'medium',
        recommendation: `Add the ${header} header with appropriate values`
      });
    }
  }

  // Check for insecure protocol
  if (url.startsWith('http://')) {
    flaws.push({
      type: 'Insecure Protocol',
      description: 'Connection is not using HTTPS',
      severity: 'high',
      recommendation: 'Enable HTTPS and redirect all HTTP traffic to HTTPS'
    });
  }

  return flaws;
}

export async function testEndpoint(
  url: string,
  method: string,
  headers?: Record<string, string>,
  body?: string,
  options: TestOptions = {}
): Promise<TestResult[]> {
  const results: TestResult[] = [];
  
  const urlObj = new URL(url);
  
  // Basic Request Testing
  try {
    const response = await fetch(url, {
      method,
      headers: headers || {},
      body,
    });

    const responseHeaders: Record<string, string> = {};
    response.headers.forEach((value, key) => {
      responseHeaders[key] = value;
    });

    const responseBody = await response.text();
    const securityFlaws = await detectSecurityFlaws(response, url);
    const sensitiveData = await detectSensitiveData(responseBody);

    const result: TestResult = {
      test: "Basic Request",
      status: response.status,
      headers: responseHeaders,
      securityFlaws,
      sensitiveData
    };

    if (options.includeResponseBody) {
      result.responseBody = responseBody;
    }

    if (sensitiveData.length > 0) {
      result.requiresUserApproval = true;
      result.warning = `Found ${sensitiveData.length} instances of sensitive data. Use extractData option to analyze.`;
    }

    if (options.extractData && sensitiveData.length > 0) {
      result.extractedData = {
        sensitiveDataCount: sensitiveData.length,
        findings: sensitiveData,
        foundData: options.extractData ? sensitiveData.map(finding => finding.preview) : undefined
      };
    }

    results.push(result);

    // Security Headers Check
    const securityHeaders = [
      'Strict-Transport-Security',
      'X-Content-Type-Options',
      'X-Frame-Options',
      'Content-Security-Policy',
      'X-XSS-Protection'
    ];

    const missingHeaders = securityHeaders.filter(header => !response.headers.has(header));
    if (missingHeaders.length > 0) {
      results.push({
        test: "Security Headers",
        status: "warning",
        details: `Missing recommended security headers: ${missingHeaders.join(', ')}`
      });
    }

    // CORS Check
    const corsHeaders = [
      'Access-Control-Allow-Origin',
      'Access-Control-Allow-Methods',
      'Access-Control-Allow-Headers'
    ];

    const corsConfig = corsHeaders.reduce((acc, header) => {
      acc[header] = response.headers.get(header) || undefined;
      return acc;
    }, {} as Record<string, string | undefined>);

    results.push({
      test: "CORS Configuration",
      configuration: corsConfig,
      warning: corsConfig['Access-Control-Allow-Origin'] === '*' ?
        "Wildcard CORS policy detected - consider restricting to specific origins" : 
        undefined
    });

  } catch (error) {
    results.push({
      test: "Basic Request Failed",
      error: error instanceof Error ? error.message : "Unknown error",
    });
  }

  // Additional Tests
  try {
    // 1. TLS Configuration
    const tlsResults = await checkTlsConfiguration(urlObj.hostname);
    results.push(tlsResults);

    // 2. Rate Limiting
    const rateLimitResults = await testRateLimiting(url, headers);
    results.push(...rateLimitResults);

    // 3. JWT Analysis if token provided
    if (headers?.['Authorization']?.startsWith('Bearer ')) {
      const token = headers['Authorization'].split(' ')[1];
      const jwtResults = await testJWTToken(token);
      results.push(jwtResults);
    }

    // 4. GraphQL Testing
    if (options.isGraphQL) {
      const graphqlResults = await testGraphQLEndpoint(url, headers);
      results.push(...graphqlResults);
    }

  } catch (error) {
    results.push({
      test: "Advanced Tests Failed",
      error: error instanceof Error ? error.message : "Unknown error",
    });
  }

  return results;
}

class ApiSecurityTester {
  private server: Server;

  constructor() {
    this.server = new Server(
      {
        name: 'api-security-tester',
        version: '0.1.0',
      },
      {
        capabilities: {
          tools: {},
        },
      }
    );

    this.setupToolHandlers();
    
    this.server.onerror = (error) => console.error('[MCP Error]', error);
    process.on('SIGINT', async () => {
      await this.server.close();
      process.exit(0);
    });
  }

  private setupToolHandlers() {
    this.server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: [
        {
          name: 'test-endpoint',
          description: 'Comprehensive security test of an API endpoint',
          inputSchema: {
            type: 'object',
            properties: {
              url: {
                type: 'string',
                description: 'The URL of the API endpoint to test'
              },
              method: {
                type: 'string',
                enum: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
                description: 'HTTP method to use'
              },
              headers: {
                type: 'object',
                additionalProperties: { type: 'string' },
                description: 'Request headers to include'
              },
              body: {
                type: 'string',
                description: 'Request body (for POST/PUT/PATCH requests)'
              },
              authToken: {
                type: 'string',
                description: 'Optional authentication token'
              },
              isGraphQL: {
                type: 'boolean',
                description: 'Whether the endpoint is a GraphQL API'
              },
              performanceTest: {
                type: 'boolean',
                description: 'Whether to perform load testing'
              },
              performanceTestDuration: {
                type: 'number',
                description: 'Duration of performance test in seconds'
              },
              validateSchema: {
                type: 'boolean',
                description: 'Whether to validate against OpenAPI/Swagger schema'
              },
              scanDocs: {
                type: 'boolean',
                description: 'Whether to scan for exposed API documentation'
              },
              extractData: {
                type: 'boolean',
                description: 'Whether to extract and analyze sensitive data found in responses',
                default: false
              },
              includeResponseBody: {
                type: 'boolean',
                description: 'Whether to include full response body in results',
                default: false
              },
              sensitiveDataPatterns: {
                type: 'array',
                items: {
                  type: 'object',
                  properties: {
                    pattern: { type: 'string' },
                    type: { type: 'string' },
                    severity: { 
                      type: 'string',
                      enum: ['low', 'medium', 'high']
                    }
                  }
                },
                description: 'Custom patterns for sensitive data detection'
              }
            },
            required: ['url', 'method']
          }
        },
        {
          name: 'extract-js',
          description: 'Extract and analyze JavaScript files from a domain',
          inputSchema: {
            type: 'object',
            properties: {
              domain: {
                type: 'string',
                description: 'Domain to scan for JavaScript files'
              },
              recursive: {
                type: 'boolean',
                description: 'Whether to recursively follow links',
                default: false
              }
            },
            required: ['domain']
          }
        },
        {
          name: 'analyze-js',
          description: 'Extract endpoints and sensitive information from JavaScript files',
          inputSchema: {
            type: 'object',
            properties: {
              url: {
                type: 'string',
                description: 'URL of the JavaScript file to analyze'
              }
            },
            required: ['url']
          }
        },
        {
          name: 'historical-endpoints',
          description: 'Discover historical endpoints from various sources',
          inputSchema: {
            type: 'object',
            properties: {
              domain: {
                type: 'string',
                description: 'Domain to search for historical endpoints'
              },
              sources: {
                type: 'array',
                items: {
                  type: 'string',
                  enum: ['wayback', 'commoncrawl', 'alienvault']
                },
                description: 'Sources to search (wayback, commoncrawl, alienvault)'
              }
            },
            required: ['domain']
          }
        },
        {
          name: 'subdomain-scan',
          description: 'Discover subdomains using various techniques',
          inputSchema: {
            type: 'object',
            properties: {
              domain: {
                type: 'string',
                description: 'Domain to scan for subdomains'
              },
              techniques: {
                type: 'array',
                items: {
                  type: 'string',
                  enum: ['dns', 'certificates', 'archives']
                },
                description: 'Techniques to use for discovery'
              }
            },
            required: ['domain']
          }
        },
        {
          name: 'fuzzing-scan',
          description: 'Perform fuzzing tests on endpoints',
          inputSchema: {
            type: 'object',
            properties: {
              url: {
                type: 'string',
                description: 'Base URL to fuzz'
              },
              wordlist: {
                type: 'string',
                description: 'Wordlist to use for fuzzing',
                enum: ['common', 'api', 'security', 'full']
              },
              concurrent: {
                type: 'number',
                description: 'Number of concurrent requests',
                default: 10
              }
            },
            required: ['url', 'wordlist']
          }
        }
      ]
    }));

    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      try {
        switch (request.params.name) {
          case 'test-endpoint': {
            const { url, method, headers, body, ...options } = request.params.arguments as {
              url: string;
              method: string;
              headers?: Record<string, string>;
              body?: string;
              [key: string]: any;
            };

            const results = await testEndpoint(url, method, headers, body, options);
            return {
              content: [
                {
                  type: 'text',
                  text: JSON.stringify(results, null, 2)
                }
              ]
            };
          }

          case 'extract-js': {
            const { domain, recursive = false } = request.params.arguments as { domain: string; recursive?: boolean };
            const files = await extractJavaScriptFiles(domain, recursive);
            return {
              content: [
                {
                  type: 'text',
                  text: JSON.stringify({ files }, null, 2)
                }
              ]
            };
          }

          case 'analyze-js': {
            const { url } = request.params.arguments as { url: string };
            const analysis = await analyzeJavaScript(url);
            return {
              content: [
                {
                  type: 'text',
                  text: JSON.stringify(analysis, null, 2)
                }
              ]
            };
          }

          case 'historical-endpoints': {
            const { domain, sources } = request.params.arguments as { domain: string; sources?: string[] };
            const endpoints = await discoverHistoricalEndpoints(domain, sources);
            return {
              content: [
                {
                  type: 'text',
                  text: JSON.stringify({ endpoints }, null, 2)
                }
              ]
            };
          }

          case 'subdomain-scan': {
            const { domain, techniques } = request.params.arguments as { domain: string; techniques?: string[] };
            const subdomains = await discoverSubdomains(domain, techniques);
            return {
              content: [
                {
                  type: 'text',
                  text: JSON.stringify({ subdomains }, null, 2)
                }
              ]
            };
          }

          case 'fuzzing-scan': {
            const { url, wordlist, concurrent = 10 } = request.params.arguments as {
              url: string;
              wordlist: string;
              concurrent?: number;
            };
            const results = await fuzzEndpoint(url, wordlist, concurrent);
            return {
              content: [
                {
                  type: 'text',
                  text: JSON.stringify({ results }, null, 2)
                }
              ]
            };
          }

          default:
            throw new McpError(
              ErrorCode.MethodNotFound,
              `Unknown tool: ${request.params.name}`
            );
        }
      } catch (error) {
        return {
          content: [
            {
              type: 'text',
              text: `Error: ${error instanceof Error ? error.message : 'Unknown error'}`
            }
          ],
          isError: true
        };
      }
    });
  }

  async run() {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    console.error('API Security Tester MCP server running on stdio');
  }
}

const server = new ApiSecurityTester();
server.run().catch(console.error);

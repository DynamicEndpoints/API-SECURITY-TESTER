# API Security Tester MCP Server

An MCP server that provides tools for comprehensive API security testing and analysis.

## Features

- Comprehensive API endpoint security testing
- JavaScript file analysis for endpoints and sensitive information
- Historical endpoint discovery
- Subdomain scanning
- API fuzzing capabilities
- GraphQL security testing
- TLS configuration analysis
- Rate limiting detection
- JWT token analysis
- Security headers validation
- CORS configuration checking

## Installation

```bash
npm install
```

## Usage

Build the project:
```bash
npm run build
```

Start the server:
```bash
npm start
```

## Available Tools

### test-endpoint
Test an API endpoint for various security concerns:
```typescript
{
  url: string;
  method: string;
  headers?: Record<string, string>;
  body?: string;
  isGraphQL?: boolean;
  performanceTest?: boolean;
  performanceTestDuration?: number;
  validateSchema?: boolean;
  scanDocs?: boolean;
  reverseEngineer?: boolean;
  crawlDepth?: number;
}
```

### extract-js
Extract JavaScript files from a domain:
```typescript
{
  domain: string;
  recursive?: boolean;
}
```

### analyze-js
Analyze JavaScript files for endpoints and sensitive information:
```typescript
{
  url: string;
}
```

### historical-endpoints
Discover historical endpoints from various sources:
```typescript
{
  domain: string;
  sources?: string[]; // ['wayback', 'commoncrawl', 'alienvault']
}
```

### subdomain-scan
Discover subdomains using various techniques:
```typescript
{
  domain: string;
  techniques?: string[]; // ['dns', 'certificates', 'archives']
}
```

### fuzzing-scan
Perform fuzzing tests on endpoints:
```typescript
{
  url: string;
  wordlist: string; // 'common', 'api', 'security', 'full'
  concurrent?: number;
}
```

## Development

Run in development mode with watch mode enabled:
```bash
npm run dev

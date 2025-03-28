import fetch from 'node-fetch';
import { JSDOM } from 'jsdom';
import * as esprima from 'esprima';
import * as estraverse from 'estraverse';
import * as escodegen from 'escodegen';

export async function extractJavaScriptFiles(domain: string, recursive = false): Promise<string[]> {
  const jsFiles: Set<string> = new Set();
  const visited: Set<string> = new Set();

  async function crawl(url: string) {
    if (visited.has(url)) return;
    visited.add(url);

    try {
      const response = await fetch(url);
      const html = await response.text();
      const dom = new JSDOM(html);
      const scripts = dom.window.document.getElementsByTagName('script');

      for (const script of scripts) {
        const src = script.getAttribute('src');
        if (src) {
          const scriptUrl = new URL(src, url).toString();
          if (scriptUrl.startsWith(domain)) {
            jsFiles.add(scriptUrl);
          }
        }
      }

      if (recursive) {
        const links = dom.window.document.getElementsByTagName('a');
        for (const link of links) {
          const href = link.getAttribute('href');
          if (href) {
            const linkUrl = new URL(href, url).toString();
            if (linkUrl.startsWith(domain)) {
              await crawl(linkUrl);
            }
          }
        }
      }
    } catch (error) {
      console.error(`Error crawling ${url}:`, error);
    }
  }

  await crawl(`https://${domain}`);
  return Array.from(jsFiles);
}

interface JsAnalysisResult {
  endpoints: string[];
  sensitiveData: {
    type: string;
    location: string;
    value?: string;
  }[];
}

export async function analyzeJavaScript(url: string): Promise<JsAnalysisResult> {
  const endpoints: string[] = [];
  const sensitiveData: JsAnalysisResult['sensitiveData'] = [];

  try {
    const response = await fetch(url);
    const code = await response.text();
    const ast = esprima.parseScript(code);

    estraverse.traverse(ast, {
      enter(node: any) {
        // Find API endpoints
        if (
          node.type === 'Literal' &&
          typeof node.value === 'string' &&
          (node.value.startsWith('/api/') || node.value.includes('/v1/') || node.value.includes('/v2/'))
        ) {
          endpoints.push(node.value);
        }

        // Find potential hardcoded secrets
        if (
          node.type === 'VariableDeclarator' &&
          node.id.type === 'Identifier' &&
          /key|token|secret|password|api|auth/i.test(node.id.name)
        ) {
          sensitiveData.push({
            type: 'Variable',
            location: node.id.name,
            value: node.init ? escodegen.generate(node.init) : undefined
          });
        }

        // Find sensitive object properties
        if (
          node.type === 'Property' &&
          node.key.type === 'Identifier' &&
          /key|token|secret|password|api|auth/i.test(node.key.name)
        ) {
          sensitiveData.push({
            type: 'Property',
            location: node.key.name,
            value: node.value ? escodegen.generate(node.value) : undefined
          });
        }
      }
    });
  } catch (error) {
    console.error(`Error analyzing JavaScript at ${url}:`, error);
  }

  return {
    endpoints: Array.from(new Set(endpoints)),
    sensitiveData
  };
}

export async function discoverHistoricalEndpoints(
  domain: string,
  sources: string[] = ['wayback', 'commoncrawl', 'alienvault']
): Promise<string[]> {
  const endpoints: Set<string> = new Set();

  for (const source of sources) {
    try {
      switch (source) {
        case 'wayback':
          const waybackUrl = `https://web.archive.org/cdx/search/cdx?url=${domain}/*&output=json&fl=original`;
          const waybackResponse = await fetch(waybackUrl);
          const waybackData = await waybackResponse.json() as string[][];
          waybackData.slice(1).forEach(([url]) => {
            if (url.includes('/api/') || url.includes('/v1/') || url.includes('/v2/')) {
              endpoints.add(url);
            }
          });
          break;

        case 'commoncrawl':
          const ccUrl = `https://index.commoncrawl.org/CC-MAIN-2023-14-index?url=${domain}/*&output=json`;
          const ccResponse = await fetch(ccUrl);
          const ccText = await ccResponse.text();
          ccText.split('\\n').forEach(line => {
            try {
              const data = JSON.parse(line);
              if (data.url.includes('/api/') || data.url.includes('/v1/') || data.url.includes('/v2/')) {
                endpoints.add(data.url);
              }
            } catch {}
          });
          break;

        case 'alienvault':
          const otxUrl = `https://otx.alienvault.com/api/v1/indicators/domain/${domain}/url_list`;
          const otxResponse = await fetch(otxUrl);
          const otxData = await otxResponse.json() as { url_list: { url: string }[] };
          otxData.url_list.forEach(({ url }) => {
            if (url.includes('/api/') || url.includes('/v1/') || url.includes('/v2/')) {
              endpoints.add(url);
            }
          });
          break;
      }
    } catch (error) {
      console.error(`Error with ${source}:`, error);
    }
  }

  return Array.from(endpoints);
}

export async function discoverSubdomains(
  domain: string,
  techniques: string[] = ['dns', 'certificates', 'archives']
): Promise<string[]> {
  const subdomains: Set<string> = new Set();

  for (const technique of techniques) {
    try {
      switch (technique) {
        case 'dns':
          // Basic DNS enumeration using common subdomains
          const commonSubdomains = ['api', 'dev', 'staging', 'test', 'admin', 'portal', 'docs'];
          for (const sub of commonSubdomains) {
            try {
              const url = `https://${sub}.${domain}`;
              await fetch(url);
              subdomains.add(`${sub}.${domain}`);
            } catch {}
          }
          break;

        case 'certificates':
          // Query crt.sh for SSL certificate history
          const crtshUrl = `https://crt.sh/?q=${domain}&output=json`;
          const crtshResponse = await fetch(crtshUrl);
          const crtshData = await crtshResponse.json() as { name_value: string }[];
          crtshData.forEach(({ name_value }) => {
            if (name_value.endsWith(domain)) {
              subdomains.add(name_value);
            }
          });
          break;

        case 'archives':
          // Check web archives for historical subdomains
          const archiveUrl = `https://web.archive.org/cdx/search/cdx?url=*.${domain}&output=json&fl=original`;
          const archiveResponse = await fetch(archiveUrl);
          const archiveData = await archiveResponse.json() as string[][];
          archiveData.slice(1).forEach(([url]) => {
            try {
              const { hostname } = new URL(url);
              if (hostname.endsWith(domain)) {
                subdomains.add(hostname);
              }
            } catch {}
          });
          break;
      }
    } catch (error) {
      console.error(`Error with ${technique}:`, error);
    }
  }

  return Array.from(subdomains);
}

export async function fuzzEndpoint(
  url: string,
  wordlist: string,
  concurrent = 10
): Promise<{ url: string; status: number; responseTime: number }[]> {
  const results: { url: string; status: number; responseTime: number }[] = [];
  const words = await loadWordlist(wordlist);
  const baseUrl = new URL(url);

  const queue = words.map(word => ({
    url: new URL(word, baseUrl).toString(),
    word
  }));

  while (queue.length > 0) {
    const batch = queue.splice(0, concurrent);
    const promises = batch.map(async ({ url }) => {
      const start = Date.now();
      try {
        const response = await fetch(url);
        const responseTime = Date.now() - start;
        return {
          url,
          status: response.status,
          responseTime
        };
      } catch {
        return null;
      }
    });

    const batchResults = await Promise.all(promises);
    results.push(...batchResults.filter((r): r is NonNullable<typeof r> => r !== null));
  }

  return results;
}

async function loadWordlist(type: string): Promise<string[]> {
  // In a real implementation, these would be loaded from files
  const wordlists: Record<string, string[]> = {
    common: [
      'admin', 'api', 'login', 'user', 'users', 'auth',
      'register', 'signup', 'signin', 'logout', 'profile',
      'settings', 'config', 'status', 'health', 'metrics'
    ],
    api: [
      'v1', 'v2', 'v3', 'graphql', 'rest', 'swagger',
      'docs', 'openapi', 'schema', 'query', 'mutation'
    ],
    security: [
      'backup', 'dev', 'test', 'staging', 'prod',
      'internal', 'admin', 'console', 'dashboard'
    ],
    full: [] // Would combine all lists plus additional words
  };

  return wordlists[type] || wordlists.common;
}

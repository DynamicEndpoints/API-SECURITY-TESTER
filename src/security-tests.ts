import fetch from 'node-fetch';
import { TestResult } from './types.js';

export async function testXssProtection(url: string): Promise<TestResult> {
  const xssPayloads = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    '"><img src=x onerror=alert(1)>',
    '{{constructor.constructor("alert(1)")()}}'
  ];

  try {
    const results = await Promise.all(
      xssPayloads.map(async payload => {
        const response = await fetch(`${url}?q=${encodeURIComponent(payload)}`);
        const text = await response.text();
        return text.includes(payload);
      })
    );

    const vulnerable = results.some(result => result);

    return {
      test: 'XSS Protection',
      status: vulnerable ? 'fail' : 'pass',
      details: vulnerable ? 
        'Potential XSS vulnerability detected - payload was reflected in response' :
        'No obvious XSS vulnerabilities detected'
    };
  } catch (error) {
    return {
      test: 'XSS Protection',
      error: error instanceof Error ? error.message : 'Unknown error'
    };
  }
}

export async function testSqlInjection(url: string): Promise<TestResult> {
  const sqlPayloads = [
    "' OR '1'='1",
    "'; DROP TABLE users--",
    "' UNION SELECT NULL--",
    "admin' --"
  ];

  try {
    const results = await Promise.all(
      sqlPayloads.map(async payload => {
        const response = await fetch(`${url}?q=${encodeURIComponent(payload)}`);
        const text = await response.text();
        return {
          status: response.status,
          text
        };
      })
    );

    const suspicious = results.some(
      result => 
        result.status === 500 || 
        result.text.toLowerCase().includes('sql') ||
        result.text.toLowerCase().includes('database error')
    );

    return {
      test: 'SQL Injection Protection',
      status: suspicious ? 'warning' : 'pass',
      details: suspicious ?
        'Potential SQL injection vulnerability - suspicious error responses detected' :
        'No obvious SQL injection vulnerabilities detected'
    };
  } catch (error) {
    return {
      test: 'SQL Injection Protection',
      error: error instanceof Error ? error.message : 'Unknown error'
    };
  }
}

export async function testNoSqlInjection(url: string): Promise<TestResult> {
  const noSqlPayloads = [
    '{"$gt": ""}',
    '{"$where": "sleep(1000)"}',
    '{"$regex": ".*"}',
    '{"$ne": null}'
  ];

  try {
    const results = await Promise.all(
      noSqlPayloads.map(async payload => {
        const response = await fetch(`${url}?q=${encodeURIComponent(payload)}`);
        const text = await response.text();
        return {
          status: response.status,
          text
        };
      })
    );

    const suspicious = results.some(
      result => 
        result.status === 500 || 
        result.text.toLowerCase().includes('mongo') ||
        result.text.toLowerCase().includes('database error')
    );

    return {
      test: 'NoSQL Injection Protection',
      status: suspicious ? 'warning' : 'pass',
      details: suspicious ?
        'Potential NoSQL injection vulnerability - suspicious error responses detected' :
        'No obvious NoSQL injection vulnerabilities detected'
    };
  } catch (error) {
    return {
      test: 'NoSQL Injection Protection',
      error: error instanceof Error ? error.message : 'Unknown error'
    };
  }
}

export async function testSsrf(url: string): Promise<TestResult> {
  const ssrfPayloads = [
    'http://localhost/',
    'http://127.0.0.1/',
    'http://[::1]/',
    'file:///etc/passwd',
    'dict://localhost:11211/'
  ];

  try {
    const results = await Promise.all(
      ssrfPayloads.map(async payload => {
        const response = await fetch(`${url}?url=${encodeURIComponent(payload)}`);
        return {
          status: response.status,
          headers: response.headers
        };
      })
    );

    const suspicious = results.some(
      result => 
        result.status === 200 || 
        result.headers.get('content-type')?.includes('text/plain')
    );

    return {
      test: 'SSRF Protection',
      status: suspicious ? 'warning' : 'pass',
      details: suspicious ?
        'Potential SSRF vulnerability - successful internal URL access detected' :
        'No obvious SSRF vulnerabilities detected'
    };
  } catch (error) {
    return {
      test: 'SSRF Protection',
      error: error instanceof Error ? error.message : 'Unknown error'
    };
  }
}

export async function testOpenRedirect(url: string): Promise<TestResult> {
  const redirectPayloads = [
    'https://evil.com',
    '//evil.com',
    '\\\\evil.com',
    'javascript:alert(1)'
  ];

  try {
    const results = await Promise.all(
      redirectPayloads.map(async payload => {
        const response = await fetch(`${url}?redirect=${encodeURIComponent(payload)}`, {
          redirect: 'manual'
        });
        return {
          status: response.status,
          location: response.headers.get('location')
        };
      })
    );

    const vulnerable = results.some(
      result => 
        (result.status === 301 || result.status === 302) &&
        result.location &&
        redirectPayloads.some(payload => 
          result.location?.toLowerCase().includes(payload.toLowerCase())
        )
    );

    return {
      test: 'Open Redirect Protection',
      status: vulnerable ? 'fail' : 'pass',
      details: vulnerable ?
        'Open redirect vulnerability detected - external redirects possible' :
        'No obvious open redirect vulnerabilities detected'
    };
  } catch (error) {
    return {
      test: 'Open Redirect Protection',
      error: error instanceof Error ? error.message : 'Unknown error'
    };
  }
}

export async function testDirectoryTraversal(url: string): Promise<TestResult> {
  const traversalPayloads = [
    '../../../etc/passwd',
    '..\\..\\..\\windows\\win.ini',
    '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
    '....//....//....//etc/passwd'
  ];

  try {
    const results = await Promise.all(
      traversalPayloads.map(async payload => {
        const response = await fetch(`${url}?file=${encodeURIComponent(payload)}`);
        const text = await response.text();
        return {
          status: response.status,
          text
        };
      })
    );

    const suspicious = results.some(
      result => 
        result.status === 200 &&
        (result.text.includes('root:') || result.text.includes('[fonts]'))
    );

    return {
      test: 'Directory Traversal Protection',
      status: suspicious ? 'fail' : 'pass',
      details: suspicious ?
        'Potential directory traversal vulnerability - suspicious file contents detected' :
        'No obvious directory traversal vulnerabilities detected'
    };
  } catch (error) {
    return {
      test: 'Directory Traversal Protection',
      error: error instanceof Error ? error.message : 'Unknown error'
    };
  }
}

export async function testCommandInjection(url: string): Promise<TestResult> {
  const injectionPayloads = [
    '| whoami',
    '; whoami',
    '\`whoami\`',
    '$(whoami)',
    '%0awhoami'
  ];

  try {
    const results = await Promise.all(
      injectionPayloads.map(async payload => {
        const response = await fetch(`${url}?cmd=${encodeURIComponent(payload)}`);
        const text = await response.text();
        return {
          status: response.status,
          text
        };
      })
    );

    const suspicious = results.some(
      result =>
        result.text.includes('root') ||
        result.text.includes('admin') ||
        result.text.includes('Administrator')
    );

    return {
      test: 'Command Injection Protection',
      status: suspicious ? 'fail' : 'pass',
      details: suspicious ?
        'Potential command injection vulnerability - command execution detected' :
        'No obvious command injection vulnerabilities detected'
    };
  } catch (error) {
    return {
      test: 'Command Injection Protection',
      error: error instanceof Error ? error.message : 'Unknown error'
    };
  }
}

export async function runAllSecurityTests(url: string): Promise<TestResult[]> {
  const tests = [
    testXssProtection,
    testSqlInjection,
    testNoSqlInjection,
    testSsrf,
    testOpenRedirect,
    testDirectoryTraversal,
    testCommandInjection
  ];

  const results = await Promise.all(
    tests.map(test => test(url).catch(error => ({
      test: test.name,
      error: error instanceof Error ? error.message : 'Unknown error'
    })))
  );

  return results;
}

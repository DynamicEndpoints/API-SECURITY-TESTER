export interface SensitiveDataFinding {
  type: string;
  location: string;
  preview: string;
  severity: 'low' | 'medium' | 'high';
  extractionPath?: string;
}

export interface SecurityFlaw {
  type: string;
  description: string;
  severity: 'low' | 'medium' | 'high';
  recommendation: string;
  evidence?: string;
}

export interface TestResult {
  test: string;
  status?: number | string;
  error?: string;
  details?: string;
  enabled?: boolean;
  warning?: string;
  valid?: boolean;
  headers?: Record<string, string>;
  configuration?: Record<string, string | undefined>;
  sensitiveData?: SensitiveDataFinding[];
  securityFlaws?: SecurityFlaw[];
  responseBody?: string;
  extractedData?: Record<string, any>;
  requiresUserApproval?: boolean;
}

export interface TestOptions {
  isGraphQL?: boolean;
  performanceTest?: boolean;
  performanceTestDuration?: number;
  validateSchema?: boolean;
  scanDocs?: boolean;
  reverseEngineer?: boolean;
  crawlDepth?: number;
  extractData?: boolean;
  includeResponseBody?: boolean;
  sensitiveDataPatterns?: {
    pattern: string;
    type: string;
    severity: 'low' | 'medium' | 'high';
  }[];
}

export interface TlsResult {
  test: string;
  protocol?: string;
  ciphers?: string[];
  certificateInfo?: {
    issuer: string;
    validFrom: string;
    validTo: string;
    keyStrength: number;
  };
  warning?: string;
  error?: string;
}

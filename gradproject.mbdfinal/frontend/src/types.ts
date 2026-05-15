/**
 * Shared TypeScript interfaces for the application.
 */

export interface Vulnerability {
  vulnerability_type: string | null;
  owasp_category: string | null;
  cvss_vector: string | null;
  cvss_score: number | null;
  severity_label: 'None' | 'Low' | 'Medium' | 'High' | 'Critical' | null;
  explanation: string;
  secure_patch: string;
  recommendations: string[];
  confidence: 'Low' | 'Medium' | 'High';
  mitre_attack_mapping?: {
    technique_id: string;
    technique_name: string;
    explanation: string;
  }[];
  notes: string | null;
}

export interface RiskMapEntry {
  label: string;
  likelihood: number;   // 1–5
  impact: number;       // 1–5
  cveId?: string;
  epssScore?: number;
  cisaKev?: boolean;
  enriched: boolean;
}

export interface AnalysisResult {
  is_vulnerable: boolean;
  vulnerabilities: Vulnerability[];
  riskMap?: RiskMapEntry[];
}

export interface Report {
  id: string;
  inputType: string;
  contentPreview: string;
  result: AnalysisResult;
  createdAt: string;
}

export interface User {
  id: string;
  email: string;
  createdAt?: string;
}

export interface AuthState {
  authenticated: boolean;
  user: User | null;
}

export type InputType = 'code' | 'link' | 'cve';

import { useState, useEffect, useCallback } from 'react';
import {
  Shield, Code, Link as LinkIcon, AlertTriangle,
  Menu, Settings, User, History,
  Download, Trash2, ChevronDown, ChevronUp,
  X, Loader2, CheckCircle, XCircle, LogOut
} from 'lucide-react';
import * as api from './api';
import type { InputType, Report, AnalysisResult, AuthState, RiskMapEntry, Vulnerability } from './types';

// ═══════════════════════════════════════════════
// Severity color mapping for UI badges
// ═══════════════════════════════════════════════
const SEVERITY_COLORS: Record<string, string> = {
  None: 'bg-gray-100 text-gray-700',
  Low: 'bg-green-100 text-green-700',
  Medium: 'bg-yellow-100 text-yellow-800',
  High: 'bg-orange-100 text-orange-700',
  Critical: 'bg-red-100 text-red-700',
};

const CONFIDENCE_COLORS: Record<string, string> = {
  Low: 'bg-gray-100 text-gray-600',
  Medium: 'bg-blue-100 text-blue-700',
  High: 'bg-emerald-100 text-emerald-700',
};

// ═══════════════════════════════════════════════
// Auth Modal Component
// ═══════════════════════════════════════════════
function AuthModal({ mode, onClose, onSuccess }: {
  mode: 'signin' | 'signup';
  onClose: () => void;
  onSuccess: () => void;
}) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      if (mode === 'signup') {
        await api.signup(email, password);
      } else {
        await api.login(email, password);
      }
      onSuccess();
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Something went wrong');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
      <div className="bg-white rounded-xl shadow-2xl w-full max-w-md mx-4 p-6">
        <div className="flex justify-between items-center mb-6">
          <h2 className="text-xl font-semibold text-gray-900">
            {mode === 'signup' ? 'Create Account' : 'Sign In'}
          </h2>
          <button onClick={onClose} className="p-1 hover:bg-gray-100 rounded-lg" aria-label="Close">
            <X className="w-5 h-5 text-gray-500" />
          </button>
        </div>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Email</label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none"
              required
              autoComplete="email"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none"
              required
              minLength={8}
              autoComplete={mode === 'signup' ? 'new-password' : 'current-password'}
            />
            {mode === 'signup' && (
              <p className="text-xs text-gray-500 mt-1">
                Min 8 characters, 1 uppercase, 1 lowercase, 1 digit
              </p>
            )}
          </div>
          {error && (
            <div className="text-red-600 text-sm bg-red-50 px-3 py-2 rounded-lg">{error}</div>
          )}
          <button
            type="submit"
            disabled={loading}
            className="w-full py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors disabled:opacity-50 flex items-center justify-center gap-2"
          >
            {loading && <Loader2 className="w-4 h-4 animate-spin" />}
            {mode === 'signup' ? 'Create Account' : 'Sign In'}
          </button>
        </form>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════
// Report Display Component
// ═══════════════════════════════════════════════

const SEVERITY_TO_NUM: Record<string, number> = {
  None: 0,
  Low: 1,
  Medium: 2,
  High: 3,
  Critical: 4,
};

const getInferredStep = (phase: string, vulnType: string = 'Unknown') => {
  const v = vulnType.toLowerCase();

  if (phase === 'Execution') {
    if (v.includes('sql')) return 'Abuse server-side query execution';
    if (v.includes('xss') || v.includes('cross-site')) return 'Execute malicious payload in victim browser';
    if (v.includes('rce') || v.includes('command') || v.includes('execution')) return 'Execute arbitrary system commands';
    if (v.includes('directory') || v.includes('path') || v.includes('lfi') || v.includes('file')) return 'Run unauthorized file read/write';
    return 'Exploit vulnerability to execute code';
  }
  if (phase === 'Privilege Escalation') {
    if (v.includes('sql')) return 'Access sensitive database functions / escalate DB privileges';
    if (v.includes('xss') || v.includes('cross-site')) return 'Hijack admin session or tokens';
    if (v.includes('rce') || v.includes('command') || v.includes('execution')) return 'Gain higher system privileges';
    if (v.includes('directory') || v.includes('path') || v.includes('lfi') || v.includes('file')) return 'Access restricted files to elevate privileges';
    return 'Escalate privileges within the application';
  }
  if (phase === 'Persistence') {
    if (v.includes('sql')) return 'Create backdoor user / maintain DB access';
    if (v.includes('xss') || v.includes('cross-site')) return 'Inject persistent malicious scripts';
    if (v.includes('rce') || v.includes('command') || v.includes('execution')) return 'Install backdoor or scheduled task';
    if (v.includes('directory') || v.includes('path') || v.includes('lfi') || v.includes('file')) return 'Modify configuration files for persistent access';
    return 'Create mechanism for persistent access';
  }
  if (phase === 'Exfiltration') {
    if (v.includes('sql')) return 'Extract or manipulate sensitive data';
    if (v.includes('xss') || v.includes('cross-site')) return 'Steal user data and exfiltrate';
    if (v.includes('rce') || v.includes('command') || v.includes('execution')) return 'Exfiltrate sensitive environment variables/files';
    if (v.includes('directory') || v.includes('path') || v.includes('lfi') || v.includes('file')) return 'Download sensitive server files';
    return 'Extract sensitive information';
  }
  if (phase === 'Initial Access') {
    return 'Exploit Public-Facing Application';
  }
  return 'Inferred phase action';
};

function AttackPathGraph({ mappings, vulnType }: { mappings: NonNullable<Vulnerability['mitre_attack_mapping']>; vulnType?: string }) {
  const PHASES = ['Initial Access', 'Execution', 'Privilege Escalation', 'Persistence', 'Exfiltration'];

  const getPhase = (m: NonNullable<Vulnerability['mitre_attack_mapping']>[0]) => {
    const text = `${m.technique_id} ${m.technique_name} ${m.explanation}`.toLowerCase();
    if (text.includes('exfiltrat') || text.includes('steal') || text.includes('impact') || text.includes('dump') || text.includes('ransom')) return 'Exfiltration';
    if (text.includes('persist') || text.includes('backdoor') || text.includes('account') || text.includes('implant')) return 'Persistence';
    if (text.includes('privilege') || text.includes('escalat') || text.includes('bypass') || text.includes('root') || text.includes('admin')) return 'Privilege Escalation';
    if (text.includes('execut') || text.includes('command') || text.includes('script') || text.includes('shell') || text.includes('eval')) return 'Execution';
    return 'Initial Access';
  };

  return (
    <div className="bg-white rounded-xl border border-gray-200 p-5 shadow-sm mb-4 print:break-inside-avoid">
      <h3 className="text-lg font-semibold text-gray-900 mb-4">Attack Path Graph</h3>
      <div className="flex flex-col md:flex-row items-stretch md:items-center justify-between gap-2 overflow-visible pb-4 relative z-0">
        {PHASES.map((phase, i) => {
          const matching = mappings.filter(m => getPhase(m) === phase);
          const hasTechnique = matching.length > 0;

          return (
            <div key={phase} className="flex flex-col md:flex-row items-center gap-2 flex-1">
              <div
                className={`flex flex-col items-center w-full min-w-[130px] p-4 rounded-lg border transition-all ${hasTechnique
                  ? 'bg-red-50 border-red-200 shadow-sm'
                  : 'bg-gray-50 border-gray-200 border-dashed'
                  }`}
              >
                <div className={`text-xs font-bold uppercase tracking-wider mb-2 ${hasTechnique ? 'text-red-700' : 'text-gray-500 text-center'}`}>
                  {phase}
                </div>
                {hasTechnique ? (
                  <div className="w-full flex flex-col gap-2">
                    {matching.map((m, idx) => (
                      <div key={idx} className="bg-white border border-red-100 rounded p-2 shadow-sm">
                        <div className="text-xs font-bold text-gray-800 text-center">
                          {m.technique_id}
                        </div>
                        <div className="text-[10px] text-gray-600 text-center leading-tight mt-0.5 line-clamp-2">
                          {m.technique_name}
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="w-full flex flex-col gap-2">
                    <div className="bg-white border border-blue-100 rounded p-2 shadow-sm">
                      <div className="flex justify-center mb-1">
                        <span className="bg-blue-50 text-blue-600 text-[8px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded">
                          Inferred
                        </span>
                      </div>
                      <div className="text-[10px] text-gray-700 text-center leading-snug">
                        {getInferredStep(phase, vulnType)}
                      </div>
                    </div>
                  </div>
                )}
              </div>

              {i < PHASES.length - 1 && (
                <div className="text-gray-300 font-bold hidden md:flex items-center justify-center shrink-0 w-6">
                  →
                </div>
              )}
              {i < PHASES.length - 1 && (
                <div className="text-gray-300 font-bold md:hidden flex items-center justify-center h-6 my-1">
                  ↓
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

function ReportView({ result, onDownloadJSON }: {
  result: AnalysisResult;
  onDownloadJSON: () => void;
}) {
  const [expandedPatches, setExpandedPatches] = useState<Record<number, boolean>>({});

  const togglePatch = (index: number) => {
    setExpandedPatches((prev) => ({ ...prev, [index]: !prev[index] }));
  };

  // Compute aggregate stats
  const maxCvss = result.vulnerabilities.reduce((max, v) => {
    if (v.cvss_score !== null && v.cvss_score > max) return v.cvss_score;
    return max;
  }, -1);

  const topSeverity = result.vulnerabilities.reduce((highest, v) => {
    if (!v.severity_label) return highest;
    if (!highest) return v.severity_label;
    if (SEVERITY_TO_NUM[v.severity_label] > SEVERITY_TO_NUM[highest]) {
      return v.severity_label;
    }
    return highest;
  }, null as string | null);

  const displayCvss = maxCvss >= 0 ? maxCvss.toFixed(1) : 'N/A';

  return (
    <div className="mt-8 space-y-4 max-w-4xl mx-auto">
      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Vulnerability Status */}
        <div className="bg-white rounded-xl border border-gray-200 p-4 shadow-sm print:break-inside-avoid">
          <div className="text-sm text-gray-500 mb-1">Status</div>
          <div className="flex items-center gap-2">
            {result.is_vulnerable ? (
              <XCircle className="w-5 h-5 text-red-500" />
            ) : (
              <CheckCircle className="w-5 h-5 text-green-500" />
            )}
            <span className={`font-semibold ${result.is_vulnerable ? 'text-red-700' : 'text-green-700'}`}>
              {result.is_vulnerable ? 'Vulnerabilities Found' : 'No Issues Found'}
            </span>
          </div>
        </div>

        {/* Highest CVSS Score */}
        <div className="bg-white rounded-xl border border-gray-200 p-4 shadow-sm print:break-inside-avoid">
          <div className="text-sm text-gray-500 mb-1">Highest CVSS Score</div>
          <div className="flex items-center gap-2">
            <span className="text-2xl font-bold text-gray-900">
              {displayCvss}
            </span>
            {topSeverity && (
              <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${SEVERITY_COLORS[topSeverity] || 'bg-gray-100 text-gray-600'}`}>
                {topSeverity}
              </span>
            )}
            <span className="text-xs text-gray-500 ml-auto">
              ({result.vulnerabilities.length} issue{result.vulnerabilities.length === 1 ? '' : 's'})
            </span>
          </div>
        </div>
      </div>

      {result.vulnerabilities.map((vuln, index) => (
        <div key={index} className="mt-8 pt-8 border-t-2 border-dashed border-gray-200">
          <h2 className="text-xl font-bold text-gray-800 mb-4">
            Vulnerability #{index + 1}: {vuln.vulnerability_type || 'Unknown Type'}
          </h2>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
            {/* CVSS Score */}
            <div className="bg-white rounded-xl border border-gray-200 p-4 shadow-sm print:break-inside-avoid">
              <div className="text-sm text-gray-500 mb-1">CVSS Score</div>
              <div className="flex items-center gap-2">
                <span className="text-2xl font-bold text-gray-900">
                  {vuln.cvss_score !== null ? vuln.cvss_score.toFixed(1) : 'N/A'}
                </span>
                {vuln.severity_label && (
                  <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${SEVERITY_COLORS[vuln.severity_label] || 'bg-gray-100 text-gray-600'}`}>
                    {vuln.severity_label}
                  </span>
                )}
              </div>
            </div>

            {/* Confidence */}
            <div className="bg-white rounded-xl border border-gray-200 p-4 shadow-sm print:break-inside-avoid">
              <div className="text-sm text-gray-500 mb-1">Confidence</div>
              <span className={`px-3 py-1 rounded-full text-sm font-medium ${CONFIDENCE_COLORS[vuln.confidence] || 'bg-gray-100 text-gray-600'}`}>
                {vuln.confidence}
              </span>
            </div>

            {/* OWASP Category */}
            {vuln.owasp_category && (
              <div className="bg-white rounded-xl border border-gray-200 p-4 shadow-sm print:break-inside-avoid">
                <div className="text-sm text-gray-500 mb-1">OWASP Category</div>
                <div className="font-medium text-gray-900 line-clamp-2">{vuln.owasp_category}</div>
              </div>
            )}
          </div>

          {/* CVSS Vector */}
          {vuln.cvss_vector && (
            <div className="bg-white rounded-xl border border-gray-200 p-4 shadow-sm mb-4">
              <div className="text-sm text-gray-500 mb-1">CVSS Vector</div>
              <code className="text-sm text-gray-800 bg-gray-100 px-2 py-1 rounded font-mono">
                {vuln.cvss_vector}
              </code>
            </div>
          )}

          {/* Explanation */}
          <div className="bg-white rounded-xl border border-gray-200 p-5 shadow-sm mb-4">
            <h3 className="text-lg font-semibold text-gray-900 mb-3">Explanation</h3>
            <p className="text-gray-700 leading-relaxed whitespace-pre-wrap">{vuln.explanation}</p>
          </div>

          {/* Secure Patch (expandable) */}
          <div className="bg-white rounded-xl border border-gray-200 shadow-sm overflow-hidden mb-4">
            <button
              onClick={() => togglePatch(index)}
              className="w-full px-5 py-4 flex items-center justify-between hover:bg-gray-50 transition-colors"
            >
              <h3 className="text-lg font-semibold text-gray-900">Secure Patch / Remediation</h3>
              {expandedPatches[index] ? <ChevronUp className="w-5 h-5 text-gray-500" /> : <ChevronDown className="w-5 h-5 text-gray-500" />}
            </button>
            {expandedPatches[index] && (
              <div className="px-5 pb-5 border-t border-gray-100">
                <pre className="bg-[#1e1e1e] text-gray-300 p-4 rounded-lg text-sm font-mono overflow-x-auto mt-3 whitespace-pre-wrap">
                  {vuln.secure_patch}
                </pre>
              </div>
            )}
          </div>

          {/* Recommendations */}
          {vuln.recommendations.length > 0 && (
            <div className="bg-white rounded-xl border border-gray-200 p-5 shadow-sm mb-4">
              <h3 className="text-lg font-semibold text-gray-900 mb-3">Recommendations</h3>
              <ul className="space-y-2">
                {vuln.recommendations.map((rec, i) => (
                  <li key={i} className="flex items-start gap-2 text-gray-700">
                    <span className="mt-1 w-5 h-5 flex-shrink-0 rounded-full bg-blue-100 text-blue-700 text-xs flex items-center justify-center font-medium">
                      {i + 1}
                    </span>
                    <span>{rec}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* MITRE ATT&CK Mapping */}
          {vuln.mitre_attack_mapping && vuln.mitre_attack_mapping.length > 0 && (
            <>
              <div className="bg-white rounded-xl border border-gray-200 p-5 shadow-sm mb-4 print:break-inside-avoid">
                <h3 className="text-lg font-semibold text-gray-900 mb-3">MITRE ATT&CK Mapping</h3>
                <div className="space-y-4">
                  {vuln.mitre_attack_mapping.map((mapping, i) => (
                    <div key={i} className="flex flex-col gap-2 p-3 bg-gray-50 rounded-lg border border-gray-100">
                      <div className="flex items-center gap-2">
                        <span className="px-2 py-0.5 bg-blue-100 text-blue-700 rounded text-xs font-mono font-bold">
                          {mapping.technique_id}
                        </span>
                        <span className="font-medium text-gray-800">{mapping.technique_name}</span>
                      </div>
                      <p className="text-sm text-gray-600 leading-relaxed">{mapping.explanation}</p>
                    </div>
                  ))}
                </div>
              </div>

              <AttackPathGraph mappings={vuln.mitre_attack_mapping} vulnType={vuln.vulnerability_type} />
            </>
          )}

          {/* Notes */}
          {vuln.notes && (
            <div className="bg-blue-50 rounded-xl border border-blue-200 p-5">
              <h3 className="text-sm font-semibold text-blue-800 mb-2">Additional Notes</h3>
              <p className="text-blue-700 text-sm">{vuln.notes}</p>
            </div>
          )}
        </div>
      ))}

      {/* Download Buttons */}
      <div className="flex gap-3 justify-center pt-6 print:hidden">
        <button
          onClick={onDownloadJSON}
          className="flex items-center gap-2 px-4 py-2 bg-white border border-gray-200 rounded-lg text-gray-700 hover:bg-gray-50 transition-colors shadow-sm"
        >
          <Download className="w-4 h-4" />
          Download JSON
        </button>
        <button
          onClick={() => window.print()}
          className="flex items-center gap-2 px-4 py-2 bg-white border border-gray-200 rounded-lg text-gray-700 hover:bg-gray-50 transition-colors shadow-sm"
        >
          <Download className="w-4 h-4" />
          Download PDF
        </button>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════
// History Panel Component
// ═══════════════════════════════════════════════
function HistoryPanel({ onClose, onSelectReport }: {
  onClose: () => void;
  onSelectReport: (report: Report) => void;
}) {
  const [reports, setReports] = useState<Report[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.getReports()
      .then((data) => setReports(data.reports))
      .catch(() => { })
      .finally(() => setLoading(false));
  }, []);

  const handleDelete = async (id: string) => {
    try {
      await api.deleteReport(id);
      setReports((prev) => prev.filter((r) => r.id !== id));
    } catch {
      // ignore
    }
  };

  const getTopSeverity = (result: AnalysisResult) => {
    const highest = result.vulnerabilities.reduce((max, v) => {
      if (!v.severity_label) return max;
      if (!max) return v.severity_label;
      if (SEVERITY_TO_NUM[v.severity_label] > SEVERITY_TO_NUM[max]) {
        return v.severity_label;
      }
      return max;
    }, null as string | null);
    return highest;
  };

  return (
    <div className="fixed inset-0 z-50 flex">
      <div className="fixed inset-0 bg-black/30" onClick={onClose} />
      <div className="relative ml-auto w-full max-w-md bg-white h-full shadow-xl overflow-y-auto z-10">
        <div className="sticky top-0 bg-white border-b border-gray-200 px-6 py-4 flex items-center justify-between">
          <h2 className="text-lg font-semibold text-gray-900">Report History</h2>
          <button onClick={onClose} className="p-1 hover:bg-gray-100 rounded-lg" aria-label="Close history">
            <X className="w-5 h-5 text-gray-500" />
          </button>
        </div>
        <div className="p-6">
          {loading ? (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="w-6 h-6 animate-spin text-blue-600" />
            </div>
          ) : reports.length === 0 ? (
            <p className="text-gray-500 text-center py-12">No reports yet</p>
          ) : (
            <div className="space-y-3">
              {reports.map((report) => {
                const topSeverity = getTopSeverity(report.result);
                return (
                  <div
                    key={report.id}
                    className="bg-gray-50 rounded-lg p-4 border border-gray-200 hover:border-blue-300 transition-colors"
                  >
                    <div className="flex items-start justify-between mb-2">
                      <button
                        onClick={() => { onSelectReport(report); onClose(); }}
                        className="text-left flex-1"
                      >
                        <div className="flex items-center gap-2 mb-1">
                          <span className="text-xs font-medium px-2 py-0.5 rounded bg-gray-200 text-gray-600 uppercase">
                            {report.inputType}
                          </span>
                          {topSeverity && (
                            <span className={`text-xs font-medium px-2 py-0.5 rounded ${SEVERITY_COLORS[topSeverity] || ''}`}>
                          {topSeverity}
                            </span>
                          )}
                        </div>
                        <p className="text-sm text-gray-700 line-clamp-2">{report.contentPreview}</p>
                        <p className="text-xs text-gray-400 mt-1">
                          {new Date(report.createdAt).toLocaleString()}
                        </p>
                      </button>
                      <button
                        onClick={() => handleDelete(report.id)}
                        className="p-1.5 hover:bg-red-50 rounded-lg text-gray-400 hover:text-red-500 transition-colors flex-shrink-0"
                        aria-label="Delete report"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════
// Cyber Risk Map Component — 5×5 Risk Assessment Matrix
// ═══════════════════════════════════════════════

// row index 0 = likelihood 1 (bottom), index 4 = likelihood 5 (top)
// col index 0 = severity 1 (left),     index 4 = severity 5 (right)
// score = likelihood × severity (1–25)
const MATRIX_COLORS: Record<string, string> = {
  low:       '#16a34a', // green-600
  medium:    '#ca8a04', // yellow-600
  high:      '#ea580c', // orange-600
  veryhigh:  '#dc2626', // red-600
};

function getCellMeta(likelihood: number, severity: number): { color: string; label: string; score: number } {
  const score = likelihood * severity;
  let label: string;
  let color: string;
  if (score <= 4)       { label = 'Low';       color = '#22c55e'; }  // green-500
  else if (score <= 9)  { label = 'Medium';    color = '#eab308'; }  // yellow-500
  else if (score <= 16) { label = 'High';      color = '#f97316'; }  // orange-500
  else                  { label = 'Very High'; color = '#ef4444'; }  // red-500
  return { color, label, score };
}

function RiskDot({ entry, index, size = 26 }: { entry: RiskMapEntry; index?: number; size?: number }) {
  return (
    <div
      title={`${entry.label}${entry.cveId ? ` • ${entry.cveId}` : ''}${entry.epssScore != null ? ` • EPSS ${(entry.epssScore * 100).toFixed(1)}%` : ''}${entry.cisaKev ? ' • CISA KEV' : ''}`}
      style={{
        width: size,
        height: size,
        borderRadius: '50%',
        background: '#1d4ed8',
        border: entry.cisaKev ? '2px solid #dc2626' : '2px solid #3b82f6',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        fontSize: 10,
        color: '#fff',
        fontWeight: 700,
        cursor: 'default',
        flexShrink: 0,
        boxShadow: '0 1px 4px rgba(0,0,0,0.25)',
        printColorAdjust: 'exact',
        WebkitPrintColorAdjust: 'exact',
      }}
    >
      {index !== undefined ? index : '●'}
    </div>
  );
}

const COL_HEADERS = ['Rare', 'Unlikely', 'Possible', 'Likely', 'Almost\nCertain'];
const ROW_LABELS = [
  { num: 5, text: 'Fatal /\nCatastrophic' },
  { num: 4, text: 'Major\nInjury' },
  { num: 3, text: 'Serious\nInjury' },
  { num: 2, text: 'Moderate\nInjury' },
  { num: 1, text: 'Minor\nInjury' },
];

const LEGEND_ITEMS = [
  { color: '#22c55e', label: 'Low Risk',       desc: 'Acceptable / Monitor' },
  { color: '#eab308', label: 'Medium Risk',    desc: 'Reduce Risk' },
  { color: '#f97316', label: 'High Risk',      desc: 'Action Required' },
  { color: '#ef4444', label: 'Very High Risk', desc: 'Stop Activity' },
];

function CyberRiskMap({ entries }: { entries: RiskMapEntry[] }) {
  if (!entries || entries.length === 0) return null;

  const CELL_W = 80;
  const CELL_H = 62;
  const ROW_LABEL_W = 96;
  const COL_HEADER_H = 44;

  return (
    <div
      className="mt-6 max-w-4xl mx-auto print:break-inside-avoid"
      style={{
        background: '#fff',
        border: '2px solid #d1d5db',
        borderRadius: 14,
        padding: '24px 28px 20px',
        boxShadow: '0 4px 16px rgba(0,0,0,0.10)',
      }}
    >
      <h3 style={{ fontSize: 18, fontWeight: 800, color: '#111827', marginBottom: 2, letterSpacing: '-0.3px' }}>
        5×5 Risk Assessment Matrix
      </h3>
      <p style={{ fontSize: 12, color: '#6b7280', marginBottom: 20, fontWeight: 500 }}>
        Likelihood × Severity = Risk Rating
      </p>

      <div style={{ overflowX: 'auto' }}>
        <div style={{ display: 'flex' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', width: 30 }}>
            <div style={{ transform: 'rotate(-90deg)', fontSize: 11, fontWeight: 700, color: '#374151', whiteSpace: 'nowrap' }}>
              Impact →
            </div>
          </div>
          <div style={{ display: 'inline-block', minWidth: ROW_LABEL_W + 5 * CELL_W + 4 * 3 }}>

          {/* Column headers */}
          <div style={{ display: 'flex', marginLeft: ROW_LABEL_W }}>
            {COL_HEADERS.map((h, ci) => (
              <div
                key={ci}
                style={{
                  width: CELL_W,
                  marginLeft: ci > 0 ? 3 : 0,
                  textAlign: 'center',
                  fontSize: 11,
                  fontWeight: 700,
                  color: '#374151',
                  lineHeight: 1.25,
                  padding: '0 2px',
                  height: COL_HEADER_H,
                  display: 'flex',
                  alignItems: 'flex-end',
                  justifyContent: 'center',
                  paddingBottom: 6,
                  borderBottom: '2px solid #6b7280',
                }}
              >
                <span style={{ whiteSpace: 'pre-line' }}>{h}</span>
              </div>
            ))}
          </div>

          {/* Grid rows */}
          {ROW_LABELS.map((rowLabel, rowIdx) => {
            const severityVal = rowLabel.num;
            return (
              <div key={rowIdx} style={{ display: 'flex', marginTop: 3 }}>
                {/* Row label */}
                <div style={{ width: ROW_LABEL_W, height: CELL_H, display: 'flex', alignItems: 'center', justifyContent: 'flex-end', paddingRight: 10, flexShrink: 0 }}>
                  <div style={{ textAlign: 'right' }}>
                    <div style={{ fontSize: 12, fontWeight: 700, color: '#111827' }}>{severityVal}.</div>
                    <div style={{ fontSize: 10, color: '#4b5563', lineHeight: 1.2, whiteSpace: 'pre-line' }}>{rowLabel.text}</div>
                  </div>
                </div>

                {/* Cells */}
                {Array.from({ length: 5 }, (_, colIdx) => {
                  const likelihoodVal = colIdx + 1;
                  const { color, label, score } = getCellMeta(likelihoodVal, severityVal);
                  const dotsHere = entries.filter(
                    (e) => Math.round(e.likelihood) === likelihoodVal && Math.round(e.impact) === severityVal
                  );
                  return (
                    <div
                      key={colIdx}
                      style={{
                        width: CELL_W,
                        height: CELL_H,
                        marginLeft: colIdx > 0 ? 3 : 0,
                        background: color,
                        border: '1.5px solid rgba(0,0,0,0.15)',
                        borderRadius: 6,
                        display: 'flex',
                        flexDirection: 'column',
                        alignItems: 'center',
                        justifyContent: 'center',
                        gap: 3,
                        padding: 4,
                        position: 'relative',
                        flexShrink: 0,
                        printColorAdjust: 'exact',
                        WebkitPrintColorAdjust: 'exact',
                      }}
                    >
                      <div style={{ fontSize: 16, fontWeight: 800, color: 'rgba(0,0,0,0.50)', lineHeight: 1, userSelect: 'none', pointerEvents: 'none' }}>
                        {score}
                      </div>
                      <div style={{ fontSize: 9, fontWeight: 700, color: 'rgba(0,0,0,0.45)', textTransform: 'uppercase', letterSpacing: '0.4px', lineHeight: 1, userSelect: 'none', pointerEvents: 'none' }}>
                        {label}
                      </div>
                      {dotsHere.length > 0 && (
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 2, justifyContent: 'center' }}>
                          {dotsHere.map((entry, di) => (
                            <RiskDot key={di} entry={entry} index={entries.indexOf(entry) + 1} size={22} />
                          ))}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            );
          })}

          {/* X-axis label */}
          <div style={{ display: 'flex', marginTop: 10, marginLeft: ROW_LABEL_W, alignItems: 'center', gap: 8 }}>
            <div style={{ height: 2, flex: 1, background: 'linear-gradient(to right, #22c55e, #eab308, #f97316, #ef4444)', borderRadius: 2, printColorAdjust: 'exact', WebkitPrintColorAdjust: 'exact' }} />
            <div style={{ fontSize: 11, fontWeight: 700, color: '#374151', whiteSpace: 'nowrap' }}>Likelihood →</div>
          </div>
        </div>
        </div>
      </div>

      {/* Vulnerability index */}
      {entries.length > 0 && (
        <div style={{ marginTop: 16, display: 'flex', flexWrap: 'wrap', gap: 6 }}>
          {entries.map((entry, i) => (
            <div
              key={i}
              title={`Likelihood: ${entry.likelihood}, Severity: ${entry.impact}${entry.epssScore != null ? `, EPSS: ${(entry.epssScore * 100).toFixed(1)}%` : ''}`}
              style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, color: '#1f2937', background: '#f3f4f6', border: '1px solid #d1d5db', borderRadius: 6, padding: '4px 9px', cursor: 'default', printColorAdjust: 'exact', WebkitPrintColorAdjust: 'exact' }}
            >
              <span style={{ width: 18, height: 18, borderRadius: '50%', background: '#1e3a8a', border: entry.cisaKev ? '2px solid #dc2626' : '2px solid #93c5fd', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 9, color: '#fff', fontWeight: 800, flexShrink: 0, printColorAdjust: 'exact', WebkitPrintColorAdjust: 'exact' }}>{i + 1}</span>
              <span style={{ fontWeight: 600 }}>{entry.label}</span>
              {entry.epssScore != null && <span style={{ color: '#6b7280' }}>EPSS: {(entry.epssScore * 100).toFixed(1)}%</span>}
              {entry.cveId && <span style={{ color: '#9ca3af' }}>({entry.cveId})</span>}
              {entry.cisaKev && <span style={{ color: '#dc2626', fontWeight: 700 }}>⚠ KEV</span>}
              {!entry.enriched && <span style={{ color: '#9ca3af' }}>*</span>}
            </div>
          ))}
          {entries.some((e) => !e.enriched) && (
            <div style={{ fontSize: 10, color: '#9ca3af', alignSelf: 'center', fontStyle: 'italic' }}>
              * Estimated from LLM severity/confidence (no dataset match)
            </div>
          )}
        </div>
      )}

      {/* Bottom legend */}
      <div style={{ marginTop: 18, borderTop: '1.5px solid #e5e7eb', paddingTop: 14, display: 'flex', flexWrap: 'wrap', gap: 10 }}>
        {LEGEND_ITEMS.map((item) => (
          <div key={item.label} style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
            <div style={{ width: 28, height: 16, background: item.color, borderRadius: 4, border: '1px solid rgba(0,0,0,0.15)', flexShrink: 0, printColorAdjust: 'exact', WebkitPrintColorAdjust: 'exact' }} />
            <div>
              <span style={{ fontSize: 11, fontWeight: 700, color: '#111827' }}>{item.label}</span>
              <span style={{ fontSize: 11, color: '#6b7280' }}> — {item.desc}</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function App() {
  const [inputType, setInputType] = useState<InputType>('code');
  const [code, setCode] = useState('');
  const [menuOpen, setMenuOpen] = useState(false);
  const [authModal, setAuthModal] = useState<'signin' | 'signup' | null>(null);
  const [historyOpen, setHistoryOpen] = useState(false);
  const [auth, setAuth] = useState<AuthState>({ authenticated: false, user: null });
  const [analyzing, setAnalyzing] = useState(false);
  const [analysisResult, setAnalysisResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState('');

  // Check auth status on mount
  const checkAuth = useCallback(async () => {
    try {
      const me = await api.getMe();
      setAuth(me);
    } catch {
      setAuth({ authenticated: false, user: null });
    }
  }, []);

  useEffect(() => {
    checkAuth();
  }, [checkAuth]);

  const handleAnalyze = async () => {
    if (!code.trim()) return;
    setError('');
    setAnalysisResult(null);
    setAnalyzing(true);
    try {
      const response = await api.analyze(inputType, code);
      setAnalysisResult(response.result);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Analysis failed. Please try again.');
    } finally {
      setAnalyzing(false);
    }
  };

  const handleLogout = async () => {
    try {
      await api.logout();
      setAuth({ authenticated: false, user: null });
      setMenuOpen(false);
    } catch {
      // ignore
    }
  };

  const handleDownloadJSON = () => {
    if (!analysisResult) return;
    const blob = new Blob([JSON.stringify(analysisResult, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'vulnerability-report.json';
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleSelectReport = (report: Report) => {
    setAnalysisResult(report.result);
  };

  const getPlaceholder = () => {
    switch (inputType) {
      case 'code':
        return 'Paste your code here...';
      case 'link':
        return 'Enter repository or file URL...';
      case 'cve':
        return 'Enter CVE ID (e.g., CVE-2024-1234)...';
    }
  };

  const getFileName = () => {
    switch (inputType) {
      case 'code':
        return 'input.code';
      case 'link':
        return 'input.url';
      case 'cve':
        return 'input.cve';
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 flex flex-col">
      {/* Header */}
      <header className="pt-16 pb-12 px-6 print:hidden">
        {/* Top Navigation */}
        <div className="fixed top-0 left-0 right-0 bg-white border-b border-gray-200 z-50">
          <div className="max-w-7xl mx-auto flex items-center justify-between px-[24px] py-[10px]">
            {/* Left Menu & Logo */}
            <div className="flex items-center gap-4">
              <div className="relative">
                <button
                  onClick={() => setMenuOpen(!menuOpen)}
                  className="p-2 hover:bg-gray-100 rounded-lg transition-colors"
                  aria-label="Menu"
                >
                  <Menu className="w-6 h-6 text-gray-700" />
                </button>

              {/* Dropdown Menu */}
              {menuOpen && (
                <>
                  <div
                    className="fixed inset-0 z-10"
                    onClick={() => setMenuOpen(false)}
                  />
                  <div className="absolute left-0 top-full mt-2 w-48 bg-white rounded-lg shadow-lg border border-gray-200 py-2 z-20">
                    <button
                      onClick={() => { setMenuOpen(false); setHistoryOpen(true); }}
                      className="w-full px-4 py-2 text-left hover:bg-gray-50 flex items-center gap-3 text-gray-700"
                    >
                      <History className="w-4 h-4" />
                      History
                    </button>
                  </div>
                </>
              )}
            </div>
            
            <div className="flex items-center gap-2 select-none">
              <Shield className="w-5 h-5 text-blue-600" />
              <span className="text-lg font-bold text-gray-900 tracking-tight">Veyra</span>
            </div>
            </div>

          {/* Right Auth Buttons */}
          <div className="flex items-center gap-3">
              {auth.authenticated && (
                <div className="flex items-center gap-3">
                  <span className="text-sm text-gray-600">{auth.user?.email}</span>
                  <button
                    onClick={handleLogout}
                    className="px-4 py-2 text-gray-700 hover:bg-gray-100 rounded-lg transition-colors"
                  >
                    Sign Out
                  </button>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Main Header Content */}
        <div className="max-w-4xl mx-auto text-center mt-10">
          <div className="flex items-center justify-center gap-3 mb-4">
            <h1 className="text-4xl text-gray-900">
              <span className="font-bold">Veyra</span> AI Secure Code Analyzer
            </h1>
          </div>
          <p className="text-gray-600 text-lg">
            Educational Vulnerability Detection and Security Report
          </p>
        </div>
      </header>

      {/* Main Content */}
      <main className="flex-1 px-6 pb-16">
        <div className="max-w-4xl mx-auto">
          {/* Input Type Tabs */}
          <div className="flex gap-2 mb-6 print:hidden">
            <button
              onClick={() => { setInputType('code'); setCode(''); setAnalysisResult(null); setError(''); }}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg transition-colors ${inputType === 'code'
                ? 'bg-blue-600 text-white'
                : 'bg-white text-gray-700 hover:bg-gray-100 border border-gray-200'
                }`}
            >
              <Code className="w-4 h-4" />
              Code
            </button>
            <button
              onClick={() => { setInputType('link'); setCode(''); setAnalysisResult(null); setError(''); }}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg transition-colors ${inputType === 'link'
                ? 'bg-blue-600 text-white'
                : 'bg-white text-gray-700 hover:bg-gray-100 border border-gray-200'
                }`}
            >
              <LinkIcon className="w-4 h-4" />
              Link
            </button>
            <button
              onClick={() => { setInputType('cve'); setCode(''); setAnalysisResult(null); setError(''); }}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg transition-colors ${inputType === 'cve'
                ? 'bg-blue-600 text-white'
                : 'bg-white text-gray-700 hover:bg-gray-100 border border-gray-200'
                }`}
            >
              <AlertTriangle className="w-4 h-4" />
              CVE
            </button>
          </div>

          {/* Code Editor */}
          <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden mb-6 print:hidden">
            <div className="bg-[#1e1e1e] px-4 py-3 border-b border-gray-700">
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded-full bg-red-500"></div>
                <div className="w-3 h-3 rounded-full bg-yellow-500"></div>
                <div className="w-3 h-3 rounded-full bg-green-500"></div>
                <span className="ml-3 text-gray-400 text-sm">{getFileName()}</span>
              </div>
            </div>
            {inputType === 'code' ? (
              <textarea
                value={code}
                onChange={(e) => setCode(e.target.value)}
                placeholder={getPlaceholder()}
                className="w-full h-72 bg-[#1e1e1e] text-gray-300 p-6 font-mono text-sm resize-none focus:outline-none placeholder:text-gray-600"
                spellCheck={false}
              />
            ) : (
              <input
                type="text"
                value={code}
                onChange={(e) => setCode(e.target.value)}
                placeholder={getPlaceholder()}
                className="w-full bg-[#1e1e1e] text-gray-300 px-6 py-4 font-mono text-sm focus:outline-none placeholder:text-gray-600"
                spellCheck={false}
              />
            )}
          </div>

          {/* Error Message */}
          {error && (
            <div className="mb-4 p-4 bg-red-50 border border-red-200 rounded-xl text-red-700 text-sm">
              {error}
            </div>
          )}

          {/* Analyze Button */}
          <div className="flex justify-center print:hidden">
            <button
              onClick={handleAnalyze}
              disabled={analyzing || !code.trim()}
              className="px-8 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors shadow-sm font-medium text-lg disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
            >
              {analyzing && <Loader2 className="w-5 h-5 animate-spin" />}
              {analyzing ? 'Analyzing...' : 'Analyze Code'}
            </button>
          </div>

          {/* Analysis Result */}
          {analysisResult && (
            <>
              <ReportView result={analysisResult} onDownloadJSON={handleDownloadJSON} />
              {analysisResult.riskMap && analysisResult.riskMap.length > 0 && (
                <CyberRiskMap entries={analysisResult.riskMap} />
              )}
            </>
          )}
        </div>
      </main>

      {/* Footer */}
      <footer className="py-6 px-6 text-center text-gray-500 text-sm print:hidden">
        <p>Educational purposes only • Learn secure coding practices</p>
      </footer>

      {/* Auth Modal */}
      {authModal && (
        <AuthModal
          mode={authModal}
          onClose={() => setAuthModal(null)}
          onSuccess={checkAuth}
        />
      )}

      {/* History Panel */}
      {historyOpen && (
        <HistoryPanel
          onClose={() => setHistoryOpen(false)}
          onSelectReport={handleSelectReport}
        />
      )}
    </div>
  );
}

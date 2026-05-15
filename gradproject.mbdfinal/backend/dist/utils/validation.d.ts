/**
 * Input validation schemas using Zod.
 * Centralizes all validation logic to ensure consistent input handling.
 * Every user-facing input is validated before processing.
 */
import { z } from 'zod';
export declare const analyzeInputSchema: z.ZodObject<{
    inputType: z.ZodEnum<["code", "url", "text"]>;
    content: z.ZodString;
}, "strip", z.ZodTypeAny, {
    inputType: "code" | "url" | "text";
    content: string;
}, {
    inputType: "code" | "url" | "text";
    content: string;
}>;
export declare const signupSchema: z.ZodObject<{
    email: z.ZodString;
    password: z.ZodString;
}, "strip", z.ZodTypeAny, {
    email: string;
    password: string;
}, {
    email: string;
    password: string;
}>;
export declare const loginSchema: z.ZodObject<{
    email: z.ZodString;
    password: z.ZodString;
}, "strip", z.ZodTypeAny, {
    email: string;
    password: string;
}, {
    email: string;
    password: string;
}>;
export declare const vulnerabilitySchema: z.ZodObject<{
    vulnerability_type: z.ZodNullable<z.ZodString>;
    owasp_category: z.ZodNullable<z.ZodString>;
    cvss_vector: z.ZodOptional<z.ZodNullable<z.ZodString>>;
    cvss_score: z.ZodOptional<z.ZodNullable<z.ZodNumber>>;
    severity_label: z.ZodNullable<z.ZodEnum<["None", "Low", "Medium", "High", "Critical"]>>;
    explanation: z.ZodString;
    secure_patch: z.ZodString;
    recommendations: z.ZodArray<z.ZodString, "many">;
    confidence: z.ZodEnum<["Low", "Medium", "High"]>;
    mitre_attack_mapping: z.ZodOptional<z.ZodArray<z.ZodObject<{
        technique_id: z.ZodString;
        technique_name: z.ZodString;
        explanation: z.ZodString;
    }, "strip", z.ZodTypeAny, {
        explanation: string;
        technique_id: string;
        technique_name: string;
    }, {
        explanation: string;
        technique_id: string;
        technique_name: string;
    }>, "many">>;
    notes: z.ZodOptional<z.ZodNullable<z.ZodString>>;
}, "strip", z.ZodTypeAny, {
    vulnerability_type: string | null;
    owasp_category: string | null;
    severity_label: "None" | "Low" | "Medium" | "High" | "Critical" | null;
    explanation: string;
    secure_patch: string;
    recommendations: string[];
    confidence: "Low" | "Medium" | "High";
    cvss_vector?: string | null | undefined;
    cvss_score?: number | null | undefined;
    mitre_attack_mapping?: {
        explanation: string;
        technique_id: string;
        technique_name: string;
    }[] | undefined;
    notes?: string | null | undefined;
}, {
    vulnerability_type: string | null;
    owasp_category: string | null;
    severity_label: "None" | "Low" | "Medium" | "High" | "Critical" | null;
    explanation: string;
    secure_patch: string;
    recommendations: string[];
    confidence: "Low" | "Medium" | "High";
    cvss_vector?: string | null | undefined;
    cvss_score?: number | null | undefined;
    mitre_attack_mapping?: {
        explanation: string;
        technique_id: string;
        technique_name: string;
    }[] | undefined;
    notes?: string | null | undefined;
}>;
export declare const llmResponseSchema: z.ZodObject<{
    is_vulnerable: z.ZodBoolean;
    vulnerabilities: z.ZodArray<z.ZodObject<{
        vulnerability_type: z.ZodNullable<z.ZodString>;
        owasp_category: z.ZodNullable<z.ZodString>;
        cvss_vector: z.ZodOptional<z.ZodNullable<z.ZodString>>;
        cvss_score: z.ZodOptional<z.ZodNullable<z.ZodNumber>>;
        severity_label: z.ZodNullable<z.ZodEnum<["None", "Low", "Medium", "High", "Critical"]>>;
        explanation: z.ZodString;
        secure_patch: z.ZodString;
        recommendations: z.ZodArray<z.ZodString, "many">;
        confidence: z.ZodEnum<["Low", "Medium", "High"]>;
        mitre_attack_mapping: z.ZodOptional<z.ZodArray<z.ZodObject<{
            technique_id: z.ZodString;
            technique_name: z.ZodString;
            explanation: z.ZodString;
        }, "strip", z.ZodTypeAny, {
            explanation: string;
            technique_id: string;
            technique_name: string;
        }, {
            explanation: string;
            technique_id: string;
            technique_name: string;
        }>, "many">>;
        notes: z.ZodOptional<z.ZodNullable<z.ZodString>>;
    }, "strip", z.ZodTypeAny, {
        vulnerability_type: string | null;
        owasp_category: string | null;
        severity_label: "None" | "Low" | "Medium" | "High" | "Critical" | null;
        explanation: string;
        secure_patch: string;
        recommendations: string[];
        confidence: "Low" | "Medium" | "High";
        cvss_vector?: string | null | undefined;
        cvss_score?: number | null | undefined;
        mitre_attack_mapping?: {
            explanation: string;
            technique_id: string;
            technique_name: string;
        }[] | undefined;
        notes?: string | null | undefined;
    }, {
        vulnerability_type: string | null;
        owasp_category: string | null;
        severity_label: "None" | "Low" | "Medium" | "High" | "Critical" | null;
        explanation: string;
        secure_patch: string;
        recommendations: string[];
        confidence: "Low" | "Medium" | "High";
        cvss_vector?: string | null | undefined;
        cvss_score?: number | null | undefined;
        mitre_attack_mapping?: {
            explanation: string;
            technique_id: string;
            technique_name: string;
        }[] | undefined;
        notes?: string | null | undefined;
    }>, "many">;
}, "strip", z.ZodTypeAny, {
    is_vulnerable: boolean;
    vulnerabilities: {
        vulnerability_type: string | null;
        owasp_category: string | null;
        severity_label: "None" | "Low" | "Medium" | "High" | "Critical" | null;
        explanation: string;
        secure_patch: string;
        recommendations: string[];
        confidence: "Low" | "Medium" | "High";
        cvss_vector?: string | null | undefined;
        cvss_score?: number | null | undefined;
        mitre_attack_mapping?: {
            explanation: string;
            technique_id: string;
            technique_name: string;
        }[] | undefined;
        notes?: string | null | undefined;
    }[];
}, {
    is_vulnerable: boolean;
    vulnerabilities: {
        vulnerability_type: string | null;
        owasp_category: string | null;
        severity_label: "None" | "Low" | "Medium" | "High" | "Critical" | null;
        explanation: string;
        secure_patch: string;
        recommendations: string[];
        confidence: "Low" | "Medium" | "High";
        cvss_vector?: string | null | undefined;
        cvss_score?: number | null | undefined;
        mitre_attack_mapping?: {
            explanation: string;
            technique_id: string;
            technique_name: string;
        }[] | undefined;
        notes?: string | null | undefined;
    }[];
}>;
export type AnalyzeInput = z.infer<typeof analyzeInputSchema>;
export type SignupInput = z.infer<typeof signupSchema>;
export type LoginInput = z.infer<typeof loginSchema>;
export type Vulnerability = z.infer<typeof vulnerabilitySchema>;
export type LlmResponse = z.infer<typeof llmResponseSchema>;
/**
 * Sanitize a string for safe output (basic HTML entity encoding).
 * Prevents XSS when rendering user-provided content.
 */
export declare function sanitizeOutput(input: string): string;
/**
 * Truncate content for safe preview storage (no full user input in DB previews).
 */
export declare function createContentPreview(content: string, maxLength?: number): string;

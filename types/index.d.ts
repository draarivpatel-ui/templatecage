export const TEMPLATECAGE_VERSION: '1.0.0';

export interface TemplateCageErrorCodes {
  readonly INVALID_INPUT: 'TEMPLATECAGE_INVALID_INPUT';
  readonly INVALID_OPTIONS: 'TEMPLATECAGE_INVALID_OPTIONS';
  readonly RESOURCE_LIMIT: 'TEMPLATECAGE_RESOURCE_LIMIT';
  readonly INPUT_TOO_LONG: 'TEMPLATECAGE_INPUT_TOO_LONG';
  readonly CONTROL_CHARACTER: 'TEMPLATECAGE_CONTROL_CHARACTER';
  readonly BIDI_CONTROL: 'TEMPLATECAGE_BIDI_CONTROL';
  readonly UNPAIRED_SURROGATE: 'TEMPLATECAGE_UNPAIRED_SURROGATE';
  readonly UNCLOSED_TAG: 'TEMPLATECAGE_UNCLOSED_TAG';
  readonly TOO_MANY_TAGS: 'TEMPLATECAGE_TOO_MANY_TAGS';
  readonly NESTING_TOO_DEEP: 'TEMPLATECAGE_NESTING_TOO_DEEP';
  readonly EXPRESSION_TOO_LONG: 'TEMPLATECAGE_EXPRESSION_TOO_LONG';
  readonly LOOP_TOO_DEEP: 'TEMPLATECAGE_LOOP_TOO_DEEP';
  readonly UNBALANCED_TAG: 'TEMPLATECAGE_UNBALANCED_TAG';
  readonly DANGEROUS_IDENTIFIER: 'TEMPLATECAGE_DANGEROUS_IDENTIFIER';
  readonly CODE_EXECUTION: 'TEMPLATECAGE_CODE_EXECUTION';
  readonly SANDBOX_ESCAPE: 'TEMPLATECAGE_SANDBOX_ESCAPE';
  readonly PROTOTYPE_ACCESS: 'TEMPLATECAGE_PROTOTYPE_ACCESS';
  readonly OBFUSCATED_ACCESS: 'TEMPLATECAGE_OBFUSCATED_ACCESS';
  readonly DANGEROUS_DIRECTIVE: 'TEMPLATECAGE_DANGEROUS_DIRECTIVE';
  readonly FILE_INCLUSION: 'TEMPLATECAGE_FILE_INCLUSION';
  readonly RAW_HTML: 'TEMPLATECAGE_RAW_HTML';
  readonly UNSAFE_FILTER: 'TEMPLATECAGE_UNSAFE_FILTER';
  readonly UNSAFE_EXPRESSION: 'TEMPLATECAGE_UNSAFE_EXPRESSION';
  readonly UNSUPPORTED_TAG: 'TEMPLATECAGE_UNSUPPORTED_TAG';
  readonly PUG_CODE: 'TEMPLATECAGE_PUG_CODE';
  readonly TEMPLATE_INJECTION: 'TEMPLATECAGE_TEMPLATE_INJECTION';
  readonly OUTPUT_LIMIT: 'TEMPLATECAGE_OUTPUT_LIMIT';
  readonly ITERATION_LIMIT: 'TEMPLATECAGE_ITERATION_LIMIT';
  readonly TEMPLATE_INTEGRITY: 'TEMPLATECAGE_TEMPLATE_INTEGRITY';
  readonly UNSAFE_VALUE: 'TEMPLATECAGE_UNSAFE_VALUE';
  readonly INVALID_DATA: 'TEMPLATECAGE_INVALID_DATA';
  readonly INVALID_TEMPLATE: 'TEMPLATECAGE_INVALID_TEMPLATE';
  readonly POLICY_INVALID: 'TEMPLATECAGE_POLICY_INVALID';
  readonly UNKNOWN_POLICY: 'TEMPLATECAGE_UNKNOWN_POLICY';
  readonly CLI_USAGE: 'TEMPLATECAGE_CLI_USAGE';
  readonly INPUT_ERROR: 'TEMPLATECAGE_INPUT_ERROR';
}

export const TEMPLATECAGE_ERROR_CODES: TemplateCageErrorCodes;
export const CODE: TemplateCageErrorCodes;
export type TemplateCageErrorCode = TemplateCageErrorCodes[keyof TemplateCageErrorCodes];

export interface TemplateCageSeverityLevels {
  readonly CRITICAL: 'critical';
  readonly HIGH: 'high';
  readonly MEDIUM: 'medium';
  readonly LOW: 'low';
  readonly INFO: 'info';
}

export const TEMPLATECAGE_SEVERITY: TemplateCageSeverityLevels;
export type TemplateCageSeverity = TemplateCageSeverityLevels[keyof TemplateCageSeverityLevels];

export class TemplateCageError extends Error {
  constructor(code: TemplateCageErrorCode, message: string, detail?: Record<string, unknown>, offset?: number);
  readonly name: 'TemplateCageError';
  readonly code: TemplateCageErrorCode;
  readonly detail: Readonly<Record<string, unknown>>;
  readonly offset?: number;
  toJSON(): Record<string, unknown>;
}

export type TemplateMode = 'html' | 'text' | 'json';
export type TemplatePolicyName = 'strict' | 'email' | 'notification' | 'audit';
export type SafeFilterName = 'upper' | 'lower' | 'trim' | 'default' | 'truncate' | 'escapeHtml' | 'escapeUrl';

export interface TemplatePolicy {
  readonly name: string;
  readonly mode: TemplateMode;
  readonly maxBytes: number;
  readonly maxTags: number;
  readonly maxNestingDepth: number;
  readonly maxLoopDepth: number;
  readonly maxExpressionLength: number;
  readonly maxIterations: number;
  readonly maxOutputBytes: number;
  readonly maxFindings: number;
  readonly allowRawHtml: boolean;
  readonly allowIncludes: boolean;
  readonly allowDirectives: boolean;
  readonly allowLoops: boolean;
  readonly allowConditionals: boolean;
  readonly allowHelpers: boolean;
  readonly allowForeignSyntax: boolean;
  readonly enforceDataOnly: boolean;
  readonly detectPugLineCode: boolean;
  readonly allowedFilters: readonly SafeFilterName[];
}

export interface TemplatePolicyOptions {
  readonly policy?: TemplatePolicyName;
  readonly name?: string;
  readonly mode?: TemplateMode;
  readonly maxBytes?: number;
  readonly maxTags?: number;
  readonly maxNestingDepth?: number;
  readonly maxLoopDepth?: number;
  readonly maxExpressionLength?: number;
  readonly maxIterations?: number;
  readonly maxOutputBytes?: number;
  readonly maxFindings?: number;
  readonly allowRawHtml?: boolean;
  readonly allowIncludes?: boolean;
  readonly allowDirectives?: boolean;
  readonly allowLoops?: boolean;
  readonly allowConditionals?: boolean;
  readonly allowHelpers?: boolean;
  readonly allowForeignSyntax?: boolean;
  readonly enforceDataOnly?: boolean;
  readonly detectPugLineCode?: boolean;
  readonly allowedFilters?: readonly SafeFilterName[];
}

export type TemplateOptions = TemplatePolicyName | TemplatePolicyOptions | TemplatePolicy;

export interface TemplateFinding {
  readonly code: TemplateCageErrorCode;
  readonly severity: TemplateCageSeverity;
  readonly message: string;
  readonly offset: number;
  readonly length: number;
  readonly construct: string;
  readonly detail?: Readonly<Record<string, unknown>>;
}

export interface TemplateAuditReport {
  readonly safe: boolean;
  readonly policy: string;
  readonly inputBytes: number;
  readonly inputLength: number;
  readonly tagCount: number;
  readonly dialects: readonly string[];
  readonly truncatedFindings: boolean;
  readonly maxFindings: number;
  readonly findings: readonly TemplateFinding[];
}

export interface CompiledTemplate {
  readonly kind: 'templatecage-compiled-template';
  readonly policy: TemplatePolicy;
  readonly inputBytes: number;
  readonly variables: readonly string[];
}

export type TemplateData = Record<string, unknown>;

export const SAFE_FILTER_NAMES: readonly SafeFilterName[];
export const TEMPLATE_POLICY_PRESETS: Readonly<Record<TemplatePolicyName, TemplatePolicy>>;

export function getPolicy(name: TemplatePolicyName): TemplatePolicy;
export function createTemplatePolicy(options?: TemplatePolicyOptions): TemplatePolicy;
export function auditTemplate(template: string, options?: TemplateOptions): TemplateAuditReport;
export function isSafeTemplate(template: string, options?: TemplateOptions): boolean;
export function validateTemplate(template: string, options?: TemplateOptions): TemplateAuditReport;
export function compileTemplate(template: string, options?: TemplateOptions): CompiledTemplate;
export function renderTemplate(template: string | CompiledTemplate, data?: TemplateData, options?: TemplateOptions): string;
export function extractTemplateVariables(template: string | CompiledTemplate, options?: TemplateOptions): readonly string[];

/* Typed errors, stable public codes, and small immutability helpers. */

export const TEMPLATECAGE_ERROR_CODES = Object.freeze({
  INVALID_INPUT: 'TEMPLATECAGE_INVALID_INPUT',
  INVALID_OPTIONS: 'TEMPLATECAGE_INVALID_OPTIONS',
  RESOURCE_LIMIT: 'TEMPLATECAGE_RESOURCE_LIMIT',
  INPUT_TOO_LONG: 'TEMPLATECAGE_INPUT_TOO_LONG',
  CONTROL_CHARACTER: 'TEMPLATECAGE_CONTROL_CHARACTER',
  BIDI_CONTROL: 'TEMPLATECAGE_BIDI_CONTROL',
  UNPAIRED_SURROGATE: 'TEMPLATECAGE_UNPAIRED_SURROGATE',
  UNCLOSED_TAG: 'TEMPLATECAGE_UNCLOSED_TAG',
  TOO_MANY_TAGS: 'TEMPLATECAGE_TOO_MANY_TAGS',
  NESTING_TOO_DEEP: 'TEMPLATECAGE_NESTING_TOO_DEEP',
  EXPRESSION_TOO_LONG: 'TEMPLATECAGE_EXPRESSION_TOO_LONG',
  LOOP_TOO_DEEP: 'TEMPLATECAGE_LOOP_TOO_DEEP',
  UNBALANCED_TAG: 'TEMPLATECAGE_UNBALANCED_TAG',
  DANGEROUS_IDENTIFIER: 'TEMPLATECAGE_DANGEROUS_IDENTIFIER',
  CODE_EXECUTION: 'TEMPLATECAGE_CODE_EXECUTION',
  SANDBOX_ESCAPE: 'TEMPLATECAGE_SANDBOX_ESCAPE',
  PROTOTYPE_ACCESS: 'TEMPLATECAGE_PROTOTYPE_ACCESS',
  OBFUSCATED_ACCESS: 'TEMPLATECAGE_OBFUSCATED_ACCESS',
  DANGEROUS_DIRECTIVE: 'TEMPLATECAGE_DANGEROUS_DIRECTIVE',
  FILE_INCLUSION: 'TEMPLATECAGE_FILE_INCLUSION',
  RAW_HTML: 'TEMPLATECAGE_RAW_HTML',
  UNSAFE_FILTER: 'TEMPLATECAGE_UNSAFE_FILTER',
  UNSAFE_EXPRESSION: 'TEMPLATECAGE_UNSAFE_EXPRESSION',
  UNSUPPORTED_TAG: 'TEMPLATECAGE_UNSUPPORTED_TAG',
  PUG_CODE: 'TEMPLATECAGE_PUG_CODE',
  TEMPLATE_INJECTION: 'TEMPLATECAGE_TEMPLATE_INJECTION',
  OUTPUT_LIMIT: 'TEMPLATECAGE_OUTPUT_LIMIT',
  ITERATION_LIMIT: 'TEMPLATECAGE_ITERATION_LIMIT',
  TEMPLATE_INTEGRITY: 'TEMPLATECAGE_TEMPLATE_INTEGRITY',
  UNSAFE_VALUE: 'TEMPLATECAGE_UNSAFE_VALUE',
  INVALID_DATA: 'TEMPLATECAGE_INVALID_DATA',
  INVALID_TEMPLATE: 'TEMPLATECAGE_INVALID_TEMPLATE',
  POLICY_INVALID: 'TEMPLATECAGE_POLICY_INVALID',
  UNKNOWN_POLICY: 'TEMPLATECAGE_UNKNOWN_POLICY',
  CLI_USAGE: 'TEMPLATECAGE_CLI_USAGE',
  INPUT_ERROR: 'TEMPLATECAGE_INPUT_ERROR'
});

export const CODE = TEMPLATECAGE_ERROR_CODES;

export const TEMPLATECAGE_SEVERITY = Object.freeze({
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low',
  INFO: 'info'
});

const FORBIDDEN_COPY_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

function copyDetailValue(value, depth) {
  if (value === null) return null;
  const type = typeof value;
  if (type === 'string' || type === 'number' || type === 'boolean' || type === 'bigint') return value;
  if (type === 'undefined') return undefined;
  if (type === 'symbol' || type === 'function') return String(type);
  if (depth <= 0) return '[truncated]';
  if (Array.isArray(value)) {
    const output = [];
    const length = Math.min(value.length, 32);
    for (let index = 0; index < length; index += 1) output.push(copyDetailValue(value[index], depth - 1));
    return Object.freeze(output);
  }
  const output = Object.create(null);
  let count = 0;
  for (const key of Object.keys(value)) {
    if (count >= 32) break;
    if (FORBIDDEN_COPY_KEYS.has(key)) continue;
    const copied = copyDetailValue(value[key], depth - 1);
    if (copied !== undefined) output[key] = copied;
    count += 1;
  }
  return Object.freeze(output);
}

function copyDetail(detail) {
  const output = Object.create(null);
  if (!detail || typeof detail !== 'object') return Object.freeze(output);
  for (const key of Object.keys(detail)) {
    if (FORBIDDEN_COPY_KEYS.has(key)) continue;
    const copied = copyDetailValue(detail[key], 5);
    if (copied !== undefined) output[key] = copied;
  }
  return Object.freeze(output);
}

export class TemplateCageError extends Error {
  constructor(code, message, detail, offset) {
    super(String(code) + ': ' + String(message));
    this.name = 'TemplateCageError';
    this.code = code;
    this.detail = copyDetail(detail);
    if (typeof offset === 'number' && Number.isSafeInteger(offset) && offset >= 0) {
      this.offset = offset;
    } else if (this.detail && typeof this.detail.offset === 'number') {
      this.offset = this.detail.offset;
    }
  }

  toJSON() {
    const output = {
      name: this.name,
      code: this.code,
      message: this.message,
      detail: this.detail
    };
    if (typeof this.offset === 'number') output.offset = this.offset;
    return output;
  }
}

export function deepFreezeGenerated(value) {
  if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value;
  const pending = [value];
  const seen = new Set();
  while (pending.length > 0) {
    const item = pending.pop();
    if (!item || typeof item !== 'object' || seen.has(item)) continue;
    seen.add(item);
    if (Array.isArray(item)) {
      for (const child of item) {
        if (child && typeof child === 'object') pending.push(child);
      }
    } else {
      for (const key of Object.keys(item)) {
        const child = item[key];
        if (child && typeof child === 'object') pending.push(child);
      }
    }
    Object.freeze(item);
  }
  return value;
}

export function own(object, key) {
  return Object.hasOwn(object, key);
}

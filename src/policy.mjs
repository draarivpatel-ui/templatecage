/* Frozen security policies and presets. */

import { CODE, TemplateCageError, deepFreezeGenerated, own } from './errors.mjs';

export const SAFE_FILTER_NAMES = Object.freeze([
  'upper',
  'lower',
  'trim',
  'default',
  'truncate',
  'escapeHtml',
  'escapeUrl'
]);

const BOOLEAN_KEYS = Object.freeze([
  'allowRawHtml',
  'allowIncludes',
  'allowDirectives',
  'allowLoops',
  'allowConditionals',
  'allowHelpers',
  'allowForeignSyntax',
  'enforceDataOnly',
  'detectPugLineCode'
]);

const LIMIT_KEYS = Object.freeze([
  'maxBytes',
  'maxTags',
  'maxNestingDepth',
  'maxLoopDepth',
  'maxExpressionLength',
  'maxIterations',
  'maxOutputBytes',
  'maxFindings'
]);

const OPTION_KEYS = new Set([
  'policy',
  'name',
  'mode',
  'allowedFilters',
  ...LIMIT_KEYS,
  ...BOOLEAN_KEYS
]);

function policyObject(values) {
  const output = Object.create(null);
  for (const key of Object.keys(values)) output[key] = values[key];
  return deepFreezeGenerated(output);
}

function baseValues(name, mode, overrides) {
  const values = {
    name,
    mode,
    maxBytes: 65536,
    maxTags: 256,
    maxNestingDepth: 8,
    maxLoopDepth: 2,
    maxExpressionLength: 384,
    maxIterations: 500,
    maxOutputBytes: 131072,
    maxFindings: 100,
    allowRawHtml: false,
    allowIncludes: false,
    allowDirectives: false,
    allowLoops: true,
    allowConditionals: true,
    allowHelpers: false,
    allowForeignSyntax: false,
    enforceDataOnly: true,
    detectPugLineCode: true,
    allowedFilters: SAFE_FILTER_NAMES.slice()
  };
  for (const key of Object.keys(overrides)) values[key] = overrides[key];
  return values;
}

const STRICT_VALUES = baseValues('strict', 'html', {
  maxBytes: 32768,
  maxTags: 128,
  maxNestingDepth: 6,
  maxLoopDepth: 2,
  maxExpressionLength: 256,
  maxIterations: 200,
  maxOutputBytes: 65536
});

const EMAIL_VALUES = baseValues('email', 'html', {
  maxBytes: 131072,
  maxTags: 512,
  maxNestingDepth: 8,
  maxLoopDepth: 3,
  maxExpressionLength: 384,
  maxIterations: 1000,
  maxOutputBytes: 262144
});

const NOTIFICATION_VALUES = baseValues('notification', 'text', {
  maxBytes: 8192,
  maxTags: 64,
  maxNestingDepth: 4,
  maxLoopDepth: 0,
  maxExpressionLength: 192,
  maxIterations: 0,
  maxOutputBytes: 16384,
  allowLoops: false
});

const AUDIT_VALUES = baseValues('audit', 'html', {
  maxBytes: 262144,
  maxTags: 1024,
  maxNestingDepth: 12,
  maxLoopDepth: 3,
  maxExpressionLength: 1024,
  maxIterations: 1000,
  maxOutputBytes: 262144,
  maxFindings: 200,
  allowForeignSyntax: true,
  enforceDataOnly: false
});

const PRESETS = Object.freeze({
  strict: policyObject(STRICT_VALUES),
  email: policyObject(EMAIL_VALUES),
  notification: policyObject(NOTIFICATION_VALUES),
  audit: policyObject(AUDIT_VALUES)
});

export const TEMPLATE_POLICY_PRESETS = PRESETS;

export function getPolicy(name) {
  if (typeof name !== 'string' || !own(PRESETS, name)) {
    throw new TemplateCageError(CODE.UNKNOWN_POLICY, 'unknown template policy preset', { value: typeof name === 'string' ? name : typeof name });
  }
  return PRESETS[name];
}

function validateLimit(key, value) {
  if (typeof value !== 'number' || !Number.isSafeInteger(value)) {
    throw new TemplateCageError(CODE.INVALID_OPTIONS, 'policy limit must be a safe integer', { key, value: String(value) });
  }
  const minimum = key === 'maxLoopDepth' || key === 'maxIterations' || key === 'maxFindings' ? 0 : 1;
  const maximum = key === 'maxBytes' || key === 'maxOutputBytes' ? 268435456 : 1000000;
  if (value < minimum || value > maximum) {
    throw new TemplateCageError(CODE.INVALID_OPTIONS, 'policy limit is outside the supported range', { key, limit: maximum, actual: value });
  }
}

function validateFilterList(value) {
  if (!Array.isArray(value)) {
    throw new TemplateCageError(CODE.INVALID_OPTIONS, 'allowedFilters must be an array');
  }
  if (value.length > SAFE_FILTER_NAMES.length) {
    throw new TemplateCageError(CODE.INVALID_OPTIONS, 'allowedFilters contains duplicate or unknown entries');
  }
  const seen = new Set();
  const output = [];
  for (const item of value) {
    if (typeof item !== 'string' || !SAFE_FILTER_NAMES.includes(item) || seen.has(item)) {
      throw new TemplateCageError(CODE.INVALID_OPTIONS, 'unknown or duplicate safe filter name', { value: String(item) });
    }
    seen.add(item);
    output.push(item);
  }
  return output;
}

function validatePolicyValues(values) {
  if (values.mode !== 'html' && values.mode !== 'text' && values.mode !== 'json') {
    throw new TemplateCageError(CODE.INVALID_OPTIONS, 'policy mode must be html, text, or json', { value: String(values.mode) });
  }
  for (const key of LIMIT_KEYS) validateLimit(key, values[key]);
  for (const key of BOOLEAN_KEYS) {
    if (typeof values[key] !== 'boolean') {
      throw new TemplateCageError(CODE.INVALID_OPTIONS, 'policy boolean option is invalid', { key, value: String(values[key]) });
    }
  }
  values.allowedFilters = validateFilterList(values.allowedFilters);
  if (typeof values.name !== 'string' || values.name.length === 0 || values.name.length > 64) {
    throw new TemplateCageError(CODE.INVALID_OPTIONS, 'policy name is invalid');
  }
  if (!values.allowLoops) values.maxLoopDepth = 0;
  return values;
}

function mergePolicy(base, overrides) {
  const values = Object.create(null);
  for (const key of Object.keys(base)) {
    if (key === 'allowedFilters') values[key] = base[key].slice();
    else values[key] = base[key];
  }
  for (const key of Object.keys(overrides)) {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype' || key === 'policy') continue;
    if (!OPTION_KEYS.has(key)) {
      throw new TemplateCageError(CODE.INVALID_OPTIONS, 'unknown template policy option', { key });
    }
    if (key === 'allowedFilters') values[key] = validateFilterList(overrides[key]);
    else values[key] = overrides[key];
  }
  return validatePolicyValues(values);
}

export function createTemplatePolicy(options) {
  if (options === undefined) return getPolicy('strict');
  if (!options || typeof options !== 'object' || Array.isArray(options)) {
    throw new TemplateCageError(CODE.INVALID_OPTIONS, 'template policy options must be an object');
  }
  const base = typeof options.policy === 'string' ? getPolicy(options.policy) : getPolicy('strict');
  const values = mergePolicy(base, options);
  return policyObject(values);
}

export function resolveTemplatePolicy(options) {
  if (options === undefined) return getPolicy('strict');
  if (typeof options === 'string') return getPolicy(options);
  if (!options || typeof options !== 'object' || Array.isArray(options)) {
    throw new TemplateCageError(CODE.INVALID_OPTIONS, 'template options must be a policy preset name or object');
  }
  if (typeof options.policy === 'string') return createTemplatePolicy(options);
  for (const presetName of Object.keys(PRESETS)) {
    if (options === PRESETS[presetName]) return options;
  }
  return createTemplatePolicy(options);
}

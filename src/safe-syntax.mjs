/* Parser for the intentionally small data-only renderer expression language. */

import { CODE, TemplateCageError } from './errors.mjs';
import { parseStringLiteral } from './scan-utils.mjs';

const BLOCKED_PATH_NAMES = new Set([
  '__proto__',
  'constructor',
  'prototype',
  'tostring',
  'valueof',
  'hasownproperty',
  'isprototypeof',
  'propertyisenumerable',
  'tolocalestring',
  '__definegetter__',
  '__lookupgetter__',
  '__definesetter__',
  '__lookupsetter__',
  '__class__',
  '__dict__',
  '__globals__',
  '__builtins__',
  '__import__',
  'globalthis',
  'global',
  'process',
  'mainmodule',
  'module',
  'exports',
  'require',
  'function',
  'eval',
  'reflect',
  'proxy',
  'child_process',
  'buffer',
  'import',
  'importmeta',
  'os',
  'subprocess'
]);

function syntaxError(message, offset, detail) {
  const merged = detail && typeof detail === 'object' ? detail : Object.create(null);
  return new TemplateCageError(CODE.UNSAFE_EXPRESSION, message, merged, offset);
}

function isPathCharacter(code) {
  return (code >= 48 && code <= 57) ||
    (code >= 65 && code <= 90) ||
    (code >= 97 && code <= 122) ||
    code === 95 ||
    code === 36 ||
    code === 45;
}

export function isBlockedPathSegment(segment) {
  const lower = String(segment).toLowerCase();
  return BLOCKED_PATH_NAMES.has(lower) || lower.startsWith('__') || lower.endsWith('__');
}

export function parseDataPath(input, offset) {
  const text = String(input).trim();
  if (text.length === 0) throw syntaxError('empty data path', offset);
  if (text === '.' || text === 'this') return Object.freeze({ text, kind: 'current', segments: Object.freeze([]) });
  if (text === '@index' || text === '@first' || text === '@last' || text === '@length') {
    return Object.freeze({ text, kind: 'loop-meta', segments: Object.freeze([text]) });
  }
  if (text.startsWith('@')) throw syntaxError('unknown loop metadata path', offset, { value: text });
  const currentPrefixed = text.startsWith('this.');
  const pathText = currentPrefixed ? text.slice(5) : text;
  if (currentPrefixed && pathText.length === 0) throw syntaxError('empty data path after this prefix', offset);
  const rawSegments = pathText.split('.');
  const segments = [];
  for (const segment of rawSegments) {
    if (segment.length === 0 || segment.length > 128) throw syntaxError('data path contains an empty or oversized segment', offset, { value: text });
    for (let index = 0; index < segment.length; index += 1) {
      if (!isPathCharacter(segment.charCodeAt(index))) {
        throw syntaxError('data path contains an unsupported character', offset, { value: segment });
      }
    }
    if (isBlockedPathSegment(segment)) {
      throw new TemplateCageError(CODE.PROTOTYPE_ACCESS, 'data path names a forbidden prototype or object member', { value: segment }, offset);
    }
    segments.push(segment);
  }
  return Object.freeze({ text, kind: currentPrefixed ? 'current-path' : 'path', segments: Object.freeze(segments) });
}

function splitPipes(text) {
  const parts = [];
  let start = 0;
  let quote = null;
  let escaped = false;
  for (let index = 0; index < text.length; index += 1) {
    const character = text[index];
    if (quote !== null) {
      if (escaped) {
        escaped = false;
      } else if (character === '\\') {
        escaped = true;
      } else if (character === quote) {
        quote = null;
      }
      continue;
    }
    if (character === "'" || character === '"') {
      quote = character;
      continue;
    }
    if (character === '|') {
      parts.push(text.slice(start, index));
      start = index + 1;
    }
  }
  parts.push(text.slice(start));
  return parts;
}

function splitFilterHead(text) {
  let quote = null;
  let escaped = false;
  for (let index = 0; index < text.length; index += 1) {
    const character = text[index];
    if (quote !== null) {
      if (escaped) escaped = false;
      else if (character === '\\') escaped = true;
      else if (character === quote) quote = null;
      continue;
    }
    if (character === "'" || character === '"') {
      quote = character;
      continue;
    }
    if (character === ':') return [text.slice(0, index), text.slice(index + 1)];
  }
  return [text, null];
}

function parseLiteral(raw, offset) {
  const text = raw.trim();
  if (text.length === 0) throw syntaxError('filter argument is empty', offset);
  if (text[0] === "'" || text[0] === '"') {
    const parsed = parseStringLiteral(text, 0);
    if (!parsed || parsed.end !== text.length) throw syntaxError('filter string argument is malformed', offset, { value: text });
    return parsed.value;
  }
  if (text === 'true') return true;
  if (text === 'false') return false;
  if (text === 'null') return null;
  let numeric = true;
  let digitCount = 0;
  for (let index = 0; index < text.length; index += 1) {
    const code = text.charCodeAt(index);
    const digit = code >= 48 && code <= 57;
    if (digit) digitCount += 1;
    if (!(digit || (index === 0 && code === 45) || code === 46)) numeric = false;
  }
  if (numeric && digitCount > 0) {
    const value = Number(text);
    if (Number.isFinite(value)) return value;
  }
  throw syntaxError('filter argument must be a quoted string, number, boolean, or null', offset, { value: text });
}

export function parseSafeExpression(input, policy, offset) {
  const original = String(input);
  const text = original.trim();
  if (text.length === 0) throw syntaxError('empty interpolation expression', offset);
  const pieces = splitPipes(text);
  const path = parseDataPath(pieces[0], offset);
  const filters = [];
  for (let index = 1; index < pieces.length; index += 1) {
    const piece = pieces[index].trim();
    if (piece.length === 0) throw syntaxError('empty filter in interpolation expression', offset);
    const pair = splitFilterHead(piece);
    const name = pair[0].trim();
    if (!/^[A-Za-z][A-Za-z0-9]*$/u.test(name)) throw syntaxError('filter name is malformed', offset, { value: name });
    if (!policy.allowedFilters.includes(name)) {
      throw new TemplateCageError(CODE.UNSAFE_FILTER, 'filter is not in the allowlist', { value: name }, offset);
    }
    let argument;
    if (pair[1] !== null) argument = parseLiteral(pair[1], offset);
    if ((name === 'default' || name === 'truncate') && argument === undefined) {
      throw syntaxError('filter requires one literal argument', offset, { value: name });
    }
    if ((name === 'upper' || name === 'lower' || name === 'trim' || name === 'escapeHtml' || name === 'escapeUrl') && argument !== undefined) {
      throw syntaxError('filter does not accept an argument', offset, { value: name });
    }
    if (name === 'truncate') {
      if (typeof argument !== 'number' || !Number.isSafeInteger(argument) || argument < 0 || argument > 100000) {
        throw new TemplateCageError(CODE.INVALID_TEMPLATE, 'truncate filter length must be an integer from 0 to 100000', { value: String(argument) }, offset);
      }
    }
    const filter = { name };
    if (argument !== undefined) filter.argument = argument;
    filters.push(Object.freeze(filter));
  }
  return Object.freeze({ text, path, filters: Object.freeze(filters) });
}

export function parseSectionTarget(input, offset) {
  const text = String(input).trim();
  if (text.length === 0) throw syntaxError('section target is empty', offset);
  if (text.includes('|')) throw syntaxError('sections accept a data path without filters', offset);
  return parseDataPath(text, offset);
}

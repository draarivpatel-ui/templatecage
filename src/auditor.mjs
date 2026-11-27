/* Iterative multi-dialect SSTI auditor. */

import { CODE, TEMPLATECAGE_SEVERITY, TemplateCageError, deepFreezeGenerated } from './errors.mjs';
import { resolveTemplatePolicy } from './policy.mjs';
import { boundedExcerpt, firstWord, hasIdentifierCall, hasPipeFilter, hostileCharacterKind, identifierOffsets, stringConcatenations, utf8Length } from './scan-utils.mjs';
import { parseSafeExpression, parseSectionTarget } from './safe-syntax.mjs';

const SEVERITY = TEMPLATECAGE_SEVERITY;

const OPENERS = Object.freeze([
  Object.freeze({ open: '{{{', close: '}}}', kind: 'triple-mustache', dialect: 'handlebars' }),
  Object.freeze({ open: '{{', close: '}}', kind: 'mustache', dialect: 'mustache' }),
  Object.freeze({ open: '{%', close: '%}', kind: 'statement', dialect: 'jinja-twig-liquid' }),
  Object.freeze({ open: '{#', close: '#}', kind: 'comment', dialect: 'jinja-twig' }),
  Object.freeze({ open: '</#', close: '>', kind: 'freemarker-close', dialect: 'freemarker' }),
  Object.freeze({ open: '<#', close: '>', kind: 'freemarker', dialect: 'freemarker' }),
  Object.freeze({ open: '<@', close: '>', kind: 'freemarker-macro', dialect: 'freemarker' }),
  Object.freeze({ open: '<%', close: '%>', kind: 'ejs', dialect: 'ejs' }),
  Object.freeze({ open: '${', close: '}', kind: 'javascript', dialect: 'javascript-template' }),
  Object.freeze({ open: '#{', close: '}', kind: 'pug', dialect: 'pug-ruby' }),
  Object.freeze({ open: '!{', close: '}', kind: 'pug-unescaped', dialect: 'pug-ruby' }),
  Object.freeze({ open: '%{', close: '}', kind: 'ognl', dialect: 'ognl' }),
  Object.freeze({ open: '*{', close: '}', kind: 'thymeleaf-selection', dialect: 'thymeleaf' }),
  Object.freeze({ open: '@{', close: '}', kind: 'thymeleaf-url', dialect: 'thymeleaf' }),
  Object.freeze({ open: '~{', close: '}', kind: 'thymeleaf-fragment', dialect: 'thymeleaf' })
]);

const DANGEROUS_TERMS = Object.freeze([
  Object.freeze({ name: '__proto__', code: CODE.PROTOTYPE_ACCESS, severity: SEVERITY.CRITICAL, reason: 'prototype chain access' }),
  Object.freeze({ name: 'constructor', code: CODE.PROTOTYPE_ACCESS, severity: SEVERITY.CRITICAL, reason: 'constructor access can reach Function' }),
  Object.freeze({ name: 'prototype', code: CODE.PROTOTYPE_ACCESS, severity: SEVERITY.HIGH, reason: 'prototype member access' }),
  Object.freeze({ name: 'globalthis', code: CODE.SANDBOX_ESCAPE, severity: SEVERITY.CRITICAL, reason: 'global object access' }),
  Object.freeze({ name: 'global', code: CODE.SANDBOX_ESCAPE, severity: SEVERITY.CRITICAL, reason: 'Node global object access' }),
  Object.freeze({ name: 'process', code: CODE.SANDBOX_ESCAPE, severity: SEVERITY.CRITICAL, reason: 'Node process object access' }),
  Object.freeze({ name: 'mainmodule', code: CODE.SANDBOX_ESCAPE, severity: SEVERITY.CRITICAL, reason: 'Node module escape access' }),
  Object.freeze({ name: 'module', code: CODE.SANDBOX_ESCAPE, severity: SEVERITY.HIGH, reason: 'Node module object access' }),
  Object.freeze({ name: 'exports', code: CODE.SANDBOX_ESCAPE, severity: SEVERITY.HIGH, reason: 'Node exports object access' }),
  Object.freeze({ name: 'require', code: CODE.CODE_EXECUTION, severity: SEVERITY.CRITICAL, reason: 'module loading primitive' }),
  Object.freeze({ name: 'function', code: CODE.CODE_EXECUTION, severity: SEVERITY.CRITICAL, reason: 'dynamic Function constructor access' }),
  Object.freeze({ name: 'eval', code: CODE.CODE_EXECUTION, severity: SEVERITY.CRITICAL, reason: 'dynamic eval access' }),
  Object.freeze({ name: 'reflect', code: CODE.SANDBOX_ESCAPE, severity: SEVERITY.HIGH, reason: 'reflection escape primitive' }),
  Object.freeze({ name: 'proxy', code: CODE.SANDBOX_ESCAPE, severity: SEVERITY.HIGH, reason: 'proxy escape primitive' }),
  Object.freeze({ name: 'child_process', code: CODE.CODE_EXECUTION, severity: SEVERITY.CRITICAL, reason: 'process execution module' }),
  Object.freeze({ name: 'fs', code: CODE.CODE_EXECUTION, severity: SEVERITY.HIGH, reason: 'file system module object' }),
  Object.freeze({ name: 'buffer', code: CODE.SANDBOX_ESCAPE, severity: SEVERITY.HIGH, reason: 'Node Buffer object access' }),
  Object.freeze({ name: 'lookup', code: CODE.SANDBOX_ESCAPE, severity: SEVERITY.HIGH, reason: 'dynamic Handlebars lookup helper' }),
  Object.freeze({ name: 'with', code: CODE.DANGEROUS_DIRECTIVE, severity: SEVERITY.MEDIUM, reason: 'context-changing template helper' }),
  Object.freeze({ name: '__definegetter__', code: CODE.PROTOTYPE_ACCESS, severity: SEVERITY.CRITICAL, reason: 'prototype mutation member' }),
  Object.freeze({ name: '__lookupgetter__', code: CODE.PROTOTYPE_ACCESS, severity: SEVERITY.CRITICAL, reason: 'prototype introspection member' }),
  Object.freeze({ name: '__definesetter__', code: CODE.PROTOTYPE_ACCESS, severity: SEVERITY.CRITICAL, reason: 'prototype mutation member' }),
  Object.freeze({ name: '__lookupsetter__', code: CODE.PROTOTYPE_ACCESS, severity: SEVERITY.CRITICAL, reason: 'prototype introspection member' }),
  Object.freeze({ name: 'cycler', code: CODE.SANDBOX_ESCAPE, severity: SEVERITY.HIGH, reason: 'Jinja or Nunjucks cycler global' }),
  Object.freeze({ name: 'joiner', code: CODE.SANDBOX_ESCAPE, severity: SEVERITY.HIGH, reason: 'Jinja or Nunjucks joiner global' }),
  Object.freeze({ name: 'namespace', code: CODE.SANDBOX_ESCAPE, severity: SEVERITY.HIGH, reason: 'Jinja namespace object' }),
  Object.freeze({ name: 'lipsum', code: CODE.SANDBOX_ESCAPE, severity: SEVERITY.MEDIUM, reason: 'Jinja lipsum global' }),
  Object.freeze({ name: 'self', code: CODE.SANDBOX_ESCAPE, severity: SEVERITY.MEDIUM, reason: 'template self object reference' }),
  Object.freeze({ name: 'request', code: CODE.SANDBOX_ESCAPE, severity: SEVERITY.HIGH, reason: 'web framework request object' }),
  Object.freeze({ name: 'config', code: CODE.SANDBOX_ESCAPE, severity: SEVERITY.HIGH, reason: 'framework config object' }),
  Object.freeze({ name: 'url_for', code: CODE.SANDBOX_ESCAPE, severity: SEVERITY.MEDIUM, reason: 'framework URL helper' }),
  Object.freeze({ name: 'get_flashed_messages', code: CODE.SANDBOX_ESCAPE, severity: SEVERITY.MEDIUM, reason: 'framework message helper' }),
  Object.freeze({ name: '__class__', code: CODE.PROTOTYPE_ACCESS, severity: SEVERITY.CRITICAL, reason: 'Python class escape member' }),
  Object.freeze({ name: '__mro__', code: CODE.PROTOTYPE_ACCESS, severity: SEVERITY.CRITICAL, reason: 'Python MRO escape member' }),
  Object.freeze({ name: '__base__', code: CODE.PROTOTYPE_ACCESS, severity: SEVERITY.CRITICAL, reason: 'Python base class escape member' }),
  Object.freeze({ name: '__bases__', code: CODE.PROTOTYPE_ACCESS, severity: SEVERITY.CRITICAL, reason: 'Python bases escape member' }),
  Object.freeze({ name: '__subclasses__', code: CODE.PROTOTYPE_ACCESS, severity: SEVERITY.CRITICAL, reason: 'Python subclass enumeration escape' }),
  Object.freeze({ name: '__globals__', code: CODE.SANDBOX_ESCAPE, severity: SEVERITY.CRITICAL, reason: 'Python globals escape member' }),
  Object.freeze({ name: '__builtins__', code: CODE.SANDBOX_ESCAPE, severity: SEVERITY.CRITICAL, reason: 'Python builtins escape member' }),
  Object.freeze({ name: '__import__', code: CODE.CODE_EXECUTION, severity: SEVERITY.CRITICAL, reason: 'Python import primitive' }),
  Object.freeze({ name: '__init__', code: CODE.PROTOTYPE_ACCESS, severity: SEVERITY.HIGH, reason: 'Python initialization escape member' }),
  Object.freeze({ name: '__dict__', code: CODE.PROTOTYPE_ACCESS, severity: SEVERITY.HIGH, reason: 'Python dictionary introspection member' }),
  Object.freeze({ name: 'subprocess', code: CODE.CODE_EXECUTION, severity: SEVERITY.CRITICAL, reason: 'process execution module' }),
  Object.freeze({ name: 'importlib', code: CODE.CODE_EXECUTION, severity: SEVERITY.HIGH, reason: 'dynamic import module' }),
  Object.freeze({ name: 'pickle', code: CODE.CODE_EXECUTION, severity: SEVERITY.HIGH, reason: 'unsafe deserialization module' }),
  Object.freeze({ name: 'marshal', code: CODE.CODE_EXECUTION, severity: SEVERITY.HIGH, reason: 'unsafe serialization module' })
]);

const OBFUSCATION_TERMS = Object.freeze([
  '__proto__',
  'constructor',
  'prototype',
  '__class__',
  '__globals__',
  '__builtins__',
  '__import__',
  'process',
  'require',
  'function',
  'eval',
  'module',
  'exports',
  'global',
  'child_process',
  'subprocess',
  'os.popen',
  'mainmodule',
  'globalthis'
]);

const FILE_DIRECTIVES = new Set(['include', 'extends', 'import', 'from', 'embed', 'use', 'render']);
const dangerousStatementDirectives = new Set(['macro', 'set', 'call', 'raw', 'assign', 'capture', 'do', 'filter', 'block', 'endblock']);
const LOOP_DIRECTIVES = new Set(['for', 'each', 'range', 'while', 'tablerow']);
const BLOCK_OPENERS = new Set(['if', 'for', 'block', 'macro', 'call', 'filter', 'raw', 'unless', 'each', 'with', 'capture', 'case', 'form', 'paginate', 'tablerow', 'define', 'range']);

function makeFinding(code, severity, message, offset, length, construct, detail) {
  const output = {
    code,
    severity,
    message,
    offset,
    length,
    construct
  };
  if (detail && typeof detail === 'object') output.detail = detail;
  return output;
}

function addFinding(state, code, severity, message, offset, length, construct, detail) {
  if (state.findings.length >= state.policy.maxFindings) {
    state.truncatedFindings = true;
    return;
  }
  state.findings.push(makeFinding(code, severity, message, offset, length, construct, detail));
}


function findBalancedBraceClose(text, start) {
  let depth = 0;
  let quote = null;
  let escaped = false;
  for (let index = start; index < text.length; index += 1) {
    const character = text[index];
    if (quote !== null) {
      if (escaped) escaped = false;
      else if (character === '\\') escaped = true;
      else if (character === quote) quote = null;
      continue;
    }
    if (character === "'" || character === '"' || character === '`') {
      quote = character;
      continue;
    }
    if (character === '{') {
      depth += 1;
      continue;
    }
    if (character === '}') {
      if (depth === 0) return index;
      depth -= 1;
    }
  }
  return -1;
}

function scanDelimitedTags(text) {
  const tags = [];
  let cursor = 0;
  while (cursor < text.length) {
    let opener = null;
    for (const candidate of OPENERS) {
      if (text.startsWith(candidate.open, cursor)) {
        opener = candidate;
        break;
      }
    }
    if (!opener) {
      cursor += 1;
      continue;
    }
    const contentStart = cursor + opener.open.length;
    const closeAt = opener.close === '}' ? findBalancedBraceClose(text, contentStart) : text.indexOf(opener.close, contentStart);
    const unclosed = closeAt === -1;
    const contentEnd = unclosed ? text.length : closeAt;
    const end = unclosed ? text.length : closeAt + opener.close.length;
    tags.push({
      start: cursor,
      end,
      contentStart,
      contentEnd,
      body: text.slice(contentStart, contentEnd),
      kind: opener.kind,
      dialect: opener.dialect,
      open: opener.open,
      close: opener.close,
      unclosed
    });
    cursor = end;
  }
  return tags;
}

function compactExpression(text) {
  let output = '';
  let quote = null;
  let escaped = false;
  let pendingWhitespace = false;
  for (let index = 0; index < text.length; index += 1) {
    const character = text[index];
    if (quote !== null) {
      output += character;
      if (escaped) escaped = false;
      else if (character === '\\') escaped = true;
      else if (character === quote) quote = null;
      continue;
    }
    if (character === "'" || character === '"' || character === '`') {
      quote = character;
      output += character;
      pendingWhitespace = false;
      continue;
    }
    if (/\s/u.test(character)) {
      pendingWhitespace = true;
      continue;
    }
    const punctuation = character === '.' || character === '[' || character === ']' || character === '(' || character === ')';
    const previous = output.length === 0 ? '' : output[output.length - 1];
    const previousPunctuation = previous === '.' || previous === '[' || previous === ']' || previous === '(' || previous === ')';
    if (pendingWhitespace && output.length > 0 && !punctuation && !previousPunctuation) output += ' ';
    pendingWhitespace = false;
    output += character;
  }
  return output;
}

function outsideStringSpans(text, visitor) {
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
    if (character === "'" || character === '"' || character === '`') {
      quote = character;
      continue;
    }
    const result = visitor(character, index);
    if (result) return result;
  }
  return null;
}

function genericCallName(text) {
  return outsideStringSpans(text, (character, index) => {
    const code = character.charCodeAt(0);
    const startsIdentifier = (code >= 65 && code <= 90) || (code >= 97 && code <= 122) || code === 95 || code === 36;
    if (!startsIdentifier) return null;
    let end = index + 1;
    while (end < text.length) {
      const part = text.charCodeAt(end);
      const identifierPart = (part >= 65 && part <= 90) || (part >= 97 && part <= 122) || (part >= 48 && part <= 57) || part === 95 || part === 36;
      if (!identifierPart) break;
      end += 1;
    }
    let cursor = end;
    while (cursor < text.length && (text[cursor] === ' ' || text[cursor] === '\t')) cursor += 1;
    if (text[cursor] === '(') return text.slice(index, end);
    return null;
  });
}

function executableOperator(text) {
  return outsideStringSpans(text, (character, index) => {
    if (character === '*' || character === '%' || character === '+' || character === '/' || character === '<' || character === '>' || character === '?' || character === '&' || character === '=' || character === '^' || character === '~') return character;
    if (character === '!') {
      if (text[index + 1] === '=') return '!=';
      return null;
    }
    if (character === '|') {
      const before = index === 0 ? '' : text[index - 1];
      const after = index + 1 >= text.length ? '' : text[index + 1];
      if (before === '|' || after === '|' || /[0-9]/u.test(before) || /[0-9]/u.test(after)) return character;
      return null;
    }
    if (character === '-') {
      const before = index === 0 ? '' : text[index - 1];
      const after = index + 1 >= text.length ? '' : text[index + 1];
      if (/[0-9]/u.test(before) || /[0-9]/u.test(after) || /\s/u.test(before) || /\s/u.test(after) || before === '(' || after === '(') return character;
    }
    return null;
  });
}

function bracketLookup(text) {
  return outsideStringSpans(text, (character) => character === '[' ? '[' : null);
}

function isHexDigit(character) {
  return typeof character === 'string' && /[0-9A-Fa-f]/u.test(character);
}

function encodedEscapeOutsideStrings(text) {
  return outsideStringSpans(text, (character, index) => {
    if (character !== '\\') return null;
    const marker = text[index + 1];
    if (marker === 'x' && isHexDigit(text[index + 2]) && isHexDigit(text[index + 3])) return '\\x';
    if (marker === 'u' && isHexDigit(text[index + 2]) && isHexDigit(text[index + 3]) && isHexDigit(text[index + 4]) && isHexDigit(text[index + 5])) return '\\u';
    if (marker === 'u' && text[index + 2] === '{' && isHexDigit(text[index + 3])) return '\\u{}';
    return null;
  });
}

function nestedTemplateSyntax(text) {
  const markers = ['{{', '{%', '{#', '<%', '${', '#{', '!{', '%{', '*{', '@{', '~{', '<#'];
  return outsideStringSpans(text, (character, index) => {
    if (character !== '{' && character !== '<' && character !== '$' && character !== '#' && character !== '!' && character !== '%' && character !== '*' && character !== '@' && character !== '~') return null;
    for (const marker of markers) {
      if (text.startsWith(marker, index)) return marker;
    }
    return null;
  });
}

function stripDelimiterWhitespaceControls(body) {
  let start = 0;
  let end = body.length;
  while (start < end && /\s/u.test(body[start])) start += 1;
  if (start < end && (body[start] === '-' || body[start] === '~')) start += 1;
  while (end > start && /\s/u.test(body[end - 1])) end -= 1;
  if (end > start && (body[end - 1] === '-' || body[end - 1] === '~')) end -= 1;
  return body.slice(start, end);
}

function delimiterWhitespaceControlMarker(body) {
  let start = 0;
  let end = body.length;
  while (start < end && /\s/u.test(body[start])) start += 1;
  if (start < end && (body[start] === '-' || body[start] === '~')) return body[start];
  while (end > start && /\s/u.test(body[end - 1])) end -= 1;
  if (end > start && (body[end - 1] === '-' || body[end - 1] === '~')) return body[end - 1];
  return null;
}

function analyzeObfuscation(body, tag, state) {
  const chains = stringConcatenations(body);
  for (const chain of chains) {
    const lower = chain.value.toLowerCase();
    for (const term of OBFUSCATION_TERMS) {
      if (!lower.includes(term)) continue;
      addFinding(
        state,
        CODE.OBFUSCATED_ACCESS,
        SEVERITY.CRITICAL,
        'string concatenation or escape encoding hides a dangerous object member',
        tag.contentStart + chain.start,
        Math.max(1, chain.end - chain.start),
        tag.kind,
        { decoded: boundedExcerpt(chain.value, 80), parts: chain.parts }
      );
      break;
    }
  }
}

function analyzeExpression(body, tag, state) {
  analyzeObfuscation(body, tag, state);
  const compact = compactExpression(body).toLowerCase();
  const normalizedCompact = compactExpression(body.normalize('NFKC')).toLowerCase();
  for (const term of DANGEROUS_TERMS) {
    if (tag.kind === 'comment' && (term.severity === SEVERITY.MEDIUM || term.severity === SEVERITY.LOW || term.severity === SEVERITY.INFO)) continue;
    const positions = identifierOffsets(compact, term.name);
    if (positions.length > 0) {
      addFinding(
        state,
        term.code,
        term.severity,
        term.reason,
        tag.contentStart + positions[0],
        term.name.length,
        tag.kind,
        { identifier: term.name }
      );
      continue;
    }
    if (normalizedCompact !== compact && identifierOffsets(normalizedCompact, term.name).length > 0) {
      addFinding(
        state,
        CODE.OBFUSCATED_ACCESS,
        SEVERITY.CRITICAL,
        'compatibility Unicode normalization hides a dangerous object member',
        tag.contentStart,
        Math.min(body.length, 32),
        tag.kind,
        { identifier: term.name }
      );
    }
  }
  const encodedEscape = encodedEscapeOutsideStrings(body);
  if (encodedEscape) {
    addFinding(state, CODE.OBFUSCATED_ACCESS, SEVERITY.CRITICAL, 'identifier escape encoding can hide dangerous object members', tag.contentStart, Math.min(body.length, 32), tag.kind, { encoding: encodedEscape });
  }
  const nestedSyntax = nestedTemplateSyntax(body);
  if (nestedSyntax) {
    addFinding(state, CODE.OBFUSCATED_ACCESS, SEVERITY.HIGH, 'nested template delimiter syntax can split or hide executable tokens', tag.contentStart, Math.min(body.length, 32), tag.kind, { marker: nestedSyntax });
  }
  if (compact.includes('os.popen') || compact.includes('os.system') || compact.includes('os.open') || normalizedCompact.includes('os.popen') || normalizedCompact.includes('os.system') || normalizedCompact.includes('os.open')) {
    addFinding(state, CODE.CODE_EXECUTION, SEVERITY.CRITICAL, 'Python os process or file execution primitive', tag.contentStart, Math.min(body.length, 32), tag.kind);
  }
  if (hasIdentifierCall(body, 'import')) {
    addFinding(state, CODE.CODE_EXECUTION, SEVERITY.CRITICAL, 'dynamic import call', tag.contentStart, Math.min(body.length, 32), tag.kind);
  }
  for (const name of ['open', 'exec', 'compile', 'getattr', 'setattr', 'delattr', 'globals', 'locals', 'vars', 'dir', 'fromcharcode']) {
    if (!hasIdentifierCall(body, name)) continue;
    addFinding(state, name === 'fromcharcode' ? CODE.OBFUSCATED_ACCESS : CODE.CODE_EXECUTION, SEVERITY.CRITICAL, 'dangerous dynamic function call', tag.contentStart, Math.min(body.length, 32), tag.kind, { identifier: name });
  }
  if (hasIdentifierCall(body, 'attr') || hasPipeFilter(body, 'attr')) {
    addFinding(state, CODE.SANDBOX_ESCAPE, SEVERITY.CRITICAL, 'Jinja attr indirection can hide object graph escapes', tag.contentStart, Math.min(body.length, 32), tag.kind);
  }
  if (hasPipeFilter(body, 'safe') || hasPipeFilter(body, 'raw')) {
    addFinding(state, CODE.RAW_HTML, SEVERITY.HIGH, 'unescaped safe or raw output filter enables HTML injection', tag.contentStart, Math.min(body.length, 32), tag.kind);
  }
  const call = genericCallName(body);
  if (call) {
    addFinding(state, CODE.CODE_EXECUTION, SEVERITY.HIGH, 'template expression contains an executable function or method call', tag.contentStart, Math.min(body.length, 32), tag.kind, { identifier: call });
  }
  const operator = executableOperator(body);
  if (operator) {
    addFinding(state, CODE.TEMPLATE_INJECTION, SEVERITY.HIGH, 'template expression contains executable operators consistent with an SSTI probe', tag.contentStart, Math.min(body.length, 32), tag.kind, { operator });
  }
  if (bracketLookup(body)) {
    addFinding(state, CODE.UNSAFE_EXPRESSION, SEVERITY.MEDIUM, 'dynamic bracket property lookup can hide forbidden object members', tag.contentStart, Math.min(body.length, 32), tag.kind);
  }
}

function statementFirstWord(body) {
  return firstWord(body).toLowerCase();
}

function analyzeStatement(tag, state) {
  const whitespaceControl = delimiterWhitespaceControlMarker(tag.body);
  if (whitespaceControl) {
    addFinding(state, CODE.UNSAFE_EXPRESSION, SEVERITY.MEDIUM, 'delimiter whitespace-control syntax is dialect-dependent and can hide statement structure', tag.contentStart, Math.min(tag.body.length, 32), tag.kind, { marker: whitespaceControl });
  }
  const body = stripDelimiterWhitespaceControls(tag.body);
  const first = statementFirstWord(body);
  if (FILE_DIRECTIVES.has(first)) {
    addFinding(state, CODE.FILE_INCLUSION, SEVERITY.CRITICAL, 'template inclusion, inheritance, import, or render directive can cause file read, SSRF, or recursion', tag.contentStart, Math.min(body.length, 48), tag.kind, { directive: first });
  }
  if (dangerousStatementDirectives.has(first)) {
    addFinding(state, first === 'raw' ? CODE.RAW_HTML : CODE.DANGEROUS_DIRECTIVE, SEVERITY.HIGH, 'dangerous template directive changes rendering or execution semantics', tag.contentStart, Math.min(body.length, 48), tag.kind, { directive: first });
  }
  if (first === 'autoescape' && /(?:^|\s)(?:false|off)(?:\s|$)/u.test(body.toLowerCase())) {
    addFinding(state, CODE.RAW_HTML, SEVERITY.HIGH, 'autoescape disabling directive enables HTML injection', tag.contentStart, Math.min(body.length, 48), tag.kind);
  }
  if (first === 'liquid') {
    for (const nested of ['include', 'render', 'assign', 'capture', 'raw']) {
      if (identifierOffsets(body, nested).length > 0) {
        addFinding(state, nested === 'raw' ? CODE.RAW_HTML : CODE.DANGEROUS_DIRECTIVE, SEVERITY.HIGH, 'Liquid inline directive contains a dangerous operation', tag.contentStart, Math.min(body.length, 48), tag.kind, { directive: nested });
      }
    }
  }
  analyzeExpression(body, tag, state);
}

function startsSectionName(trimmed) {
  if (!trimmed.startsWith('#')) return null;
  const rest = trimmed.slice(1).trim();
  const name = firstWord(rest).toLowerCase();
  return name.length === 0 ? null : name;
}

function analyzeGoAction(tag, state, first) {
  if (first === 'template') {
    addFinding(state, CODE.FILE_INCLUSION, SEVERITY.CRITICAL, 'Go template invocation can include recursive or file-backed templates', tag.contentStart, Math.min(tag.body.length, 48), tag.kind);
  } else if (first === 'define' || first === 'block') {
    addFinding(state, CODE.DANGEROUS_DIRECTIVE, SEVERITY.HIGH, 'Go template definition or block directive changes template execution', tag.contentStart, Math.min(tag.body.length, 48), tag.kind, { directive: first });
  }
}

function helperLikeExpression(trimmed) {
  if (trimmed.length === 0) return false;
  const first = firstWord(trimmed);
  if (first.length === trimmed.length) return false;
  if (trimmed.includes('|')) return false;
  return true;
}

function analyzeMustache(tag, state) {
  const whitespaceControl = delimiterWhitespaceControlMarker(tag.body);
  if (whitespaceControl) {
    addFinding(state, CODE.UNSAFE_EXPRESSION, SEVERITY.MEDIUM, 'delimiter whitespace-control syntax is dialect-dependent and can hide expression structure', tag.contentStart, Math.min(tag.body.length, 32), tag.kind, { marker: whitespaceControl });
  }
  const normalizedBody = stripDelimiterWhitespaceControls(tag.body);
  const trimmed = normalizedBody.trim();
  const lower = trimmed.toLowerCase();
  if (tag.kind === 'triple-mustache') {
    addFinding(state, CODE.RAW_HTML, SEVERITY.HIGH, 'triple mustache emits raw unescaped HTML', tag.start, Math.min(tag.end - tag.start, 32), tag.kind);
  }
  if (trimmed.startsWith('&')) {
    addFinding(state, CODE.RAW_HTML, SEVERITY.HIGH, 'ampersand mustache emits raw unescaped HTML', tag.start, Math.min(tag.end - tag.start, 32), tag.kind);
  }
  if (trimmed.startsWith('>')) {
    addFinding(state, CODE.FILE_INCLUSION, SEVERITY.CRITICAL, 'mustache partial inclusion can read files or recurse', tag.start, Math.min(tag.end - tag.start, 48), tag.kind);
  }
  if (trimmed.startsWith('<') || trimmed.startsWith('$')) {
    addFinding(state, CODE.FILE_INCLUSION, SEVERITY.HIGH, 'mustache inheritance construct can include external layout content', tag.start, Math.min(tag.end - tag.start, 48), tag.kind);
  }
  const first = firstWord(trimmed).toLowerCase();
  if (first === 'template' || first === 'define' || first === 'block') analyzeGoAction(tag, state, first);
  const goControl = first === 'if' || first === 'range' || first === 'else' || first === 'end';
  if (helperLikeExpression(trimmed) && !goControl && !trimmed.startsWith('#') && !trimmed.startsWith('/') && !trimmed.startsWith('!')) {
    addFinding(state, CODE.CODE_EXECUTION, SEVERITY.MEDIUM, 'whitespace-separated template expression may invoke a helper or function', tag.contentStart, Math.min(trimmed.length, 48), tag.kind);
  }
  const section = startsSectionName(trimmed);
  if (section === 'with' || lower.startsWith('lookup ')) {
    addFinding(state, CODE.SANDBOX_ESCAPE, SEVERITY.HIGH, 'dynamic context or lookup helper is a known escape primitive', tag.contentStart, Math.min(trimmed.length, 48), tag.kind);
  }
  if (!trimmed.startsWith('/') && trimmed !== 'else') analyzeExpression(normalizedBody, tag, state);
}

function dataOnlyMustacheCheck(tag, state, policy) {
  const trimmed = tag.body.trim();
  const offset = tag.contentStart;
  if (trimmed.startsWith('!')) return;
  if (trimmed.startsWith('#')) {
    const rest = trimmed.slice(1).trim();
    const name = firstWord(rest).toLowerCase();
    const target = rest.slice(firstWord(rest).length).trim();
    if ((name === 'if' || name === 'unless') && policy.allowConditionals) {
      try {
        parseSectionTarget(target, offset + 1);
      } catch (error) {
        addFinding(state, error.code || CODE.UNSAFE_EXPRESSION, SEVERITY.HIGH, 'conditional section target is not a safe data path', offset, Math.min(trimmed.length, 48), tag.kind, { value: boundedExcerpt(trimmed, 80) });
      }
      return;
    }
    if (name === 'each' && policy.allowLoops) {
      try {
        parseSectionTarget(target, offset + 1);
      } catch (error) {
        addFinding(state, error.code || CODE.UNSAFE_EXPRESSION, SEVERITY.HIGH, 'loop target is not a safe data path', offset, Math.min(trimmed.length, 48), tag.kind, { value: boundedExcerpt(trimmed, 80) });
      }
      return;
    }
    addFinding(state, CODE.UNSUPPORTED_TAG, SEVERITY.HIGH, 'template section is not in the data-only allowlist', offset, Math.min(trimmed.length, 48), tag.kind, { value: firstWord(rest) });
    return;
  }
  if (trimmed.startsWith('/')) {
    const name = trimmed.slice(1).trim().toLowerCase();
    if (name === 'if' || name === 'unless' || name === 'each') return;
    addFinding(state, CODE.UNSUPPORTED_TAG, SEVERITY.HIGH, 'closing section is not in the data-only allowlist', offset, Math.min(trimmed.length, 48), tag.kind, { value: name });
    return;
  }
  if (trimmed === 'else') return;
  if (trimmed.startsWith('>') || trimmed.startsWith('&') || trimmed.startsWith('<') || trimmed.startsWith('$')) {
    addFinding(state, CODE.UNSUPPORTED_TAG, SEVERITY.HIGH, 'mustache partial, inheritance, or raw output is not data-only', offset, Math.min(trimmed.length, 48), tag.kind);
    return;
  }
  try {
    parseSafeExpression(trimmed, policy, offset);
  } catch (error) {
    addFinding(state, error.code || CODE.UNSAFE_EXPRESSION, SEVERITY.HIGH, 'interpolation is outside the safe data-only expression subset', offset, Math.min(trimmed.length, 48), tag.kind, { value: boundedExcerpt(trimmed, 80) });
  }
}

function enforceDataOnly(tag, state, policy) {
  if (!policy.enforceDataOnly) return;
  if (tag.kind === 'mustache') {
    dataOnlyMustacheCheck(tag, state, policy);
    return;
  }
  addFinding(state, CODE.UNSUPPORTED_TAG, SEVERITY.HIGH, 'foreign executable template syntax is forbidden by the data-only policy', tag.start, Math.min(tag.end - tag.start, 48), tag.kind, { dialect: tag.dialect });
}

function analyzeEjs(tag, state) {
  const trimmed = tag.body.trim();
  if (trimmed.startsWith('-')) {
    addFinding(state, CODE.RAW_HTML, SEVERITY.HIGH, 'EJS raw output tag emits unescaped HTML', tag.start, Math.min(tag.end - tag.start, 32), tag.kind);
  }
  const severity = trimmed.startsWith('=') || trimmed.startsWith('-') ? SEVERITY.HIGH : SEVERITY.CRITICAL;
  addFinding(state, CODE.CODE_EXECUTION, severity, 'EJS tag evaluates arbitrary JavaScript', tag.start, Math.min(tag.end - tag.start, 48), tag.kind);
  analyzeExpression(tag.body, tag, state);
}

function analyzeEvaluatedDelimiter(tag, state) {
  const label = tag.kind === 'javascript' ? 'JavaScript template interpolation evaluates arbitrary JavaScript' : 'Pug or Ruby interpolation evaluates server-side code';
  addFinding(state, CODE.CODE_EXECUTION, SEVERITY.HIGH, label, tag.start, Math.min(tag.end - tag.start, 48), tag.kind);
  analyzeExpression(tag.body, tag, state);
}

function analyzePugUnescaped(tag, state) {
  addFinding(state, CODE.RAW_HTML, SEVERITY.HIGH, 'Pug unescaped interpolation emits raw HTML', tag.start, Math.min(tag.end - tag.start, 32), tag.kind);
  addFinding(state, CODE.CODE_EXECUTION, SEVERITY.HIGH, 'Pug unescaped interpolation evaluates server-side JavaScript', tag.start, Math.min(tag.end - tag.start, 48), tag.kind);
  analyzeExpression(tag.body, tag, state);
}

function analyzeForeignEvaluation(tag, state) {
  if (tag.kind === 'thymeleaf-fragment') {
    addFinding(state, CODE.FILE_INCLUSION, SEVERITY.CRITICAL, 'Thymeleaf fragment inclusion can compose external template content', tag.start, Math.min(tag.end - tag.start, 48), tag.kind);
  } else if (tag.kind === 'ognl') {
    addFinding(state, CODE.TEMPLATE_INJECTION, SEVERITY.HIGH, 'OGNL interpolation evaluates object graph expressions', tag.start, Math.min(tag.end - tag.start, 48), tag.kind);
  } else {
    addFinding(state, CODE.TEMPLATE_INJECTION, SEVERITY.HIGH, 'Thymeleaf interpolation evaluates server-side expression language', tag.start, Math.min(tag.end - tag.start, 48), tag.kind);
  }
  analyzeExpression(tag.body, tag, state);
}

function analyzeFreemarker(tag, state) {
  const first = firstWord(tag.body.trim()).toLowerCase();
  if (tag.kind === 'freemarker-macro') {
    addFinding(state, CODE.CODE_EXECUTION, SEVERITY.HIGH, 'FreeMarker macro invocation executes template-defined code', tag.start, Math.min(tag.end - tag.start, 48), tag.kind);
  } else if (first === 'include' || first === 'import') {
    addFinding(state, CODE.FILE_INCLUSION, SEVERITY.CRITICAL, 'FreeMarker include or import directive can read or recurse into templates', tag.start, Math.min(tag.end - tag.start, 48), tag.kind, { directive: first });
  } else if (first === 'eval') {
    addFinding(state, CODE.CODE_EXECUTION, SEVERITY.CRITICAL, 'FreeMarker eval directive evaluates template expressions dynamically', tag.start, Math.min(tag.end - tag.start, 48), tag.kind, { directive: first });
  } else {
    addFinding(state, CODE.DANGEROUS_DIRECTIVE, SEVERITY.HIGH, 'FreeMarker directive changes server-side template execution', tag.start, Math.min(tag.end - tag.start, 48), tag.kind, { directive: first || 'unknown' });
  }
  analyzeExpression(tag.body, tag, state);
}

function structuralNameForMustache(trimmed) {
  if (trimmed.startsWith('#')) return { role: 'open', name: firstWord(trimmed.slice(1).trim()).toLowerCase() };
  if (trimmed.startsWith('/')) return { role: 'close', name: trimmed.slice(1).trim().toLowerCase() };
  const first = firstWord(trimmed).toLowerCase();
  if (first === 'if' || first === 'range' || first === 'with' || first === 'block' || first === 'define') return { role: 'open', name: first === 'range' ? 'each' : first };
  if (first === 'end') return { role: 'close', name: 'go' };
  return null;
}

function structuralNameForStatement(trimmed) {
  const first = firstWord(trimmed).toLowerCase();
  if (BLOCK_OPENERS.has(first)) return { role: 'open', name: first === 'for' || first === 'tablerow' ? 'each' : first };
  if (first.startsWith('end') && first.length > 3) {
    const name = first.slice(3);
    return { role: 'close', name: name === 'for' || name === 'tablerow' ? 'each' : name };
  }
  if (first === 'end') return { role: 'close', name: 'go' };
  return null;
}

function structuralRole(tag) {
  const trimmed = stripDelimiterWhitespaceControls(tag.body).trim();
  if (trimmed.length === 0) return null;
  if (tag.kind === 'mustache' || tag.kind === 'triple-mustache') return structuralNameForMustache(trimmed);
  if (tag.kind === 'statement') return structuralNameForStatement(trimmed);
  return null;
}

function analyzeStructure(tags, state) {
  const policy = state.policy;
  const stack = [];
  let loopDepth = 0;
  for (const tag of tags) {
    const role = structuralRole(tag);
    if (!role || role.name.length === 0) continue;
    if (role.role === 'open') {
      const loop = LOOP_DIRECTIVES.has(role.name) || role.name === 'each';
      stack.push({ name: role.name, loop, offset: tag.start });
      if (loop) loopDepth += 1;
      if (stack.length > policy.maxNestingDepth) {
        addFinding(state, CODE.NESTING_TOO_DEEP, SEVERITY.HIGH, 'template block nesting exceeds the configured depth bound', tag.start, Math.min(tag.end - tag.start, 48), tag.kind, { limit: policy.maxNestingDepth, actual: stack.length });
      }
      if (loopDepth > policy.maxLoopDepth) {
        addFinding(state, CODE.LOOP_TOO_DEEP, SEVERITY.CRITICAL, 'nested template loops exceed the expansion bomb depth bound', tag.start, Math.min(tag.end - tag.start, 48), tag.kind, { limit: policy.maxLoopDepth, actual: loopDepth });
      }
      continue;
    }
    if (stack.length === 0) {
      addFinding(state, CODE.UNBALANCED_TAG, SEVERITY.MEDIUM, 'closing template block has no opening block', tag.start, Math.min(tag.end - tag.start, 48), tag.kind, { name: role.name });
      continue;
    }
    const top = stack.pop();
    if (top.loop) loopDepth -= 1;
    const compatible = top.name === role.name || role.name === 'go' || (top.name === 'if' && role.name === 'if') || (top.name === 'each' && role.name === 'each');
    if (!compatible) {
      addFinding(state, CODE.UNBALANCED_TAG, SEVERITY.MEDIUM, 'template closing block does not match its opening block', tag.start, Math.min(tag.end - tag.start, 48), tag.kind, { expected: top.name, actual: role.name });
    }
  }
  for (const item of stack) {
    addFinding(state, CODE.UNBALANCED_TAG, SEVERITY.HIGH, 'template block is not closed', item.offset, 2, 'structure', { name: item.name });
  }
}

function scanPugLineCode(text, state) {
  if (!state.policy.detectPugLineCode) return;
  let lineStart = 0;
  while (lineStart <= text.length) {
    let lineEnd = text.indexOf('\n', lineStart);
    if (lineEnd === -1) lineEnd = text.length;
    let cursor = lineStart;
    while (cursor < lineEnd && (text[cursor] === ' ' || text[cursor] === '\t')) cursor += 1;
    if (text[cursor] === '-' && cursor + 1 < lineEnd) {
      const rest = text.slice(cursor + 1, lineEnd).trim();
      const first = firstWord(rest).toLowerCase();
      const keyword = first === 'var' || first === 'let' || first === 'const' || first === 'if' || first === 'for' || first === 'while' || first === 'function' || first === 'process' || first === 'require' || first === 'eval';
      const obviousCode = rest.includes('=') || rest.includes('(') || keyword;
      if (obviousCode) {
        addFinding(state, CODE.PUG_CODE, SEVERITY.HIGH, 'Pug or Jade unbuffered dash line executes server-side JavaScript', cursor, Math.min(lineEnd - cursor, 64), 'pug-line', { value: boundedExcerpt(rest, 64) });
      }
    }
    if (lineEnd >= text.length) break;
    lineStart = lineEnd + 1;
  }
}

const VELOCITY_DIRECTIVES = Object.freeze([
  Object.freeze({ name: '#set', code: CODE.DANGEROUS_DIRECTIVE, severity: SEVERITY.HIGH, reason: 'Velocity assignment directive creates mutable template state' }),
  Object.freeze({ name: '#foreach', code: CODE.DANGEROUS_DIRECTIVE, severity: SEVERITY.HIGH, reason: 'Velocity loop directive can amplify template expansion' }),
  Object.freeze({ name: '#macro', code: CODE.DANGEROUS_DIRECTIVE, severity: SEVERITY.HIGH, reason: 'Velocity macro directive defines executable template code' }),
  Object.freeze({ name: '#parse', code: CODE.FILE_INCLUSION, severity: SEVERITY.CRITICAL, reason: 'Velocity parse directive includes file-backed templates' }),
  Object.freeze({ name: '#include', code: CODE.FILE_INCLUSION, severity: SEVERITY.CRITICAL, reason: 'Velocity include directive reads file-backed content' }),
  Object.freeze({ name: '#evaluate', code: CODE.CODE_EXECUTION, severity: SEVERITY.CRITICAL, reason: 'Velocity evaluate directive dynamically evaluates template input' }),
  Object.freeze({ name: '#render', code: CODE.FILE_INCLUSION, severity: SEVERITY.CRITICAL, reason: 'Velocity render directive composes external template content' }),
  Object.freeze({ name: '#stop', code: CODE.DANGEROUS_DIRECTIVE, severity: SEVERITY.MEDIUM, reason: 'Velocity stop directive changes template execution flow' }),
  Object.freeze({ name: '#break', code: CODE.DANGEROUS_DIRECTIVE, severity: SEVERITY.MEDIUM, reason: 'Velocity break directive changes loop execution flow' }),
  Object.freeze({ name: '#if', code: CODE.DANGEROUS_DIRECTIVE, severity: SEVERITY.MEDIUM, reason: 'Velocity conditional directive evaluates server-side expressions' })
]);

function scanVelocityDirectives(text, state) {
  for (const directive of VELOCITY_DIRECTIVES) {
    const positions = identifierOffsets(text, directive.name);
    for (const position of positions) {
      let cursor = position + directive.name.length;
      while (cursor < text.length && /\s/u.test(text[cursor])) cursor += 1;
      if (text[cursor] !== '(') continue;
      addFinding(state, directive.code, directive.severity, directive.reason, position, directive.name.length, 'velocity', { directive: directive.name });
    }
  }
}

function scanSmartySyntax(text, state) {
  const lower = text.toLowerCase();
  const phpOpen = lower.indexOf('{php}');
  const phpClose = lower.indexOf('{/php}');
  if (phpOpen !== -1 || phpClose !== -1) {
    addFinding(state, CODE.CODE_EXECUTION, SEVERITY.CRITICAL, 'Smarty php tag executes server-side PHP code', phpOpen === -1 ? phpClose : phpOpen, 5, 'smarty');
  }
  for (const directive of ['include', 'eval', 'fetch', 'insert']) {
    const needle = '{' + directive;
    let cursor = 0;
    while (cursor <= lower.length - needle.length) {
      const found = lower.indexOf(needle, cursor);
      if (found === -1) break;
      const after = text.charCodeAt(found + needle.length);
      const boundary = after === 32 || after === 9 || after === 10 || after === 13 || after === 125;
      if (boundary) {
        addFinding(state, directive === 'include' || directive === 'fetch' ? CODE.FILE_INCLUSION : CODE.CODE_EXECUTION, SEVERITY.CRITICAL, 'Smarty directive can include content or execute template code', found, needle.length, 'smarty', { directive });
      }
      cursor = found + needle.length;
    }
  }
  for (let index = 0; index + 2 < text.length; index += 1) {
    if (text[index] !== '{' || text[index + 1] !== '$') continue;
    const code = text.charCodeAt(index + 2);
    const identifierStart = (code >= 65 && code <= 90) || (code >= 97 && code <= 122) || code === 95 || code === 36;
    if (!identifierStart) continue;
    addFinding(state, CODE.TEMPLATE_INJECTION, SEVERITY.HIGH, 'Smarty variable interpolation is a foreign executable template syntax', index, 2, 'smarty');
  }
}

function scanUnicodeDelimiterEvasion(text, state) {
  const normalized = text.normalize('NFKC');
  if (normalized === text) return;
  for (const marker of ['{{', '{%', '{#', '<%', '${', '#{', '!{', '%{', '*{', '@{', '~{', '<#']) {
    if (!normalized.includes(marker) || text.includes(marker)) continue;
    addFinding(state, CODE.OBFUSCATED_ACCESS, SEVERITY.CRITICAL, 'compatibility Unicode normalization creates executable template delimiters', 0, Math.min(text.length, marker.length), 'unicode', { marker });
    return;
  }
}

function analyzeTag(tag, state, policy) {
  if (tag.unclosed) {
    addFinding(state, CODE.UNCLOSED_TAG, SEVERITY.HIGH, 'template delimiter is not closed', tag.start, Math.min(tag.end - tag.start, 48), tag.kind);
  }
  if (tag.body.length > policy.maxExpressionLength) {
    addFinding(state, CODE.EXPRESSION_TOO_LONG, SEVERITY.HIGH, 'template expression exceeds the configured length bound', tag.contentStart, tag.body.length, tag.kind, { limit: policy.maxExpressionLength, actual: tag.body.length });
  }
  enforceDataOnly(tag, state, policy);
  if (tag.kind === 'statement') analyzeStatement(tag, state);
  else if (tag.kind === 'ejs') analyzeEjs(tag, state);
  else if (tag.kind === 'javascript' || tag.kind === 'pug') analyzeEvaluatedDelimiter(tag, state);
  else if (tag.kind === 'pug-unescaped') analyzePugUnescaped(tag, state);
  else if (tag.kind === 'ognl' || tag.kind === 'thymeleaf-selection' || tag.kind === 'thymeleaf-url' || tag.kind === 'thymeleaf-fragment') analyzeForeignEvaluation(tag, state);
  else if (tag.kind === 'freemarker' || tag.kind === 'freemarker-close' || tag.kind === 'freemarker-macro') analyzeFreemarker(tag, state);
  else if (tag.kind === 'comment') analyzeExpression(tag.body, tag, state);
  else analyzeMustache(tag, state);
}

function hostileCode(kind) {
  if (kind === 'unpaired-surrogate') return CODE.UNPAIRED_SURROGATE;
  if (kind === 'bidi-control') return CODE.BIDI_CONTROL;
  return CODE.CONTROL_CHARACTER;
}

function scanHostileCharacters(text, state) {
  for (let index = 0; index < text.length; index += 1) {
    const kind = hostileCharacterKind(text, index);
    if (!kind) continue;
    const codePoint = text.codePointAt(index);
    addFinding(state, hostileCode(kind), kind === 'control-character' ? TEMPLATECAGE_SEVERITY.HIGH : TEMPLATECAGE_SEVERITY.MEDIUM, 'template contains a forbidden control, bidi, separator, or surrogate character', index, 1, 'input', { value: 'U+' + codePoint.toString(16).toUpperCase().padStart(4, '0') });
  }
}

export function auditTemplate(template, options) {
  if (typeof template !== 'string') {
    throw new TemplateCageError(CODE.INVALID_INPUT, 'template must be a string', { actual: typeof template });
  }
  const policy = resolveTemplatePolicy(options);
  const state = {
    policy,
    findings: [],
    truncatedFindings: false
  };
  if (policy.maxFindings === 0) {
    state.findings.push(makeFinding(CODE.RESOURCE_LIMIT, TEMPLATECAGE_SEVERITY.CRITICAL, 'maxFindings is zero so the audit fails closed', 0, 0, 'policy', { limit: 0 }));
    state.truncatedFindings = true;
  }
  const inputBytes = utf8Length(template);
  if (inputBytes > policy.maxBytes) {
    addFinding(state, CODE.INPUT_TOO_LONG, TEMPLATECAGE_SEVERITY.HIGH, 'template exceeds the configured UTF-8 byte bound', 0, 0, 'input', { limit: policy.maxBytes, actual: inputBytes });
  }
  scanHostileCharacters(template, state);
  const tags = scanDelimitedTags(template);
  if (tags.length > policy.maxTags) {
    addFinding(state, CODE.TOO_MANY_TAGS, TEMPLATECAGE_SEVERITY.HIGH, 'template contains more delimited tags than the configured bound', 0, 0, 'input', { limit: policy.maxTags, actual: tags.length });
  }
  const analyzed = tags.length > policy.maxTags ? tags.slice(0, policy.maxTags) : tags;
  for (const tag of analyzed) analyzeTag(tag, state, policy);
  analyzeStructure(analyzed, state);
  scanPugLineCode(template, state);
  scanVelocityDirectives(template, state);
  scanSmartySyntax(template, state);
  scanUnicodeDelimiterEvasion(template, state);
  const dialects = [];
  const seenDialects = new Set();
  for (const tag of tags) {
    if (seenDialects.has(tag.dialect)) continue;
    seenDialects.add(tag.dialect);
    dialects.push(tag.dialect);
  }
  const report = {
    safe: state.findings.length === 0 && !state.truncatedFindings,
    policy: policy.name,
    inputBytes,
    inputLength: template.length,
    tagCount: tags.length,
    dialects,
    truncatedFindings: state.truncatedFindings,
    maxFindings: policy.maxFindings,
    findings: state.findings
  };
  return deepFreezeGenerated(report);
}

export function isSafeTemplate(template, options) {
  if (typeof template !== 'string') return false;
  return auditTemplate(template, options).safe;
}

export function validateTemplate(template, options) {
  const report = auditTemplate(template, options);
  if (report.safe) return report;
  const first = report.findings[0];
  throw new TemplateCageError(first.code, first.message, {
    construct: first.construct,
    severity: first.severity,
    findingCount: report.findings.length,
    truncatedFindings: report.truncatedFindings
  }, first.offset);
}

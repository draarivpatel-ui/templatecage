/* Zero-eval iterative sandboxed renderer for a bounded Mustache subset. */

import { types as utilTypes } from 'node:util';
import { CODE, TemplateCageError, deepFreezeGenerated, own } from './errors.mjs';
import { resolveTemplatePolicy } from './policy.mjs';
import { firstWord, hostileCharacterKind, stripDangerousText, utf8Length } from './scan-utils.mjs';
import { isBlockedPathSegment, parseSafeExpression, parseSectionTarget } from './safe-syntax.mjs';

const compiledTemplates = new WeakSet();
const MISSING = Object.freeze({ missing: true });

function isPlainDataContainer(value) {
  if (Array.isArray(value)) return true;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function compileError(code, message, offset, detail) {
  return new TemplateCageError(code, message, detail, offset);
}

function rejectHostileCharacters(template) {
  for (let index = 0; index < template.length; index += 1) {
    const kind = hostileCharacterKind(template, index);
    if (!kind) continue;
    const codePoint = template.codePointAt(index);
    const code = kind === 'unpaired-surrogate' ? CODE.UNPAIRED_SURROGATE : kind === 'bidi-control' ? CODE.BIDI_CONTROL : CODE.CONTROL_CHARACTER;
    throw compileError(code, 'template contains a forbidden control, bidi, separator, or surrogate character', index, { value: 'U+' + codePoint.toString(16).toUpperCase().padStart(4, '0') });
  }
}

function rejectForeignDelimiters(template) {
  const foreign = ['{%', '{#', '<%', '${', '#{'];
  for (let index = 0; index + 1 < template.length; index += 1) {
    for (const marker of foreign) {
      if (!template.startsWith(marker, index)) continue;
      if (marker === '{#' && index > 0 && template[index - 1] === '{') continue;
      throw compileError(CODE.UNSUPPORTED_TAG, 'foreign executable template syntax is forbidden in the safe renderer', index, { marker });
    }
  }
}


function findMustacheClose(template, start) {
  let quote = null;
  let escaped = false;
  for (let index = start; index + 1 < template.length; index += 1) {
    const character = template[index];
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
    if (character === '}' && template[index + 1] === '}') return index;
  }
  return -1;
}

function addTextInstruction(instructions, value) {
  if (value.length === 0) return;
  instructions.push({ op: 'text', value });
}

function parseTagNameAndTarget(rest) {
  const name = firstWord(rest).toLowerCase();
  const target = rest.slice(firstWord(rest).length).trim();
  return [name, target];
}

function processInterpolation(trimmed, offset, policy, instructions, variables) {
  const expression = parseSafeExpression(trimmed, policy, offset);
  variables.add(expression.path.text);
  instructions.push({ op: 'var', path: expression.path, filters: expression.filters, offset });
}

function processTemplateTag(body, offset, policy, instructions, stack, variables, state) {
  const trimmed = body.trim();
  if (trimmed.length === 0) throw compileError(CODE.INVALID_TEMPLATE, 'empty template tag', offset);
  if (trimmed.startsWith('!')) return;
  if (trimmed.startsWith('&') || trimmed.startsWith('>') || trimmed.startsWith('<') || trimmed.startsWith('$')) {
    throw compileError(trimmed.startsWith('&') ? CODE.RAW_HTML : CODE.FILE_INCLUSION, 'raw output, partials, and inheritance constructs are forbidden', offset, { marker: trimmed[0] });
  }
  if (trimmed === 'else') {
    if (stack.length === 0) throw compileError(CODE.UNBALANCED_TAG, 'else tag has no open conditional', offset);
    const entry = stack[stack.length - 1];
    if ((entry.type !== 'if' && entry.type !== 'unless') || entry.elseIndex !== null) {
      throw compileError(CODE.UNBALANCED_TAG, 'else tag is not inside exactly one conditional section', offset);
    }
    const jumpIndex = instructions.length;
    instructions.push({ op: 'jump', target: null, offset });
    instructions[entry.jumpIndex].target = jumpIndex + 1;
    entry.elseIndex = jumpIndex;
    return;
  }
  if (trimmed.startsWith('#')) {
    const rest = trimmed.slice(1).trim();
    const pair = parseTagNameAndTarget(rest);
    const name = pair[0];
    const target = pair[1];
    if (name !== 'if' && name !== 'unless' && name !== 'each') {
      throw compileError(CODE.UNSUPPORTED_TAG, 'template section is not in the data-only allowlist', offset, { value: name });
    }
    if ((name === 'if' || name === 'unless') && !policy.allowConditionals) {
      throw compileError(CODE.UNSUPPORTED_TAG, 'conditional sections are disabled by policy', offset, { value: name });
    }
    if (name === 'each' && !policy.allowLoops) {
      throw compileError(CODE.UNSUPPORTED_TAG, 'loop sections are disabled by policy', offset, { value: name });
    }
    if (stack.length + 1 > policy.maxNestingDepth) {
      throw compileError(CODE.NESTING_TOO_DEEP, 'template block nesting exceeds the configured depth bound', offset, { limit: policy.maxNestingDepth, actual: stack.length + 1 });
    }
    if (name === 'each' && state.loopDepth + 1 > policy.maxLoopDepth) {
      throw compileError(CODE.LOOP_TOO_DEEP, 'nested loops exceed the configured loop depth bound', offset, { limit: policy.maxLoopDepth, actual: state.loopDepth + 1 });
    }
    const path = parseSectionTarget(target, offset + 1);
    variables.add(path.text);
    const index = instructions.length;
    if (name === 'each') {
      instructions.push({ op: 'loop', path, start: index + 1, end: null, offset });
      state.loopDepth += 1;
    } else {
      instructions.push({ op: 'jumpIfFalse', path, invert: name === 'unless', target: null, offset });
    }
    stack.push({ type: name, instructionIndex: index, jumpIndex: index, elseIndex: null, offset });
    return;
  }
  if (trimmed.startsWith('/')) {
    const name = trimmed.slice(1).trim().toLowerCase();
    if (name.length === 0 || /\s/u.test(name)) throw compileError(CODE.INVALID_TEMPLATE, 'closing section name is malformed', offset);
    if (name !== 'if' && name !== 'unless' && name !== 'each') {
      throw compileError(CODE.UNSUPPORTED_TAG, 'closing section is not in the data-only allowlist', offset, { value: name });
    }
    if (stack.length === 0) throw compileError(CODE.UNBALANCED_TAG, 'closing section has no opening section', offset, { value: name });
    const entry = stack[stack.length - 1];
    if (entry.type !== name) {
      throw compileError(CODE.UNBALANCED_TAG, 'closing section does not match the innermost opening section', offset, { expected: entry.type, actual: name });
    }
    stack.pop();
    if (name === 'each') {
      state.loopDepth -= 1;
      const endIndex = instructions.length;
      instructions.push({ op: 'loopEnd', loopIndex: entry.instructionIndex, offset });
      instructions[entry.instructionIndex].end = endIndex;
    } else {
      if (entry.elseIndex === null) instructions[entry.jumpIndex].target = instructions.length;
      else instructions[entry.elseIndex].target = instructions.length;
    }
    return;
  }
  processInterpolation(trimmed, offset, policy, instructions, variables);
}

function compileInstructions(template, policy) {
  const instructions = [];
  const stack = [];
  const variables = new Set();
  const state = { loopDepth: 0 };
  let cursor = 0;
  let tagCount = 0;
  while (cursor <= template.length) {
    const open = template.indexOf('{{', cursor);
    if (open === -1) {
      addTextInstruction(instructions, template.slice(cursor));
      break;
    }
    addTextInstruction(instructions, template.slice(cursor, open));
    if (template.startsWith('{{{', open)) {
      throw compileError(CODE.RAW_HTML, 'triple mustache raw HTML output is forbidden', open);
    }
    const close = findMustacheClose(template, open + 2);
    if (close === -1) throw compileError(CODE.UNCLOSED_TAG, 'template tag is not closed', open);
    tagCount += 1;
    if (tagCount > policy.maxTags) {
      throw compileError(CODE.TOO_MANY_TAGS, 'template contains more tags than the configured bound', open, { limit: policy.maxTags, actual: tagCount });
    }
    const body = template.slice(open + 2, close);
    if (body.length > policy.maxExpressionLength) {
      throw compileError(CODE.EXPRESSION_TOO_LONG, 'template expression exceeds the configured length bound', open + 2, { limit: policy.maxExpressionLength, actual: body.length });
    }
    processTemplateTag(body, open + 2, policy, instructions, stack, variables, state);
    cursor = close + 2;
  }
  if (stack.length !== 0) {
    const entry = stack[stack.length - 1];
    throw compileError(CODE.UNBALANCED_TAG, 'template section is not closed', entry.offset, { value: entry.type });
  }
  return {
    instructions,
    variables: Array.from(variables).sort()
  };
}

export function compileTemplate(template, options) {
  if (typeof template !== 'string') {
    throw new TemplateCageError(CODE.INVALID_INPUT, 'template must be a string', { actual: typeof template });
  }
  const policy = resolveTemplatePolicy(options);
  const inputBytes = utf8Length(template);
  if (inputBytes > policy.maxBytes) {
    throw new TemplateCageError(CODE.INPUT_TOO_LONG, 'template exceeds the configured UTF-8 byte bound', { limit: policy.maxBytes, actual: inputBytes }, 0);
  }
  rejectHostileCharacters(template);
  rejectForeignDelimiters(template);
  const compiledParts = compileInstructions(template, policy);
  const compiled = {
    kind: 'templatecage-compiled-template',
    policy,
    inputBytes,
    instructions: compiledParts.instructions,
    variables: compiledParts.variables
  };
  deepFreezeGenerated(compiled);
  compiledTemplates.add(compiled);
  return compiled;
}

function readOwnData(object, key, pathText) {
  if (!object || typeof object !== 'object') return MISSING;
  if (utilTypes.isProxy(object)) {
    throw new TemplateCageError(CODE.UNSAFE_VALUE, 'proxy objects are forbidden in template data', { path: pathText, key });
  }
  if (isBlockedPathSegment(key)) {
    throw new TemplateCageError(CODE.PROTOTYPE_ACCESS, 'template attempted to read a forbidden object member', { path: pathText, key });
  }
  if (!isPlainDataContainer(object)) return MISSING;
  if (!own(object, key)) return MISSING;
  const descriptor = Object.getOwnPropertyDescriptor(object, key);
  if (!descriptor) return MISSING;
  if (!own(descriptor, 'value')) {
    throw new TemplateCageError(CODE.UNSAFE_VALUE, 'template data uses a getter on a requested path', { path: pathText, key });
  }
  const value = descriptor.value;
  if (typeof value === 'function') {
    throw new TemplateCageError(CODE.UNSAFE_VALUE, 'template data exposes a function on a requested path', { path: pathText, key });
  }
  if (!descriptor.enumerable && !(Array.isArray(object) && key === 'length')) return MISSING;
  return value;
}

function loopMetadata(name, loopStack) {
  if (loopStack.length === 0) return undefined;
  const frame = loopStack[loopStack.length - 1];
  if (name === '@index') return frame.index;
  if (name === '@first') return frame.index === 0;
  if (name === '@last') return frame.index + 1 === frame.length;
  if (name === '@length') return frame.length;
  return undefined;
}

function resolvePath(path, scopes, loopStack) {
  if (path.kind === 'current') return scopes[scopes.length - 1];
  if (path.kind === 'loop-meta') return loopMetadata(path.segments[0], loopStack);
  const segments = path.segments;
  let value;
  if (path.kind === 'current-path') {
    value = scopes[scopes.length - 1];
    for (let index = 0; index < segments.length; index += 1) {
      const next = readOwnData(value, segments[index], path.text);
      if (next === MISSING) return undefined;
      value = next;
    }
    return value;
  }
  let found = false;
  for (let scopeIndex = scopes.length - 1; scopeIndex >= 0; scopeIndex -= 1) {
    const first = readOwnData(scopes[scopeIndex], segments[0], path.text);
    if (first !== MISSING) {
      value = first;
      found = true;
      break;
    }
  }
  if (!found) return undefined;
  for (let index = 1; index < segments.length; index += 1) {
    const next = readOwnData(value, segments[index], path.text);
    if (next === MISSING) return undefined;
    value = next;
  }
  return value;
}

function templateTruth(value) {
  if (value === undefined || value === null || value === false) return false;
  if (typeof value === 'object' && utilTypes.isProxy(value)) {
    throw new TemplateCageError(CODE.UNSAFE_VALUE, 'proxy objects are forbidden in template conditionals');
  }
  if (typeof value === 'number' && value === 0) return false;
  if (typeof value === 'string' && value.length === 0) return false;
  if (Array.isArray(value) && value.length === 0) return false;
  return true;
}

function primitiveText(value, pathText) {
  if (value === undefined || value === null) return '';
  const type = typeof value;
  if (type === 'string') return stripDangerousText(value);
  if (type === 'number') {
    if (!Number.isFinite(value)) throw new TemplateCageError(CODE.UNSAFE_VALUE, 'non-finite numbers cannot be rendered', { path: pathText });
    return String(value);
  }
  if (type === 'boolean' || type === 'bigint') return String(value);
  throw new TemplateCageError(CODE.UNSAFE_VALUE, 'only primitive data values can be rendered', { path: pathText, actual: type });
}

function escapeHtmlText(value) {
  let output = '';
  for (const character of value) {
    if (character === '&') output += '&amp;';
    else if (character === '<') output += '&lt;';
    else if (character === '>') output += '&gt;';
    else if (character === '"') output += '&quot;';
    else if (character === "'") output += '&#39;';
    else if (character === '`') output += '&#96;';
    else output += character;
  }
  return output;
}

function truncateCodePoints(text, maximum) {
  if (maximum === 0) return '';
  let output = '';
  let count = 0;
  for (const character of text) {
    if (count >= maximum) break;
    output += character;
    count += 1;
  }
  return output;
}

function applyFilters(value, filters, pathText) {
  let current = value;
  let htmlSafe = false;
  for (const filter of filters) {
    if (filter.name === 'default') {
      if (current === undefined || current === null || current === '') {
        current = filter.argument;
        htmlSafe = false;
      }
      continue;
    }
    const text = primitiveText(current, pathText);
    if (filter.name === 'upper') current = text.toUpperCase();
    else if (filter.name === 'lower') current = text.toLowerCase();
    else if (filter.name === 'trim') current = text.trim();
    else if (filter.name === 'truncate') current = truncateCodePoints(text, filter.argument);
    else if (filter.name === 'escapeHtml') {
      current = escapeHtmlText(text);
      htmlSafe = true;
    } else if (filter.name === 'escapeUrl') {
      current = encodeURIComponent(text);
    } else {
      throw new TemplateCageError(CODE.UNSAFE_FILTER, 'filter is not in the allowlist', { path: pathText, value: filter.name });
    }
  }
  return { value: current, htmlSafe };
}

function jsonPrimitive(value, pathText) {
  if (value === undefined || value === null) return 'null';
  const type = typeof value;
  if (type === 'string') return JSON.stringify(stripDangerousText(value));
  if (type === 'number') {
    if (!Number.isFinite(value)) return 'null';
    return String(value);
  }
  if (type === 'boolean') return String(value);
  throw new TemplateCageError(CODE.UNSAFE_VALUE, 'only strings, finite numbers, booleans, and null can be rendered in json mode', { path: pathText, actual: type });
}

function finalizeValue(value, filters, pathText, mode) {
  const filtered = applyFilters(value, filters, pathText);
  if (mode === 'json') return jsonPrimitive(filtered.value, pathText);
  const text = primitiveText(filtered.value, pathText);
  if (mode === 'html' && !filtered.htmlSafe) return escapeHtmlText(text);
  return text;
}

function createRenderState(policy) {
  return {
    output: '',
    outputBytes: 0,
    iterations: 0,
    maxOutputBytes: policy.maxOutputBytes,
    maxIterations: policy.maxIterations
  };
}

function appendOutput(state, chunk, offset) {
  if (chunk.length === 0) return;
  const chunkBytes = utf8Length(chunk);
  const nextBytes = state.outputBytes + chunkBytes;
  if (nextBytes > state.maxOutputBytes) {
    throw new TemplateCageError(CODE.OUTPUT_LIMIT, 'rendered output exceeds the configured byte bound', { limit: state.maxOutputBytes, actual: nextBytes }, offset);
  }
  state.output += chunk;
  state.outputBytes = nextBytes;
}

function countIteration(state, offset) {
  state.iterations += 1;
  if (state.iterations > state.maxIterations) {
    throw new TemplateCageError(CODE.ITERATION_LIMIT, 'template loop iterations exceed the configured bound', { limit: state.maxIterations, actual: state.iterations }, offset);
  }
}

function renderInstructions(compiled, data, policy) {
  const instructions = compiled.instructions;
  const scopes = [data];
  const loopStack = [];
  const state = createRenderState(policy);
  let ip = 0;
  while (ip < instructions.length) {
    const instruction = instructions[ip];
    if (instruction.op === 'text') {
      appendOutput(state, instruction.value, ip);
      ip += 1;
      continue;
    }
    if (instruction.op === 'var') {
      const value = resolvePath(instruction.path, scopes, loopStack);
      appendOutput(state, finalizeValue(value, instruction.filters, instruction.path.text, policy.mode), instruction.offset);
      ip += 1;
      continue;
    }
    if (instruction.op === 'jumpIfFalse') {
      const value = resolvePath(instruction.path, scopes, loopStack);
      const truth = templateTruth(value);
      const jump = instruction.invert ? truth : !truth;
      ip = jump ? instruction.target : ip + 1;
      continue;
    }
    if (instruction.op === 'jump') {
      ip = instruction.target;
      continue;
    }
    if (instruction.op === 'loop') {
      const value = resolvePath(instruction.path, scopes, loopStack);
      if (value && typeof value === 'object' && utilTypes.isProxy(value)) {
        throw new TemplateCageError(CODE.UNSAFE_VALUE, 'proxy arrays are forbidden as loop sources', { path: instruction.path.text }, instruction.offset);
      }
      const items = value && typeof value === 'object' && Array.isArray(value) ? value : [];
      const lengthValue = Array.isArray(items) ? readOwnData(items, 'length', instruction.path.text) : 0;
      const length = typeof lengthValue === 'number' && Number.isSafeInteger(lengthValue) && lengthValue >= 0 ? lengthValue : 0;
      if (length === 0) {
        ip = instruction.end + 1;
        continue;
      }
      countIteration(state, instruction.offset);
      loopStack.push({ items, length, index: 0, start: instruction.start, end: instruction.end });
      const firstItem = readOwnData(items, '0', instruction.path.text);
      scopes.push(firstItem === MISSING ? undefined : firstItem);
      ip = instruction.start;
      continue;
    }
    if (instruction.op === 'loopEnd') {
      if (loopStack.length === 0) throw new TemplateCageError(CODE.TEMPLATE_INTEGRITY, 'compiled loop stack is inconsistent', { instruction: ip });
      const frame = loopStack[loopStack.length - 1];
      if (frame.end !== ip) throw new TemplateCageError(CODE.TEMPLATE_INTEGRITY, 'compiled loop end is inconsistent', { instruction: ip });
      if (frame.index + 1 < frame.length) {
        frame.index += 1;
        countIteration(state, instruction.offset);
        const itemKey = String(frame.index);
        const item = readOwnData(frame.items, itemKey, 'array index');
        scopes[scopes.length - 1] = item === MISSING ? undefined : item;
        ip = frame.start;
      } else {
        loopStack.pop();
        scopes.pop();
        ip += 1;
      }
      continue;
    }
    throw new TemplateCageError(CODE.TEMPLATE_INTEGRITY, 'compiled template contains an unknown instruction', { instruction: ip });
  }
  if (loopStack.length !== 0) throw new TemplateCageError(CODE.TEMPLATE_INTEGRITY, 'compiled loop stack is not empty after rendering');
  return state.output;
}

function validCompiled(value) {
  return value && typeof value === 'object' && compiledTemplates.has(value);
}

function prepareCompiled(templateOrCompiled, options) {
  if (typeof templateOrCompiled === 'string') return compileTemplate(templateOrCompiled, options);
  if (!validCompiled(templateOrCompiled)) {
    throw new TemplateCageError(CODE.TEMPLATE_INTEGRITY, 'compiled template object was not produced by compileTemplate', { actual: typeof templateOrCompiled });
  }
  return templateOrCompiled;
}

export function renderTemplate(templateOrCompiled, data, options) {
  const compiled = prepareCompiled(templateOrCompiled, options);
  const policy = options === undefined ? compiled.policy : resolveTemplatePolicy(options);
  const input = data === undefined ? Object.create(null) : data;
  if (!input || typeof input !== 'object' || Array.isArray(input) || utilTypes.isProxy(input)) {
    throw new TemplateCageError(CODE.INVALID_DATA, 'render data must be a non-proxy object', { actual: Array.isArray(input) ? 'array' : typeof input });
  }
  return renderInstructions(compiled, input, policy);
}

export function extractTemplateVariables(templateOrCompiled, options) {
  const compiled = prepareCompiled(templateOrCompiled, options);
  return Object.freeze(compiled.variables.slice());
}

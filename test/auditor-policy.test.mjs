import test from 'node:test';
import { CODE, TEMPLATE_POLICY_PRESETS, TemplateCageError, auditTemplate, createTemplatePolicy, getPolicy, isSafeTemplate, validateTemplate } from '../src/index.mjs';
import { assert, assertHasCode, expectTemplateError, hasCode } from './helpers.mjs';

const presetNames = ['strict', 'email', 'notification', 'audit'];

for (const name of presetNames) {
  test('preset exists and is deeply frozen ' + name, () => {
    const policy = getPolicy(name);
    assert.equal(policy.name, name);
    assert.equal(Object.isFrozen(policy), true);
    assert.equal(Object.isFrozen(policy.allowedFilters), true);
    assert.equal(TEMPLATE_POLICY_PRESETS[name], policy);
  });

  test('preset cannot be mutated ' + name, () => {
    const policy = getPolicy(name);
    assert.throws(() => {
      policy.maxBytes = 1;
    }, TypeError);
    assert.throws(() => {
      policy.allowedFilters.push('evil');
    }, TypeError);
  });
}

test('unknown preset throws typed error', () => {
  expectTemplateError(() => getPolicy('missing'), CODE.UNKNOWN_POLICY);
});

test('default audit policy is strict', () => {
  assert.equal(auditTemplate('{{ name }}').policy, 'strict');
});

const validCustomizations = [
  [{ policy: 'email', maxBytes: 1000 }, 'email', 1000],
  [{ policy: 'notification', maxOutputBytes: 1000 }, 'notification', 1000],
  [{ policy: 'audit', maxFindings: 3 }, 'audit', 3],
  [{ maxIterations: 7 }, 'strict', 500]
];

for (const [index, entry] of validCustomizations.entries()) {
  test('createTemplatePolicy accepts valid customization ' + index, () => {
    const options = entry[0];
    const policy = createTemplatePolicy(options);
    assert.equal(policy.name, entry[1]);
    if (options.maxBytes !== undefined) assert.equal(policy.maxBytes, entry[2]);
    if (options.maxOutputBytes !== undefined) assert.equal(policy.maxOutputBytes, entry[2]);
    if (options.maxFindings !== undefined) assert.equal(policy.maxFindings, entry[2]);
    if (options.maxIterations !== undefined) assert.equal(policy.maxIterations, 7);
    assert.equal(Object.isFrozen(policy), true);
  });
}

const invalidPolicyOptions = [
  ['negative maxBytes', { maxBytes: -1 }],
  ['zero maxBytes', { maxBytes: 0 }],
  ['fraction maxTags', { maxTags: 1.5 }],
  ['string maxTags', { maxTags: '10' }],
  ['too large maxBytes', { maxBytes: 268435457 }],
  ['negative loop depth', { maxLoopDepth: -1 }],
  ['negative iterations', { maxIterations: -1 }],
  ['negative findings', { maxFindings: -1 }],
  ['invalid mode', { mode: 'xml' }],
  ['unknown option', { unsafeMode: true }],
  ['unknown filter', { allowedFilters: ['system'] }],
  ['duplicate filter', { allowedFilters: ['upper', 'upper'] }],
  ['filter wrong type', { allowedFilters: 'upper' }],
  ['boolean wrong type', { allowLoops: 1 }],
  ['empty name', { name: '' }],
  ['long name', { name: 'x'.repeat(65) }],
  ['unknown base', { policy: 'missing' }]
];

for (const [name, options] of invalidPolicyOptions) {
  test('invalid policy option rejected ' + name, () => {
    assert.throws(() => createTemplatePolicy(options), (error) => {
      assert.equal(error.name, 'TemplateCageError');
      assert.equal(error.code === CODE.INVALID_OPTIONS || error.code === CODE.UNKNOWN_POLICY, true);
      return true;
    });
  });
}

test('policy option copies filter array instead of sharing it', () => {
  const filters = ['upper'];
  const policy = createTemplatePolicy({ allowedFilters: filters });
  filters.push('lower');
  assert.deepEqual(policy.allowedFilters, ['upper']);
});

test('policy creation ignores prototype pollution keys', () => {
  const options = JSON.parse('{"__proto__":{"polluted":true},"maxBytes":1024}');
  const policy = createTemplatePolicy(options);
  assert.equal(policy.maxBytes, 1024);
  assert.equal({}.polluted, undefined);
});

test('manually forged frozen policy is revalidated', () => {
  const forged = Object.freeze({ name: 'strict', maxBytes: -1 });
  assert.throws(() => auditTemplate('x', forged), (error) => error.name === 'TemplateCageError');
});

test('maxFindings zero fails closed', () => {
  const report = auditTemplate('plain text', { maxFindings: 0 });
  assert.equal(report.safe, false);
  assert.equal(report.truncatedFindings, true);
  assertHasCode(report, CODE.RESOURCE_LIMIT);
});

test('maxFindings one truncates additional findings', () => {
  const report = auditTemplate('{{7*7}}{% include "x" %}', { policy: 'audit', maxFindings: 1 });
  assert.equal(report.safe, false);
  assert.equal(report.findings.length, 1);
  assert.equal(report.truncatedFindings, true);
});

for (const limit of [1, 2, 5]) {
  test('maxFindings cap is respected ' + limit, () => {
    const report = auditTemplate('{{ constructor }}{% include "x" %}{{{x}}}', { policy: 'audit', maxFindings: limit });
    assert.equal(report.findings.length <= limit, true);
    assert.equal(report.safe, false);
  });
}

for (const [bytes, expected] of [[1, true], [8, true], [9, false], [32, false]]) {
  test('maxBytes audit boundary ' + bytes, () => {
    const template = 'x'.repeat(bytes);
    const report = auditTemplate(template, { maxBytes: 8 });
    assert.equal(report.safe, expected);
    if (!expected) assertHasCode(report, CODE.INPUT_TOO_LONG);
  });
}

test('maxBytes counts UTF-8 bytes not code units', () => {
  const report = auditTemplate('☃☃', { maxBytes: 5 });
  assert.equal(report.inputBytes, 6);
  assert.equal(report.safe, false);
  assertHasCode(report, CODE.INPUT_TOO_LONG);
});

for (const count of [1, 2, 3, 4]) {
  test('maxTags boundary count ' + count, () => {
    const template = '{{x}}'.repeat(count);
    const report = auditTemplate(template, { maxTags: 2 });
    assert.equal(report.tagCount, count);
    assert.equal(report.safe, count <= 2);
    if (count > 2) assertHasCode(report, CODE.TOO_MANY_TAGS);
  });
}

for (const length of [3, 8, 9, 40]) {
  test('maxExpressionLength boundary ' + length, () => {
    const template = '{{ ' + 'x'.repeat(length) + ' }}';
    const report = auditTemplate(template, { maxExpressionLength: 8 });
    assert.equal(report.safe, length <= 6);
  });
}

function nestedSections(depth) {
  let output = '';
  for (let index = 0; index < depth; index += 1) output += '{{#if x}}';
  for (let index = 0; index < depth; index += 1) output += '{{/if}}';
  return output;
}

for (const depth of [1, 2, 3, 5]) {
  test('maxNestingDepth audit depth ' + depth, () => {
    const report = auditTemplate(nestedSections(depth), { maxNestingDepth: 2 });
    assert.equal(report.safe, depth <= 2);
    if (depth > 2) assertHasCode(report, CODE.NESTING_TOO_DEEP);
  });
}

function nestedLoops(depth) {
  let output = '';
  for (let index = 0; index < depth; index += 1) output += '{{#each x}}';
  output += 'x';
  for (let index = 0; index < depth; index += 1) output += '{{/each}}';
  return output;
}

for (const depth of [1, 2, 3, 4]) {
  test('maxLoopDepth audit depth ' + depth, () => {
    const report = auditTemplate(nestedLoops(depth), { maxLoopDepth: 2 });
    assert.equal(report.safe, depth <= 2);
    if (depth > 2) assertHasCode(report, CODE.LOOP_TOO_DEEP);
  });
}

const controlCases = [
  ['NUL', 0x0000, CODE.CONTROL_CHARACTER],
  ['SOH', 0x0001, CODE.CONTROL_CHARACTER],
  ['backspace', 0x0008, CODE.CONTROL_CHARACTER],
  ['vertical tab', 0x000b, CODE.CONTROL_CHARACTER],
  ['escape', 0x001b, CODE.CONTROL_CHARACTER],
  ['delete', 0x007f, CODE.CONTROL_CHARACTER],
  ['C1 control', 0x0085, CODE.CONTROL_CHARACTER],
  ['Arabic letter mark', 0x061c, CODE.BIDI_CONTROL],
  ['left to right mark', 0x200e, CODE.BIDI_CONTROL],
  ['right to left mark', 0x200f, CODE.BIDI_CONTROL],
  ['left to right embedding', 0x202a, CODE.BIDI_CONTROL],
  ['right to left override', 0x202e, CODE.BIDI_CONTROL],
  ['line separator', 0x2028, CODE.CONTROL_CHARACTER],
  ['paragraph separator', 0x2029, CODE.CONTROL_CHARACTER],
  ['left isolate', 0x2066, CODE.BIDI_CONTROL],
  ['pop isolate', 0x2069, CODE.BIDI_CONTROL]
];

for (const [name, codePoint, expectedCode] of controlCases) {
  test('audit rejects hostile character ' + name, () => {
    const report = auditTemplate('a' + String.fromCodePoint(codePoint) + 'b', 'audit');
    assert.equal(report.safe, false);
    assertHasCode(report, expectedCode);
  });
}

for (const codeUnit of [0xd800, 0xdbff, 0xdc00, 0xdfff]) {
  test('audit rejects unpaired surrogate ' + codeUnit.toString(16), () => {
    const report = auditTemplate('a' + String.fromCharCode(codeUnit) + 'b', 'audit');
    assert.equal(report.safe, false);
    assertHasCode(report, CODE.UNPAIRED_SURROGATE);
  });
}

for (const character of ['\t', '\n', '\r']) {
  test('audit permits ordinary whitespace control ' + JSON.stringify(character), () => {
    assert.equal(auditTemplate('a' + character + 'b', 'audit').safe, true);
  });
}

const foreignStrictTemplates = [
  '{% include "x" %}',
  '{% set x = 1 %}',
  '{# comment #}',
  '<% const x = 1 %>',
  '<%= x %>',
  '${x}',
  '#{x}',
  '{{> partial}}',
  '{{{x}}}',
  '{{&x}}'
];

for (const [index, template] of foreignStrictTemplates.entries()) {
  test('strict policy rejects foreign or raw syntax ' + index, () => {
    const report = auditTemplate(template, 'strict');
    assert.equal(report.safe, false);
    assert.equal(hasCode(report, CODE.UNSUPPORTED_TAG) || hasCode(report, CODE.RAW_HTML) || hasCode(report, CODE.FILE_INCLUSION), true);
  });
}

test('notification policy rejects loops', () => {
  const report = auditTemplate('{{#each items}}{{this}}{{/each}}', 'notification');
  assert.equal(report.safe, false);
  assertHasCode(report, CODE.UNSUPPORTED_TAG);
});

test('notification policy accepts simple interpolation', () => {
  assert.equal(auditTemplate('Hello {{ user.name }}', 'notification').safe, true);
});

test('audit preset does not apply data-only unsupported tag finding to jinja if', () => {
  const report = auditTemplate('{% if user %}hello{% endif %}', 'audit');
  assert.equal(report.safe, true);
  assert.equal(hasCode(report, CODE.UNSUPPORTED_TAG), false);
});

test('strict report is deeply frozen', () => {
  const report = auditTemplate('{{7*7}}', 'audit');
  assert.equal(Object.isFrozen(report), true);
  assert.equal(Object.isFrozen(report.findings), true);
  assert.equal(Object.isFrozen(report.findings[0]), true);
  assert.throws(() => {
    report.findings.push({});
  }, TypeError);
});

test('TemplateCageError exposes frozen detail and offset', () => {
  try {
    validateTemplate('{{7*7}}', 'audit');
    assert.fail('expected throw');
  } catch (error) {
    assert.equal(error instanceof TemplateCageError, true);
    assert.equal(error.code, CODE.TEMPLATE_INJECTION);
    assert.equal(typeof error.offset, 'number');
    assert.equal(Object.isFrozen(error.detail), true);
    assert.equal(error.toJSON().code, CODE.TEMPLATE_INJECTION);
  }
});

for (const value of [undefined, null, 0, 1, true, {}, [], () => {}]) {
  test('isSafeTemplate rejects non string input type ' + String(value === undefined ? 'undefined' : Array.isArray(value) ? 'array' : typeof value), () => {
    assert.equal(isSafeTemplate(value), false);
  });
}

for (const value of [null, 0, true, {}, []]) {
  test('auditTemplate rejects non string input type ' + String(Array.isArray(value) ? 'array' : typeof value), () => {
    expectTemplateError(() => auditTemplate(value), CODE.INVALID_INPUT);
  });
}

test('safe validate returns same shaped frozen report', () => {
  const report = validateTemplate('Hello {{ name }}', 'strict');
  assert.equal(report.safe, true);
  assert.equal(Object.isFrozen(report), true);
});

test('audit does not mutate or freeze a caller owned options object', () => {
  const options = { maxBytes: 100 };
  const before = Object.isFrozen(options);
  auditTemplate('hello', options);
  assert.equal(Object.isFrozen(options), before);
  assert.deepEqual(options, { maxBytes: 100 });
});

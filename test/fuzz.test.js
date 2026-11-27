import test from 'node:test';
import assert from 'node:assert/strict';
import fc from 'fast-check';

import {
  CODE,
  TemplateCageError,
  auditTemplate,
  compileTemplate,
  renderTemplate,
} from '../src/index.mjs';

const propertyOptions = { seed: 20261127, numRuns: 120 };
const textUnit = fc.constantFrom(...'abcXYZ019 <>&"\''.split(''));
const safeText = fc.string({ unit: textUnit, minLength: 0, maxLength: 24 });

function escapeHtml(value) {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

test('benign generated values render with exact contextual escaping', () => {
  fc.assert(
    fc.property(safeText, (value) => {
      assert.equal(renderTemplate('Hello {{ name }}', { name: value }), `Hello ${escapeHtml(value)}`);
    }),
    propertyOptions,
  );
});

test('generated dangerous terms are unsafe in every scanned delimiter family', () => {
  const term = fc.constantFrom('constructor', '__proto__', 'process', 'require', 'eval', '__class__', 'subprocess');
  const family = fc.constantFrom('mustache', 'jinja', 'javascript');
  fc.assert(
    fc.property(term, family, (dangerousTerm, delimiterFamily) => {
      const template = delimiterFamily === 'mustache'
        ? `{{ x.${dangerousTerm} }}`
        : delimiterFamily === 'jinja'
          ? `{% set value = x.${dangerousTerm} %}`
          : '${x.' + dangerousTerm + '}';
      const report = auditTemplate(template, 'audit');
      assert.equal(report.safe, false, template);
      assert.ok(report.findings.length > 0);
      assert.ok(report.findings.every((finding) => finding.code.startsWith('TEMPLATECAGE_')));
    }),
    propertyOptions,
  );
});

test('generated prototype path segments are rejected at compile time', () => {
  const segment = fc.constantFrom('__proto__', 'constructor', 'prototype', '__class__', '__globals__');
  fc.assert(
    fc.property(segment, (blockedSegment) => {
      assert.throws(
        () => compileTemplate(`{{ user.${blockedSegment} }}`),
        (error) => error instanceof TemplateCageError && error.code === CODE.PROTOTYPE_ACCESS,
      );
    }),
    propertyOptions,
  );
});

test('generated inherited values are neutralized rather than rendered', () => {
  fc.assert(
    fc.property(safeText, (secret) => {
      const prototype = { secret };
      const user = Object.create(prototype);
      assert.equal(renderTemplate('{{ user.secret }}', { user }), '');
    }),
    propertyOptions,
  );
});

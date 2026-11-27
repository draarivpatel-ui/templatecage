import test from 'node:test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { assert, assertNoControlOutput, cliPath, repoRoot, runCli } from './helpers.mjs';

function json(result) {
  return JSON.parse(result.stdout);
}

test('CLI help exits zero', () => {
  const result = runCli(['--help']);
  assert.equal(result.status, 0);
  assert.match(result.stdout, /templatecage 1\.0\.0/);
  assert.match(result.stdout, /audit \[template\]/);
  assert.match(result.stdout, /extract-vars/);
});

test('CLI short help exits zero', () => {
  assert.equal(runCli(['-h']).status, 0);
});

test('CLI version exits zero', () => {
  const result = runCli(['--version']);
  assert.equal(result.status, 0);
  assert.equal(result.stdout, 'templatecage 1.0.0\n');
});

test('CLI short version exits zero', () => {
  assert.equal(runCli(['-v']).status, 0);
});

const usageCases = [
  [],
  ['bogus'],
  ['audit', 'x', 'y'],
  ['audit', 'x', '--bogus'],
  ['audit', 'x', '--policy'],
  ['audit', 'x', '--policy', 'missing'],
  ['render', 'x', '--policy', 'audit'],
  ['render', 'x', '--data'],
  ['render', 'x', '--data', '{bad'],
  ['render', 'x', '--data', '[1]'],
  ['extract-vars', 'x', '--policy', 'audit'],
  ['extract-vars', 'x', '--unknown']
];

for (const [index, args] of usageCases.entries()) {
  test('CLI usage error exits two ' + index, () => {
    const result = runCli(args);
    assert.equal(result.status, 2, result.stderr);
    assertNoControlOutput(result.stderr);
  });
}

const auditCases = [
  ['plain text', 0],
  ['Hello {{ user.name }}', 0],
  ['{{7*7}}', 1],
  ['{{ x.constructor }}', 1],
  ['{% include "x" %}', 1],
  ['{{{x}}}', 1],
  ['<%- x %>', 1],
  ['${process.exit()}', 1],
  ['#{process.exit()}', 1],
  ['{{ x | safe }}', 1],
  ['{{> partial}}', 1],
  ['{% set x = 1 %}', 1],
  ['{{ obj["\\x63onstructor"] }}', 1]
];

for (const [template, status] of auditCases) {
  test('CLI audit exit status for ' + template.slice(0, 24), () => {
    const result = runCli(['audit', template]);
    assert.equal(result.status, status, result.stderr + result.stdout);
    assertNoControlOutput(result.stdout);
  });
}

test('CLI audit plain output marks safe yes', () => {
  const result = runCli(['audit', 'Hello {{ name }}']);
  assert.equal(result.status, 0);
  assert.match(result.stdout, /safe: yes/);
  assert.match(result.stdout, /policy: audit/);
});

test('CLI audit plain output marks unsafe and finding', () => {
  const result = runCli(['audit', '{{7*7}}']);
  assert.equal(result.status, 1);
  assert.match(result.stdout, /safe: no/);
  assert.match(result.stdout, /TEMPLATECAGE_TEMPLATE_INJECTION/);
});

test('CLI audit JSON output parses', () => {
  const result = runCli(['audit', '{{7*7}}', '--json']);
  assert.equal(result.status, 1);
  const report = json(result);
  assert.equal(report.safe, false);
  assert.equal(report.policy, 'audit');
  assert.equal(report.findings[0].code, 'TEMPLATECAGE_TEMPLATE_INJECTION');
});

test('CLI audit strict policy accepts data-only template', () => {
  assert.equal(runCli(['audit', '{{#if user.ok}}yes{{/if}}', '--policy', 'strict']).status, 0);
});

test('CLI audit notification policy rejects loop', () => {
  assert.equal(runCli(['audit', '{{#each x}}{{this}}{{/each}}', '--policy', 'notification']).status, 1);
});

test('CLI audit equals policy syntax works', () => {
  assert.equal(runCli(['audit', '{{ name }}', '--policy=strict']).status, 0);
});

const renderCases = [
  ['Hello {{ name }}', '{"name":"Ada"}', 'Hello Ada\n'],
  ['{{ value }}', '{"value":"<x>"}', '&lt;x&gt;\n'],
  ['{{ value | upper }}', '{"value":"ab"}', 'AB\n'],
  ['{{#if ok}}yes{{else}}no{{/if}}', '{"ok":true}', 'yes\n'],
  ['{{#if ok}}yes{{else}}no{{/if}}', '{"ok":false}', 'no\n'],
  ['{{#unless hidden}}shown{{/unless}}', '{"hidden":false}', 'shown\n'],
  ['{{#each items}}{{this}}{{/each}}', '{"items":["a","b"]}', 'ab\n'],
  ['{{#each users}}{{this.name}}{{/each}}', '{"users":[{"name":"a"},{"name":"b"}]}', 'ab\n'],
  ['{{ missing | default:\'x\' }}', '{}', 'x\n'],
  ['{{ value | escapeUrl }}', '{"value":"a b"}', 'a%20b\n']
];

for (const [index, entry] of renderCases.entries()) {
  test('CLI render output case ' + index, () => {
    const result = runCli(['render', entry[0], '--data', entry[1]]);
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout, entry[2]);
  });
}

test('CLI render missing data uses empty object', () => {
  const result = runCli(['render', 'Hello {{ name }}']);
  assert.equal(result.status, 0);
  assert.equal(result.stdout, 'Hello \n');
});

test('CLI render invalid template exits one', () => {
  const result = runCli(['render', '{{7*7}}']);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /TEMPLATECAGE/);
  assertNoControlOutput(result.stderr);
});

test('CLI render foreign syntax exits one', () => {
  assert.equal(runCli(['render', '{% include "x" %}']).status, 1);
});

test('CLI render JSON output parses', () => {
  const result = runCli(['render', 'Hello {{ name }}', '--data', '{"name":"Ada"}', '--json']);
  assert.equal(result.status, 0);
  assert.deepEqual(json(result), { output: 'Hello Ada' });
});

test('CLI render JSON error output parses and exits one', () => {
  const result = runCli(['render', '{{7*7}}', '--json']);
  assert.equal(result.status, 1);
  const report = json(result);
  assert.equal(report.error.code, 'TEMPLATECAGE_UNSAFE_EXPRESSION');
});

test('CLI render equals data syntax works', () => {
  const result = runCli(['render', '{{x}}', '--data={"x":"a"}']);
  assert.equal(result.status, 0);
  assert.equal(result.stdout, 'a\n');
});

test('CLI render notification policy uses text mode', () => {
  const result = runCli(['render', '{{x}}', '--data', '{"x":"<b>"}', '--policy', 'notification']);
  assert.equal(result.status, 0);
  assert.equal(result.stdout, '<b>\n');
});

test('CLI render data file works', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'templatecage-cli-'));
  try {
    const file = path.join(directory, 'data.json');
    fs.writeFileSync(file, '{"name":"Ada"}', 'utf8');
    const result = runCli(['render', 'Hello {{name}}', '--data', '@' + file]);
    assert.equal(result.status, 0);
    assert.equal(result.stdout, 'Hello Ada\n');
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('CLI render missing data file exits two', () => {
  const result = runCli(['render', 'x', '--data', '@/definitely/missing/templatecage-data.json']);
  assert.equal(result.status, 2);
});

test('CLI render reads stdin template', () => {
  const result = runCli(['render', '--data', '{"name":"Ada"}'], 'Hello {{ name }}\n');
  assert.equal(result.status, 0);
  assert.equal(result.stdout, 'Hello Ada\n');
});

test('CLI stdin removes exactly one LF', () => {
  const result = runCli(['render'], 'x\n\n');
  assert.equal(result.status, 0);
  assert.equal(result.stdout, 'x\n\n');
});

test('CLI stdin removes one CRLF', () => {
  const result = runCli(['render'], 'x\r\n');
  assert.equal(result.status, 0);
  assert.equal(result.stdout, 'x\n');
});

test('CLI stdin preserves leading and trailing spaces', () => {
  const result = runCli(['render'], '  x  \n');
  assert.equal(result.status, 0);
  assert.equal(result.stdout, '  x  \n');
});

test('CLI audit reads stdin template', () => {
  const result = runCli(['audit'], '{{7*7}}\n');
  assert.equal(result.status, 1);
});

test('CLI extract vars reads stdin template', () => {
  const result = runCli(['extract-vars'], '{{ user.name }}\n');
  assert.equal(result.status, 0);
  assert.equal(result.stdout, 'user.name\n');
});

test('CLI stdin invalid UTF-8 exits two', () => {
  const result = spawnSync(process.execPath, [cliPath, 'render'], {
    cwd: repoRoot,
    input: Buffer.from([0xff, 0xfe]),
    encoding: 'utf8',
    timeout: 10000
  });
  assert.equal(result.status, 2);
  assertNoControlOutput(result.stderr);
});

test('CLI stdin byte cap exits two', () => {
  const result = spawnSync(process.execPath, [cliPath, 'render'], {
    cwd: repoRoot,
    input: Buffer.alloc(1048577, 65),
    encoding: 'utf8',
    timeout: 10000,
    maxBuffer: 1024 * 1024 * 4
  });
  assert.equal(result.status, 2);
});

const extractCases = [
  ['{{name}}', ['name']],
  ['{{ user.name | upper }}', ['user.name']],
  ['{{#if user.ok}}{{user.name}}{{/if}}', ['user.name', 'user.ok']],
  ['{{#each users}}{{this.name}}{{/each}}', ['this.name', 'users']],
  ['{{b}}{{a}}', ['a', 'b']]
];

for (const [index, entry] of extractCases.entries()) {
  test('CLI extract vars case ' + index, () => {
    const result = runCli(['extract-vars', entry[0]]);
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(result.stdout.trim().split('\n').filter(Boolean), entry[1]);
  });
}

test('CLI extract vars JSON output parses', () => {
  const result = runCli(['extract-vars', '{{#if user.ok}}{{user.name}}{{/if}}', '--json']);
  assert.equal(result.status, 0);
  assert.deepEqual(json(result).variables, ['user.name', 'user.ok']);
});

test('CLI extract vars invalid template exits one', () => {
  assert.equal(runCli(['extract-vars', '{{> partial}}']).status, 1);
});

test('CLI stderr neutralizes bidi characters in unknown command', () => {
  const result = runCli(['bogus' + String.fromCharCode(0x202e)]);
  assert.equal(result.status, 2);
  assertNoControlOutput(result.stderr);
  assert.match(result.stderr, /<U\+202E>/);
});

test('CLI stderr neutralizes ANSI escape in unknown command', () => {
  const result = runCli(['bogus' + String.fromCharCode(27) + '[31m']);
  assert.equal(result.status, 2);
  assertNoControlOutput(result.stderr);
  assert.match(result.stderr, /<U\+001B>/);
});

test('CLI rendered output cannot contain data supplied ANSI control', () => {
  const data = JSON.stringify({ x: 'a' + String.fromCharCode(27) + '[31mb' });
  const result = runCli(['render', '{{x}}', '--data', data]);
  assert.equal(result.status, 0);
  assertNoControlOutput(result.stdout);
  assert.equal(result.stdout.includes('[31mb'), true);
});

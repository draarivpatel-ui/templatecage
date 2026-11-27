import test from 'node:test';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import * as esm from '../src/index.mjs';
import { assert, repoFiles, repoJson, repoRoot, repoText } from './helpers.mjs';

const require = createRequire(import.meta.url);
const cjs = require('../cjs/index.cjs');

const packageJson = repoJson('package.json');

test('package name version license and author are correct', () => {
  assert.equal(packageJson.name, 'templatecage');
  assert.equal(packageJson.version, '1.0.0');
  assert.equal(packageJson.license, 'MIT');
  assert.equal(packageJson.author, 'draarivpatel-ui');
});

test('package keeps runtime dependencies empty and fast-check development-only', () => {
  assert.deepEqual(packageJson.dependencies, {});
  assert.deepEqual(packageJson.devDependencies, { 'fast-check': '4.10.3' });
});

test('package requires Node eighteen or newer', () => {
  assert.equal(packageJson.engines.node, '>=18.0.0');
});

test('package is marked side effect free', () => {
  assert.equal(packageJson.sideEffects, false);
});

test('package export map exposes types ESM and CJS', () => {
  assert.equal(packageJson.exports['.'].types, './types/index.d.ts');
  assert.equal(packageJson.exports['.'].import, './src/index.mjs');
  assert.equal(packageJson.exports['.'].require, './cjs/index.cjs');
});

test('package main module and types paths are correct', () => {
  assert.equal(packageJson.main, './cjs/index.cjs');
  assert.equal(packageJson.module, './src/index.mjs');
  assert.equal(packageJson.types, './types/index.d.ts');
});

test('package bin points at the CLI', () => {
  assert.equal(packageJson.bin.templatecage, 'bin/templatecage.mjs');
});

for (const entry of ['bin', 'src', 'cjs', 'types', 'examples', 'README.md', 'SECURITY.md', 'CONTRIBUTING.md', 'CODE_OF_CONDUCT.md', 'CHANGELOG.md', 'LICENSE']) {
  test('package files list includes ' + entry, () => {
    assert.equal(packageJson.files.includes(entry), true);
  });
}

for (const script of ['build:cjs', 'check:cjs', 'check:types', 'smoke', 'test', 'prepack']) {
  test('package script exists ' + script, () => {
    assert.equal(typeof packageJson.scripts[script], 'string');
  });
}

const publicNames = [
  'TEMPLATECAGE_VERSION',
  'TEMPLATECAGE_ERROR_CODES',
  'TEMPLATECAGE_SEVERITY',
  'CODE',
  'TemplateCageError',
  'SAFE_FILTER_NAMES',
  'TEMPLATE_POLICY_PRESETS',
  'createTemplatePolicy',
  'getPolicy',
  'auditTemplate',
  'isSafeTemplate',
  'validateTemplate',
  'compileTemplate',
  'renderTemplate',
  'extractTemplateVariables'
];

for (const name of publicNames) {
  test('ESM public export exists ' + name, () => {
    assert.equal(esm[name] !== undefined, true);
  });
  test('CJS public export exists ' + name, () => {
    assert.equal(cjs[name] !== undefined, true);
  });
}

const parityCases = [
  ['plain', 'Hello {{ name }}', { name: 'Ada' }],
  ['escape', '{{ value }}', { value: '<x>&' }],
  ['filter', '{{ value | upper }}', { value: 'ab' }],
  ['default', '{{ missing | default:\'x\' }}', {}],
  ['if', '{{#if ok}}yes{{else}}no{{/if}}', { ok: false }],
  ['unless', '{{#unless hidden}}shown{{/unless}}', { hidden: false }],
  ['each', '{{#each items}}{{this}}{{/each}}', { items: [1, 2] }],
  ['nested this', '{{#each users}}{{this.name}}{{/each}}', { users: [{ name: 'a' }] }],
  ['metadata', '{{#each items}}{{ @index }}{{/each}}', { items: ['a', 'b'] }],
  ['text mode', '{{ value }}', { value: '<x>' }]
];

for (const [name, template, data] of parityCases) {
  test('CJS and ESM render parity ' + name, () => {
    const options = name === 'text mode' ? 'notification' : 'strict';
    assert.equal(cjs.renderTemplate(template, data, options), esm.renderTemplate(template, data, options));
  });
}

for (const template of ['{{7*7}}', '{% include "x" %}', '{{ x.constructor }}', '{{ x | safe }}']) {
  test('CJS and ESM audit parity ' + template, () => {
    const left = cjs.auditTemplate(template, 'audit');
    const right = esm.auditTemplate(template, 'audit');
    assert.deepEqual(left.findings.map((finding) => finding.code), right.findings.map((finding) => finding.code));
    assert.equal(left.safe, right.safe);
  });
}

test('CJS version matches ESM version', () => {
  assert.equal(cjs.TEMPLATECAGE_VERSION, esm.TEMPLATECAGE_VERSION);
  assert.equal(cjs.TEMPLATECAGE_VERSION, packageJson.version);
});

test('CJS compiled templates enforce their own integrity boundary', () => {
  const compiled = cjs.compileTemplate('Hello {{name}}');
  assert.equal(cjs.renderTemplate(compiled, { name: 'x' }), 'Hello x');
  assert.throws(() => cjs.renderTemplate({ kind: 'templatecage-compiled-template' }, {}), /TEMPLATECAGE_TEMPLATE_INTEGRITY/);
});

test('CJS build is current', () => {
  const result = spawnSync(process.execPath, [path.join(repoRoot, 'scripts', 'build-cjs.mjs'), '--check'], { cwd: repoRoot, encoding: 'utf8', timeout: 120000 });
  assert.equal(result.status, 0, result.stdout + result.stderr);
});

test('CJS build carries generated marker', () => {
  assert.equal(repoText('cjs/index.cjs').includes('Generated by scripts/build-cjs.mjs'), true);
});

test('strict TypeScript declaration fixture passes', () => {
  const result = spawnSync(process.execPath, [path.join(repoRoot, 'scripts', 'check-types.mjs')], { cwd: repoRoot, encoding: 'utf8', timeout: 120000 });
  assert.equal(result.status, 0, result.stdout + result.stderr);
});

test('types declare public API without any', () => {
  const text = repoText('types/index.d.ts');
  assert.equal(/\bany\b/u.test(text), false);
  for (const name of ['auditTemplate', 'isSafeTemplate', 'validateTemplate', 'compileTemplate', 'renderTemplate', 'extractTemplateVariables', 'createTemplatePolicy', 'getPolicy']) {
    assert.equal(text.includes('function ' + name + '('), true, name);
  }
});

test('types declare every runtime error code', () => {
  const text = repoText('types/index.d.ts');
  for (const key of Object.keys(esm.TEMPLATECAGE_ERROR_CODES)) {
    assert.equal(text.includes('readonly ' + key + ':'), true, key);
    assert.equal(text.includes("'" + esm.TEMPLATECAGE_ERROR_CODES[key] + "'"), true, key);
  }
});

test('test runner enumerates tests with readdirSync rather than shell globs', () => {
  const runner = repoText('scripts/run-tests.mjs');
  assert.equal(runner.includes('fs.readdirSync'), true);
  assert.equal(runner.includes('*.test.mjs'), false);
});

test('type checker script is Windows compatible', () => {
  const text = repoText('scripts/check-types.mjs');
  assert.equal(text.includes("process.platform === 'win32'"), true);
  assert.equal(text.includes("name + '.cmd'"), true);
  assert.equal(text.includes('shell: process.platform === \'win32\''), true);
});

test('CI tests Linux and Windows across four Node versions', () => {
  const ci = repoText('.github/workflows/ci.yml');
  assert.equal(ci.includes('os: [ubuntu-24.04, windows-latest]'), true);
  assert.equal(ci.includes('node: [18, 20, 22, 24]'), true);
});

test('CI runs tests CJS types smoke and pack verification', () => {
  const ci = repoText('.github/workflows/ci.yml');
  for (const command of ['npm test', 'node scripts/build-cjs.mjs --check', 'node scripts/check-types.mjs', 'node scripts/cli-smoke.mjs', 'npm pack --dry-run']) {
    assert.equal(ci.includes(command), true, command);
  }
});

test('gitignore excludes package tarballs dependencies and local noise', () => {
  const text = repoText('.gitignore');
  assert.equal(text.includes('node_modules/'), true);
  assert.equal(text.includes('*.tgz'), true);
  assert.equal(text.includes('.DS_Store'), true);
});

test('gitattributes normalizes text line endings', () => {
  const text = repoText('.gitattributes');
  assert.equal(text.includes('*.mjs text eol=lf'), true);
  assert.equal(text.includes('*.cjs text eol=lf'), true);
});

test('MIT license copyright is correct', () => {
  assert.equal(repoText('LICENSE').includes('Copyright (c) 2026 draarivpatel-ui'), true);
});

test('README documents security boundary and renderer constraints', () => {
  const text = repoText('README.md');
  for (const phrase of ['does not read files', 'never intentionally walks the prototype chain', 'maxIterations', 'maxOutputBytes', 'Security boundary', 'not a complete sanitizer']) {
    assert.equal(text.includes(phrase), true, phrase);
  }
});

test('SECURITY CONTRIBUTING and CHANGELOG cover required process', () => {
  assert.equal(repoText('SECURITY.md').includes('private GitHub Security Advisory'), true);
  assert.equal(repoText('CONTRIBUTING.md').includes('zero-dependency'), true);
  assert.equal(repoText('CHANGELOG.md').includes('## 1.0.0'), true);
});

test('repository files contain no em dash or en dash', () => {
  const em = String.fromCharCode(0x2014);
  const en = String.fromCharCode(0x2013);
  for (const file of repoFiles()) {
    const text = fs.readFileSync(file, 'utf8');
    assert.equal(text.includes(em) || text.includes(en), false, path.relative(repoRoot, file));
  }
});

test('repository files contain no local absolute user paths', () => {
  const marker = '/' + 'Users' + '/';
  for (const file of repoFiles()) {
    const text = fs.readFileSync(file, 'utf8');
    assert.equal(text.includes(marker), false, path.relative(repoRoot, file));
  }
});

test('repository files contain no private mailbox fragments', () => {
  const markers = ['someone' + '@gmail', 'handle-redacted' + '286'];
  for (const file of repoFiles()) {
    const text = fs.readFileSync(file, 'utf8');
    for (const marker of markers) assert.equal(text.includes(marker), false, path.relative(repoRoot, file));
  }
});

test('source has no external package imports', () => {
  for (const file of fs.readdirSync(path.join(repoRoot, 'src')).filter((name) => name.endsWith('.mjs'))) {
    const text = fs.readFileSync(path.join(repoRoot, 'src', file), 'utf8');
    const imports = Array.from(text.matchAll(/from\s+['"]([^'"]+)['"]/gu), (match) => match[1]);
    for (const specifier of imports) assert.equal(specifier.startsWith('./') || specifier.startsWith('node:'), true, file + ': ' + specifier);
  }
});

test('source does not call eval or the Function constructor', () => {
  for (const file of repoFiles()) {
    const relative = path.relative(repoRoot, file);
    if (!relative.startsWith('src') && !relative.startsWith('bin')) continue;
    const text = fs.readFileSync(file, 'utf8');
    assert.equal(/\beval\s*\(/u.test(text), false, relative);
    assert.equal(/new\s+Function\s*\(/u.test(text), false, relative);
  }
});

test('no package tarball or node_modules directory is present', () => {
  assert.equal(repoFiles().some((file) => file.endsWith('.tgz')), false);
  assert.equal(fs.existsSync(path.join(repoRoot, 'node_modules')), false);
});

test('examples parse as valid JavaScript', () => {
  for (const file of fs.readdirSync(path.join(repoRoot, 'examples')).filter((name) => name.endsWith('.mjs'))) {
    const result = spawnSync(process.execPath, ['--check', path.join(repoRoot, 'examples', file)], { encoding: 'utf8' });
    assert.equal(result.status, 0, file);
  }
});

test('all examples execute successfully', () => {
  for (const file of fs.readdirSync(path.join(repoRoot, 'examples')).filter((name) => name.endsWith('.mjs')).sort()) {
    const result = spawnSync(process.execPath, [path.join(repoRoot, 'examples', file)], { cwd: repoRoot, encoding: 'utf8', timeout: 10000 });
    assert.equal(result.status, 0, file + ': ' + result.stderr);
  }
});

test('CLI file is executable and has a shebang', () => {
  const text = repoText('bin/templatecage.mjs');
  assert.equal(text.startsWith('#!/usr/bin/env node'), true);
  if (process.platform !== 'win32') {
    const mode = fs.statSync(path.join(repoRoot, 'bin', 'templatecage.mjs')).mode;
    assert.equal((mode & 0o111) !== 0, true);
  }
});

test('policy presets object is frozen', () => {
  assert.equal(Object.isFrozen(esm.TEMPLATE_POLICY_PRESETS), true);
  for (const name of ['strict', 'email', 'notification', 'audit']) {
    assert.equal(Object.isFrozen(esm.TEMPLATE_POLICY_PRESETS[name]), true);
  }
});

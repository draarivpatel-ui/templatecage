import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

export { assert };

export const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const cliPath = path.join(repoRoot, 'bin', 'templatecage.mjs');

export function repoText(relative) {
  return fs.readFileSync(path.join(repoRoot, relative), 'utf8');
}

export function repoJson(relative) {
  return JSON.parse(repoText(relative));
}

export function repoFiles(directory = repoRoot, output = []) {
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    if (entry.name === '.git' || entry.name === 'node_modules') continue;
    const full = path.join(directory, entry.name);
    if (entry.isDirectory()) repoFiles(full, output);
    else if (entry.isFile()) output.push(full);
  }
  return output.sort();
}

export function runCli(args, input = '') {
  return spawnSync(process.execPath, [cliPath, ...args], {
    cwd: repoRoot,
    input,
    encoding: 'utf8',
    timeout: 10000
  });
}

export function codes(report) {
  return report.findings.map((finding) => finding.code);
}

export function hasCode(report, code) {
  return codes(report).includes(code);
}

export function assertHasCode(report, code) {
  assert.equal(hasCode(report, code), true, 'expected ' + code + ' in ' + codes(report).join(','));
}

export function expectTemplateError(fn, code) {
  assert.throws(fn, (error) => {
    assert.equal(error.name, 'TemplateCageError');
    assert.equal(error.code, code);
    return true;
  });
}

export function assertNoControlOutput(value) {
  assert.equal(/[\u0000-\u0009\u000B-\u001F\u007F-\u009F\u00AD\u200B-\u200F\u2028\u2029\u202A-\u202E\u2066-\u2069\uFEFF]/u.test(value), false);
}

export function repeat(count, factory) {
  return Array.from({ length: count }, (_, index) => factory(index));
}

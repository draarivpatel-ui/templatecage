import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const cli = path.join(root, 'bin', 'templatecage.mjs');

function run(args, input = '') {
  return spawnSync(process.execPath, [cli, ...args], { cwd: root, input, encoding: 'utf8', timeout: 10000 });
}

assert.equal(run(['--version']).stdout.trim(), 'templatecage 1.0.0');
assert.equal(run(['--help']).status, 0);
assert.equal(run(['render', 'Hello {{ name }}', '--data', '{"name":"<world>"}']).stdout.trim(), 'Hello &lt;world&gt;');
assert.equal(run(['audit', '{{7*7}}']).status, 1);
assert.equal(run(['audit', 'Hello {{ name }}']).status, 0);
const vars = JSON.parse(run(['extract-vars', '{{#if user.ok}}{{user.name}}{{/if}}', '--json']).stdout);
assert.deepEqual(vars.variables, ['user.name', 'user.ok']);
assert.equal(run(['render'], 'Hello {{ name }}\n').status, 0);
process.stdout.write('templatecage CLI smoke passed\n');

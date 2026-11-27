import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const typesPath = path.join(root, 'types', 'index.d.ts');
const tsconfigPath = path.join(root, 'test', 'tsconfig.json');
const declaration = fs.readFileSync(typesPath, 'utf8');

if (/\bany\b/u.test(declaration)) {
  console.error('types/index.d.ts must not use the any type');
  process.exit(1);
}
for (const required of ['auditTemplate', 'isSafeTemplate', 'validateTemplate', 'compileTemplate', 'renderTemplate', 'extractTemplateVariables', 'createTemplatePolicy', 'getPolicy']) {
  if (!declaration.includes('function ' + required + '(')) {
    console.error('types/index.d.ts does not declare ' + required);
    process.exit(1);
  }
}

function command(name) {
  return process.platform === 'win32' ? name + '.cmd' : name;
}

function run(cmd, args) {
  return spawnSync(cmd, args, {
    cwd: root,
    encoding: 'utf8',
    shell: process.platform === 'win32',
    timeout: 120000
  });
}

let result = run(command('tsc'), ['-p', tsconfigPath, '--pretty', 'false']);
if ((result.error && result.error.code === 'ENOENT') || (process.platform === 'win32' && result.status !== 0)) {
  const fallback = run(command('npm'), ['exec', '--yes', '--package=typescript@5.9.2', '--', 'tsc', '-p', tsconfigPath, '--pretty', 'false']);
  if (!fallback.error || fallback.error.code !== 'ENOENT') result = fallback;
}
if (result.error) {
  console.error('type checker could not be started: ' + result.error.message);
  process.exit(1);
}
if (result.status !== 0) {
  process.stderr.write(result.stdout + result.stderr);
  process.exit(result.status === null ? 1 : result.status);
}
process.stdout.write('strict TypeScript declaration check passed\n');

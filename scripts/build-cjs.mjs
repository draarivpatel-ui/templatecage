/*
 * Generate the CommonJS bundle from the ESM sources.
 * The bundler is deliberately narrow and accepts only the explicit static
 * import and export forms used by src/*.mjs.
 */
import { mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const sourceDirectory = path.join(root, 'src');
const args = process.argv.slice(2);
for (const arg of args) {
  if (arg !== '--check') throw new Error('unknown build-cjs argument: ' + arg);
}
const check = args.includes('--check');

const PUBLIC_EXPORTS = [
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

function parseImportClause(clause) {
  return clause.split(',').map((part) => {
    const words = part.trim().split(/\s+/);
    if (words.length === 1 && /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(words[0])) {
      return { imported: words[0], local: words[0] };
    }
    if (words.length === 3 && words[1] === 'as' && /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(words[0]) && /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(words[2])) {
      return { imported: words[0], local: words[2] };
    }
    throw new Error('unsupported import clause entry: ' + part.trim());
  });
}

function parseExportClause(clause) {
  return clause.split(',').map((part) => {
    const words = part.trim().split(/\s+/);
    if (words.length === 1 && /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(words[0])) {
      return { local: words[0], exported: words[0] };
    }
    if (words.length === 3 && words[1] === 'as' && /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(words[0]) && /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(words[2])) {
      return { local: words[0], exported: words[2] };
    }
    throw new Error('unsupported export clause entry: ' + part.trim());
  });
}

function readImports(source) {
  const imports = [];
  const pattern = /^import\s*\{([^}]+)\}\s*from\s*['"]([^'"]+)['"];\s*$/gm;
  let match;
  while ((match = pattern.exec(source)) !== null) {
    imports.push({ specifier: match[2], entries: parseImportClause(match[1]) });
  }
  return imports;
}

function topoSort(moduleMap) {
  const ordered = [];
  const state = new Map();
  const visit = (name, stack) => {
    const mark = state.get(name) || 0;
    if (mark === 2) return;
    if (mark === 1) throw new Error('cyclic ESM import graph: ' + stack.concat(name).join(' -> '));
    state.set(name, 1);
    const moduleInfo = moduleMap.get(name);
    for (const item of moduleInfo.imports) {
      if (!item.specifier.startsWith('./')) continue;
      const dependency = item.specifier.slice(2);
      if (!moduleMap.has(dependency)) throw new Error('missing local ESM dependency ' + item.specifier + ' in ' + name);
      visit(dependency, stack.concat(name));
    }
    state.set(name, 2);
    ordered.push(name);
  };
  for (const name of moduleMap.keys()) visit(name, []);
  return ordered;
}

function transformModule(name, source, moduleVariables) {
  const imports = readImports(source);
  const exportEntries = [];
  let body = source;
  const importLines = [];
  for (const item of imports) {
    const parts = item.entries.map((entry) => entry.imported === entry.local
      ? entry.imported
      : entry.imported + ': ' + entry.local);
    if (item.specifier.startsWith('./')) {
      const dependency = item.specifier.slice(2);
      const variable = moduleVariables.get(dependency);
      importLines.push('const { ' + parts.join(', ') + ' } = ' + variable + ';');
    } else {
      if (!item.specifier.startsWith('node:')) throw new Error('unsupported external import ' + item.specifier + ' in ' + name);
      importLines.push('const { ' + parts.join(', ') + ' } = require(' + JSON.stringify(item.specifier) + ');');
    }
  }
  body = body.replace(/^import\s*\{[^}]+\}\s*from\s*['"][^'"]+['"];\s*\n?/gm, '');

  body = body.replace(/^export\s*\{([^}]+)\};\s*$/gm, (whole, clause) => {
    exportEntries.push(...parseExportClause(clause));
    return '';
  });
  body = body.replace(/^export\s+default\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*;\s*$/gm, (whole, local) => {
    exportEntries.push({ local, exported: 'default' });
    return '';
  });
  const declarationPattern = /^export\s+(?=(?:async\s+function|function|class|const)\b)(?:async\s+function|function|class|const)\s+([A-Za-z_$][A-Za-z0-9_$]*)/gm;
  let declarationMatch;
  while ((declarationMatch = declarationPattern.exec(body)) !== null) {
    exportEntries.push({ local: declarationMatch[1], exported: declarationMatch[1] });
  }
  body = body.replace(/^export\s+(?=(?:async\s+function|function|class|const)\b)/gm, '');

  if (/^import\s/m.test(body) || /^export\s/m.test(body)) {
    throw new Error('unsupported import or export syntax remains in ' + name);
  }
  const seenExports = new Set();
  for (const entry of exportEntries) {
    if (seenExports.has(entry.exported)) throw new Error('duplicate export ' + entry.exported + ' in ' + name);
    seenExports.add(entry.exported);
  }
  const exportLines = exportEntries.map((entry) => '__exports[' + JSON.stringify(entry.exported) + '] = ' + entry.local + ';');
  return [
    'const ' + moduleVariables.get(name) + ' = (() => {',
    ...importLines,
    body.trim(),
    'const __exports = Object.create(null);',
    ...exportLines,
    'return __exports;',
    '})();'
  ].join('\n');
}

const fileNames = (await readdir(sourceDirectory)).filter((name) => name.endsWith('.mjs')).sort();
if (!fileNames.includes('index.mjs')) throw new Error('src/index.mjs is missing');
const sources = new Map();
for (const name of fileNames) sources.set(name, await readFile(path.join(sourceDirectory, name), 'utf8'));
const moduleMap = new Map();
for (const [name, source] of sources.entries()) moduleMap.set(name, { name, source, imports: readImports(source) });
const ordered = topoSort(moduleMap);
const moduleVariables = new Map();
for (let index = 0; index < ordered.length; index += 1) moduleVariables.set(ordered[index], '__templatecageModule' + index);
const sections = [];
for (const name of ordered) {
  sections.push('/* src/' + name + ' */');
  sections.push(transformModule(name, sources.get(name), moduleVariables));
}
const indexVariable = moduleVariables.get('index.mjs');
const exportLines = PUBLIC_EXPORTS.map((name) => '  ' + name + ': ' + indexVariable + '[' + JSON.stringify(name) + '],');
const output = [
  "'use strict';",
  '',
  '/* Generated by scripts/build-cjs.mjs from src/*.mjs. Do not edit directly. */',
  '',
  sections.join('\n\n'),
  '',
  'module.exports = {',
  ...exportLines,
  '};',
  '',
  'module.exports.default = module.exports;',
  ''
].join('\n');

const outputPath = path.join(root, 'cjs', 'index.cjs');
if (check) {
  let current;
  try {
    current = await readFile(outputPath);
  } catch {
    console.error('cjs/index.cjs is missing or unreadable');
    process.exit(1);
  }
  if (!current.equals(Buffer.from(output, 'utf8'))) {
    console.error('cjs/index.cjs is stale; run node scripts/build-cjs.mjs');
    process.exit(1);
  }
  process.stdout.write('cjs/index.cjs is up to date\n');
} else {
  await mkdir(path.join(root, 'cjs'), { recursive: true });
  await writeFile(outputPath, output, 'utf8');
}

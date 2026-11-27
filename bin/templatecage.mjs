#!/usr/bin/env node
import fs from 'node:fs';
import { TextDecoder } from 'node:util';
import { TEMPLATECAGE_VERSION, TemplateCageError, auditTemplate, compileTemplate, extractTemplateVariables, renderTemplate } from '../src/index.mjs';
import { terminalSafe } from '../src/scan-utils.mjs';

const STDIN_LIMIT = 1048576;
const DATA_LIMIT = 1048576;

function writeOut(value) {
  process.stdout.write(terminalSafe(value));
}

function writeErr(value) {
  process.stderr.write(terminalSafe(value) + '\n');
}

function usage() {
  return [
    'templatecage ' + TEMPLATECAGE_VERSION,
    '',
    'Usage:',
    '  templatecage audit [template] [--policy strict|email|notification|audit] [--json]',
    '  templatecage render [template] [--data json|@file] [--policy strict|email|notification] [--json]',
    '  templatecage extract-vars [template] [--policy strict|email|notification] [--json]',
    '',
    'When template is omitted, exactly one terminal newline is removed from bounded standard input.',
    'Exit codes: 0 success or safe, 1 unsafe or processing failure, 2 usage error.'
  ].join('\n') + '\n';
}

function failUsage(message) {
  writeErr('usage error: ' + message);
  process.stderr.write(usage());
  process.exit(2);
}

function parseArgs(args) {
  const output = { positional: [], policy: undefined, data: undefined, json: false };
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === '--json') {
      output.json = true;
      continue;
    }
    if (arg === '--policy' || arg === '--data') {
      if (index + 1 >= args.length) failUsage(arg + ' requires a value');
      output[arg.slice(2)] = args[index + 1];
      index += 1;
      continue;
    }
    if (arg.startsWith('--policy=')) {
      output.policy = arg.slice('--policy='.length);
      continue;
    }
    if (arg.startsWith('--data=')) {
      output.data = arg.slice('--data='.length);
      continue;
    }
    if (arg.startsWith('--')) failUsage('unknown option ' + arg);
    output.positional.push(arg);
  }
  if (output.positional.length > 1) failUsage('too many positional arguments');
  return output;
}

function stripOneTerminalNewline(value) {
  if (!value.endsWith('\n')) return value;
  const withoutLf = value.slice(0, -1);
  if (withoutLf.endsWith('\r')) return withoutLf.slice(0, -1);
  return withoutLf;
}

function readBoundedStdin(limit) {
  if (process.stdin.isTTY) throw new Error('template input is empty and standard input is a terminal');
  const chunks = [];
  let total = 0;
  const scratch = Buffer.alloc(65536);
  for (;;) {
    const count = fs.readSync(0, scratch, 0, scratch.length, null);
    if (count === 0) break;
    total += count;
    if (total > limit) throw new Error('standard input exceeds the byte limit');
    chunks.push(Buffer.from(scratch.subarray(0, count)));
  }
  const bytes = Buffer.concat(chunks);
  const decoder = new TextDecoder('utf-8', { fatal: true });
  return stripOneTerminalNewline(decoder.decode(bytes));
}

function readTemplate(positional) {
  if (positional.length === 1) return positional[0];
  try {
    return readBoundedStdin(STDIN_LIMIT);
  } catch (error) {
    failUsage(error.message);
  }
}

function readData(value) {
  if (value === undefined) return Object.create(null);
  let text = value;
  if (value.startsWith('@')) {
    const file = value.slice(1);
    if (file.length === 0) failUsage('--data @ requires a file path');
    const stat = fs.statSync(file);
    if (!stat.isFile() || stat.size > DATA_LIMIT) failUsage('data file is missing, not a file, or too large');
    text = fs.readFileSync(file, 'utf8');
  }
  if (Buffer.byteLength(text, 'utf8') > DATA_LIMIT) failUsage('data JSON exceeds the byte limit');
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    failUsage('data is not valid JSON');
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) failUsage('data JSON must be an object');
  return parsed;
}

function jsonOut(value) {
  writeOut(JSON.stringify(value, null, 2) + '\n');
}

function findingLine(finding) {
  return '- [' + finding.severity + '] ' + finding.code + ' at ' + finding.offset + ': ' + finding.message;
}

function commandAudit(options) {
  const template = readTemplate(options.positional);
  const policy = options.policy || 'audit';
  let report;
  try {
    report = auditTemplate(template, policy);
  } catch (error) {
    if (error instanceof TemplateCageError) {
      writeErr(error.message);
      process.exit(1);
    }
    throw error;
  }
  if (options.json) jsonOut(report);
  else {
    writeOut('safe: ' + (report.safe ? 'yes' : 'no') + '\n');
    writeOut('policy: ' + report.policy + '\n');
    writeOut('tags: ' + report.tagCount + '\n');
    writeOut('findings: ' + report.findings.length + '\n');
    for (const finding of report.findings) writeOut(findingLine(finding) + '\n');
  }
  process.exit(report.safe ? 0 : 1);
}

function commandRender(options) {
  const template = readTemplate(options.positional);
  const policy = options.policy || 'strict';
  let data;
  try {
    data = readData(options.data);
  } catch (error) {
    failUsage(error.message);
  }
  try {
    const output = renderTemplate(template, data, policy);
    if (options.json) jsonOut({ output });
    else writeOut(output + '\n');
    process.exit(0);
  } catch (error) {
    if (error instanceof TemplateCageError) {
      if (options.json) jsonOut({ error: error.toJSON() });
      else writeErr(error.message);
      process.exit(1);
    }
    throw error;
  }
}

function commandVars(options) {
  const template = readTemplate(options.positional);
  const policy = options.policy || 'strict';
  try {
    const compiled = compileTemplate(template, policy);
    const variables = extractTemplateVariables(compiled);
    if (options.json) jsonOut({ variables });
    else {
      for (const variable of variables) writeOut(variable + '\n');
    }
    process.exit(0);
  } catch (error) {
    if (error instanceof TemplateCageError) {
      writeErr(error.message);
      process.exit(1);
    }
    throw error;
  }
}

function main() {
  const args = process.argv.slice(2);
  if (args.length === 1 && (args[0] === '--help' || args[0] === '-h')) {
    writeOut(usage());
    process.exit(0);
  }
  if (args.length === 1 && (args[0] === '--version' || args[0] === '-v')) {
    writeOut('templatecage ' + TEMPLATECAGE_VERSION + '\n');
    process.exit(0);
  }
  if (args.length === 0) failUsage('missing command');
  const command = args[0];
  if (command !== 'audit' && command !== 'render' && command !== 'extract-vars') failUsage('unknown command ' + command);
  const options = parseArgs(args.slice(1));
  const policies = command === 'audit' ? ['strict', 'email', 'notification', 'audit'] : ['strict', 'email', 'notification'];
  if (options.policy !== undefined && !policies.includes(options.policy)) failUsage('unknown or unsupported policy ' + options.policy);
  if (command === 'audit') commandAudit(options);
  else if (command === 'render') commandRender(options);
  else commandVars(options);
}

try {
  main();
} catch (error) {
  writeErr(error && error.message ? error.message : 'unexpected CLI failure');
  process.exit(1);
}

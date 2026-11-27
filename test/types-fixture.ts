import {
  CODE,
  TemplateCageError,
  auditTemplate,
  compileTemplate,
  createTemplatePolicy,
  extractTemplateVariables,
  getPolicy,
  isSafeTemplate,
  renderTemplate,
  validateTemplate
} from '../types/index.js';

const policy = createTemplatePolicy({ policy: 'strict', maxIterations: 10, allowedFilters: ['upper', 'default'] });
const report = auditTemplate('Hello {{ user.name }}', policy);
const safe: boolean = report.safe;
const firstOffset: number | undefined = report.findings[0]?.offset;
const validation = validateTemplate('Hello {{ name }}', 'strict');
const compiled = compileTemplate('Hello {{ name | upper }}', policy);
const output: string = renderTemplate(compiled, { name: 'world' });
const direct: string = renderTemplate('{{ name }}', { name: 'world' }, 'strict');
const variables: readonly string[] = extractTemplateVariables(compiled);
const preset = getPolicy('email');
const mode: 'html' | 'text' | 'json' = preset.mode;
const safeResult: boolean = isSafeTemplate('plain text', 'audit');
const error = new TemplateCageError(CODE.INVALID_INPUT, 'example', { key: 'value' }, 0);
const code = error.code;

void safe;
void firstOffset;
void validation;
void output;
void direct;
void variables;
void mode;
void safeResult;
void code;

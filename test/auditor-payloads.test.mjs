import test from 'node:test';
import { auditTemplate, isSafeTemplate, validateTemplate, CODE } from '../src/index.mjs';
import { assert, assertHasCode, expectTemplateError, hasCode } from './helpers.mjs';

const dangerousTerms = [
  ['constructor', CODE.PROTOTYPE_ACCESS],
  ['__proto__', CODE.PROTOTYPE_ACCESS],
  ['prototype', CODE.PROTOTYPE_ACCESS],
  ['globalThis', CODE.SANDBOX_ESCAPE],
  ['process', CODE.SANDBOX_ESCAPE],
  ['mainModule', CODE.SANDBOX_ESCAPE],
  ['require', CODE.CODE_EXECUTION],
  ['Function', CODE.CODE_EXECUTION],
  ['eval', CODE.CODE_EXECUTION],
  ['Reflect', CODE.SANDBOX_ESCAPE],
  ['Proxy', CODE.SANDBOX_ESCAPE],
  ['child_process', CODE.CODE_EXECUTION],
  ['fs', CODE.CODE_EXECUTION],
  ['Buffer', CODE.SANDBOX_ESCAPE],
  ['lookup', CODE.SANDBOX_ESCAPE],
  ['with', CODE.DANGEROUS_DIRECTIVE],
  ['__defineGetter__', CODE.PROTOTYPE_ACCESS],
  ['__lookupGetter__', CODE.PROTOTYPE_ACCESS],
  ['__defineSetter__', CODE.PROTOTYPE_ACCESS],
  ['__lookupSetter__', CODE.PROTOTYPE_ACCESS],
  ['cycler', CODE.SANDBOX_ESCAPE],
  ['joiner', CODE.SANDBOX_ESCAPE],
  ['namespace', CODE.SANDBOX_ESCAPE],
  ['lipsum', CODE.SANDBOX_ESCAPE],
  ['self', CODE.SANDBOX_ESCAPE],
  ['request', CODE.SANDBOX_ESCAPE],
  ['config', CODE.SANDBOX_ESCAPE],
  ['url_for', CODE.SANDBOX_ESCAPE],
  ['get_flashed_messages', CODE.SANDBOX_ESCAPE],
  ['__class__', CODE.PROTOTYPE_ACCESS],
  ['__mro__', CODE.PROTOTYPE_ACCESS],
  ['__base__', CODE.PROTOTYPE_ACCESS],
  ['__bases__', CODE.PROTOTYPE_ACCESS],
  ['__subclasses__', CODE.PROTOTYPE_ACCESS],
  ['__globals__', CODE.SANDBOX_ESCAPE],
  ['__builtins__', CODE.SANDBOX_ESCAPE],
  ['__import__', CODE.CODE_EXECUTION],
  ['__init__', CODE.PROTOTYPE_ACCESS],
  ['__dict__', CODE.PROTOTYPE_ACCESS],
  ['subprocess', CODE.CODE_EXECUTION],
  ['importlib', CODE.CODE_EXECUTION],
  ['pickle', CODE.CODE_EXECUTION],
  ['marshal', CODE.CODE_EXECUTION]
];

for (const [term, code] of dangerousTerms) {
  test('audit detects dangerous term in mustache ' + term, () => {
    const report = auditTemplate('{{ x.' + term + ' }}', 'audit');
    assert.equal(report.safe, false);
    assertHasCode(report, code);
  });
}

for (const [term, code] of dangerousTerms.slice(0, 30)) {
  test('audit detects dangerous term in jinja statement ' + term, () => {
    const report = auditTemplate('{% set value = x.' + term + ' %}', 'audit');
    assert.equal(report.safe, false);
    assertHasCode(report, code);
  });
}

const exploitChains = [
  ['node constructor chain', '{{ range.constructor.constructor("return process")() }}', CODE.PROTOTYPE_ACCESS],
  ['handlebars lookup chain', '{{ lookup this "constructor" }}', CODE.SANDBOX_ESCAPE],
  ['python mro chain', "{{ ''.__class__.__mro__[1].__subclasses__() }}", CODE.PROTOTYPE_ACCESS],
  ['python globals chain', "{{ x.__init__.__globals__ }}", CODE.SANDBOX_ESCAPE],
  ['flask config chain', '{{ config.__class__ }}', CODE.PROTOTYPE_ACCESS],
  ['os popen', '{{ os.popen("id") }}', CODE.CODE_EXECUTION],
  ['subprocess call', '{{ subprocess.check_output("id") }}', CODE.CODE_EXECUTION],
  ['dynamic import', '${import("node:fs")}', CODE.CODE_EXECUTION],
  ['require call', '${require("node:child_process")}', CODE.CODE_EXECUTION],
  ['process mainModule', '${process.mainModule.require("fs")}', CODE.SANDBOX_ESCAPE],
  ['flask request', '{{ request.args }}', CODE.SANDBOX_ESCAPE],
  ['url_for', '{{ url_for.__globals__ }}', CODE.SANDBOX_ESCAPE],
  ['get flashed messages', '{{ get_flashed_messages.__globals__ }}', CODE.SANDBOX_ESCAPE],
  ['attr call', "{{ attr('__class__') }}", CODE.SANDBOX_ESCAPE],
  ['attr filter', "{{ x|attr('__class__') }}", CODE.SANDBOX_ESCAPE]
];

for (const [name, payload, code] of exploitChains) {
  test('audit blocks exploit chain ' + name, () => {
    const report = auditTemplate(payload, 'audit');
    assert.equal(report.safe, false);
    assertHasCode(report, code);
  });
}

const obfuscatedPayloads = [
  "{{ obj['con' + 'structor'] }}",
  '{{ obj["con" + "structor"] }}',
  '{{ obj["\\x63onstructor"] }}',
  '{{ obj["\\u0063onstructor"] }}',
  '{{ obj["\\u{63}onstructor"] }}',
  '{{ obj["\\143onstructor"] }}',
  "{{ attr('__cla'~'ss__') }}",
  '{{ attr("__cla"~"ss__") }}',
  "{{ attr('__glob'~'als__') }}",
  '{{ obj["\\x5f\\x5fproto\\x5f\\x5f"] }}',
  '{{ obj["\\u005f\\u005fproto\\u005f\\u005f"] }}',
  '{% set x = "__pro" + "to__" %}',
  '<%= obj["\\x63onstructor"] %>',
  '${obj["\\x63onstructor"]}',
  '#{obj["\\x63onstructor"]}',
  '{{ obj["pro" + "totype"] }}',
  '{{ obj["sub" + "process"] }}',
  '{{ obj["child" + "_process"] }}',
  '{{ obj["main" + "Module"] }}',
  '{{ obj["global" + "This"] }}'
];

for (const [index, payload] of obfuscatedPayloads.entries()) {
  test('audit detects string obfuscation payload ' + index, () => {
    const report = auditTemplate(payload, 'audit');
    assert.equal(report.safe, false, payload);
    assertHasCode(report, CODE.OBFUSCATED_ACCESS);
  });
}

const directivePayloads = [
  ['include jinja', '{% include "x.html" %}', CODE.FILE_INCLUSION],
  ['extends jinja', '{% extends "base.html" %}', CODE.FILE_INCLUSION],
  ['import jinja', '{% import "x" as x %}', CODE.FILE_INCLUSION],
  ['from jinja', '{% from "x" import y %}', CODE.FILE_INCLUSION],
  ['embed twig', '{% embed "x" %}', CODE.FILE_INCLUSION],
  ['use twig', '{% use "x" %}', CODE.FILE_INCLUSION],
  ['render liquid', '{% render "x" %}', CODE.FILE_INCLUSION],
  ['include liquid inline', '{% liquid include "x" %}', CODE.DANGEROUS_DIRECTIVE],
  ['macro jinja', '{% macro x() %}{% endmacro %}', CODE.DANGEROUS_DIRECTIVE],
  ['set jinja', '{% set x = 1 %}', CODE.DANGEROUS_DIRECTIVE],
  ['call jinja', '{% call x() %}{% endcall %}', CODE.DANGEROUS_DIRECTIVE],
  ['raw jinja', '{% raw %}x{% endraw %}', CODE.RAW_HTML],
  ['assign liquid', '{% assign x = 1 %}', CODE.DANGEROUS_DIRECTIVE],
  ['capture liquid', '{% capture x %}x{% endcapture %}', CODE.DANGEROUS_DIRECTIVE],
  ['do twig', '{% do x %}', CODE.DANGEROUS_DIRECTIVE],
  ['filter twig', '{% filter upper %}x{% endfilter %}', CODE.DANGEROUS_DIRECTIVE],
  ['autoescape off', '{% autoescape false %}x{% endautoescape %}', CODE.RAW_HTML],
  ['mustache partial', '{{> partial }}', CODE.FILE_INCLUSION],
  ['mustache layout', '{{< layout }}', CODE.FILE_INCLUSION],
  ['mustache block', '{{$ title }}x{{/title}}', CODE.FILE_INCLUSION],
  ['go template', '{{ template "x" . }}', CODE.FILE_INCLUSION],
  ['go define', '{{ define "x" }}{{ end }}', CODE.DANGEROUS_DIRECTIVE],
  ['go block', '{{ block "x" . }}{{ end }}', CODE.DANGEROUS_DIRECTIVE]
];

for (const [name, payload, code] of directivePayloads) {
  test('audit blocks dangerous directive ' + name, () => {
    const report = auditTemplate(payload, 'audit');
    assert.equal(report.safe, false);
    assertHasCode(report, code);
  });
}

const rawPayloads = [
  '{{{x}}}',
  '{{{ x }}}',
  '{{&x}}',
  '{{& x }}',
  '{{ x | safe }}',
  '{{ x|safe }}',
  '{{ x | raw }}',
  '<%- x %>',
  '<%-x%>',
  '{% autoescape off %}x{% endautoescape %}',
  '{% raw %}{{ x }}{% endraw %}'
];

for (const [index, payload] of rawPayloads.entries()) {
  test('audit blocks raw html output payload ' + index, () => {
    const report = auditTemplate(payload, 'email');
    assert.equal(report.safe, false);
    assertHasCode(report, CODE.RAW_HTML);
  });
}

const evaluatedDialectPayloads = [
  ['ejs scriptlet', '<% const x = process.exit() %>'],
  ['ejs output', '<%= process.version %>'],
  ['ejs raw', '<%- process.version %>'],
  ['javascript interpolation', '${process.exit()}'],
  ['javascript constructor', '${x.constructor.constructor("return process")()}'],
  ['pug interpolation', '#{process.exit()}'],
  ['pug attribute interpolation', 'a(href="#{process.env}")'],
  ['pug unbuffered var', '- var x = process.exit()'],
  ['pug unbuffered const', '- const x = require("fs")'],
  ['pug unbuffered process', '- process.exit()']
];

for (const [name, payload] of evaluatedDialectPayloads) {
  test('audit blocks evaluated dialect ' + name, () => {
    const report = auditTemplate(payload, 'audit');
    assert.equal(report.safe, false);
    assert.equal(hasCode(report, CODE.CODE_EXECUTION) || hasCode(report, CODE.PUG_CODE) || hasCode(report, CODE.SANDBOX_ESCAPE), true);
  });
}

const probePayloads = [
  '{{7*7}}',
  '{{ 7 * 7 }}',
  '{{7*\'7\'}}',
  '{{ 1 + 1 }}',
  '{{ x / y }}',
  '{{ x % y }}',
  '{{ x == y }}',
  '{{ x > y }}',
  '{{ x ? y : z }}',
  '{{ x && y }}',
  '<%= 7*7 %>',
  '${7*7}',
  '#{7*7}',
  '{{ (7).__class__ }}',
  '{{ [].constructor }}'
];

for (const [index, payload] of probePayloads.entries()) {
  test('audit blocks executable expression probe ' + index, () => {
    const report = auditTemplate(payload, 'audit');
    assert.equal(report.safe, false);
    assert.equal(hasCode(report, CODE.TEMPLATE_INJECTION) || hasCode(report, CODE.PROTOTYPE_ACCESS) || hasCode(report, CODE.CODE_EXECUTION), true);
  });
}

const strictSafeTemplates = [
  'plain text',
  'Hello {{ name }}',
  'Hello {{ user.name }}',
  '{{ user.name | upper }}',
  '{{ user.name | lower | trim }}',
  '{{ user.nickname | default:\'Anonymous\' }}',
  '{{ user.bio | truncate:20 }}',
  '{{ user.url | escapeUrl }}',
  '{{ user.html | escapeHtml }}',
  '{{#if user.ok}}yes{{/if}}',
  '{{#if user.ok}}yes{{else}}no{{/if}}',
  '{{#unless user.hidden}}visible{{/unless}}',
  '{{#each items}}{{this}}{{/each}}',
  '{{#each users}}{{ @index }} {{ this.name }}{{/each}}',
  '{{! comment }}Hello {{ name }}',
  '{{ user.items.0 }}',
  '{{ user.deeply.nested.value }}',
  '<p>Hello {{ name }}</p>',
  'line one\nline two {{ name }}',
  '{{ name }}'
];

for (const [index, template] of strictSafeTemplates.entries()) {
  test('strict audit accepts safe data-only template ' + index, () => {
    const report = auditTemplate(template, 'strict');
    assert.equal(report.safe, true, codesText(report));
    assert.equal(isSafeTemplate(template, 'strict'), true);
    assert.equal(validateTemplate(template, 'strict').safe, true);
  });
}

function codesText(report) {
  return report.findings.map((finding) => finding.code).join(',');
}

const auditSafeTemplates = [
  'plain text',
  'Hello {{ user.name }}',
  '{{ user.name | upper }}',
  '{{ user.items.0 }}',
  '{{ . }}',
  '{{ this }}',
  '{% if user %}hello{% endif %}',
  '{% for item in items %}{{ item }}{% endfor %}',
  '{{#if user.ok}}yes{{/if}}',
  '{{#each items}}{{this}}{{/each}}'
];

for (const [index, template] of auditSafeTemplates.entries()) {
  test('audit preset accepts non executable template shape ' + index, () => {
    const report = auditTemplate(template, 'audit');
    assert.equal(report.safe, true, codesText(report));
  });
}

const malformedTemplates = [
  '{{ unclosed',
  '{% unclosed',
  '<% unclosed',
  '${ unclosed',
  '#{ unclosed',
  '{{{ unclosed',
  '{{/if}}',
  '{% endif %}',
  '{{#if x}}{{/each}}',
  '{{#each x}}',
  '{% for x in y %}',
  '{{#if a}}{{#if b}}{{/if}}'
];

for (const [index, template] of malformedTemplates.entries()) {
  test('audit rejects malformed or unbalanced template ' + index, () => {
    const report = auditTemplate(template, 'audit');
    assert.equal(report.safe, false);
    assert.equal(hasCode(report, CODE.UNCLOSED_TAG) || hasCode(report, CODE.UNBALANCED_TAG), true);
  });
}

for (const [index, template] of malformedTemplates.slice(0, 8).entries()) {
  test('validateTemplate throws for malformed template ' + index, () => {
    assert.throws(() => validateTemplate(template, 'audit'), (error) => {
      assert.equal(error.name, 'TemplateCageError');
      assert.equal(typeof error.code, 'string');
      assert.equal(typeof error.detail, 'object');
      return true;
    });
  });
}

test('validateTemplate throws typed error with offset detail', () => {
  expectTemplateError(() => validateTemplate('{{7*7}}', 'audit'), CODE.TEMPLATE_INJECTION);
});

test('audit detects constructor after nested object literal in javascript interpolation', () => {
  const report = auditTemplate('${({a:1}).constructor}', 'audit');
  assert.equal(report.safe, false);
  assertHasCode(report, CODE.PROTOTYPE_ACCESS);
});

test('audit detects constructor after nested hash literal in pug interpolation', () => {
  const report = auditTemplate('#{ {a:1}.constructor }', 'audit');
  assert.equal(report.safe, false);
  assertHasCode(report, CODE.PROTOTYPE_ACCESS);
});

test('audit treats balanced brace interpolation as unclosed when close is missing', () => {
  const report = auditTemplate('${({a:1}).constructor', 'audit');
  assert.equal(report.safe, false);
  assertHasCode(report, CODE.UNCLOSED_TAG);
});

test('audit accepts ordinary Jinja comment prose', () => {
  assert.equal(auditTemplate('{# comment with spaces #}', 'audit').safe, true);
});

test('audit scans dangerous content inside Jinja comments', () => {
  const report = auditTemplate('{# {{7*7}} constructor #}', 'audit');
  assert.equal(report.safe, false);
  assertHasCode(report, CODE.PROTOTYPE_ACCESS);
});

test('audit accepts bounded Go range and if control shapes', () => {
  assert.equal(auditTemplate('{{ range . }}{{ . }}{{ end }}', 'audit').safe, true);
  assert.equal(auditTemplate('{{ if . }}yes{{ end }}', 'audit').safe, true);
});

const dialectsExpectations = [
  ['{{x}}', 'mustache'],
  ['{{{x}}}', 'handlebars'],
  ['{% x %}', 'jinja-twig-liquid'],
  ['{# x #}', 'jinja-twig'],
  ['<% x %>', 'ejs'],
  ['${x}', 'javascript-template'],
  ['#{x}', 'pug-ruby']
];

for (const [template, dialect] of dialectsExpectations) {
  test('audit reports dialect family ' + dialect, () => {
    const report = auditTemplate(template, 'audit');
    assert.equal(report.dialects.includes(dialect), true);
  });
}

const whitespaceControlPayloads = [
  ['dash include', '{%- include "x.html" %}', CODE.FILE_INCLUSION],
  ['tilde include', '{%~ include "x.html" %}', CODE.FILE_INCLUSION],
  ['dash extends', '{%- extends "base.html" %}', CODE.FILE_INCLUSION],
  ['tilde set', '{%~ set x = 1 %}', CODE.DANGEROUS_DIRECTIVE]
];

for (const [name, payload, code] of whitespaceControlPayloads) {
  test('audit detects whitespace controlled directive ' + name, () => {
    const report = auditTemplate(payload, 'audit');
    assert.equal(report.safe, false);
    assertHasCode(report, code);
  });
}

const operatorProbePayloads = [
  ['numeric subtraction', '{{7-7}}'],
  ['bitwise xor', '{{7^7}}'],
  ['numeric bitwise or', '{{7|7}}'],
  ['bitwise not or whitespace ambiguity', '{{~7}}']
];

for (const [name, payload] of operatorProbePayloads) {
  test('audit blocks operator or whitespace ambiguity probe ' + name, () => {
    const report = auditTemplate(payload, 'audit');
    assert.equal(report.safe, false, codesText(report));
  });
}

const foreignDialectPayloads = [
  ['pug unescaped output', '!{process.env}', CODE.RAW_HTML],
  ['freemarker assign', '<#assign x = "constructor">', CODE.DANGEROUS_DIRECTIVE],
  ['freemarker include', '<#include "secret.txt">', CODE.FILE_INCLUSION],
  ['freemarker macro invocation', '<@macro />', CODE.CODE_EXECUTION],
  ['velocity set', '#set($x = $runtime.exec("id"))', CODE.DANGEROUS_DIRECTIVE],
  ['velocity parse', '#parse("secret.vm")', CODE.FILE_INCLUSION],
  ['smarty php', '{php}system("id");{/php}', CODE.CODE_EXECUTION],
  ['smarty variable', '{$smarty.template}', CODE.TEMPLATE_INJECTION],
  ['thymeleaf selection', '*{user.constructor}', CODE.PROTOTYPE_ACCESS],
  ['thymeleaf url', '@{javascript:alert(1)}', CODE.TEMPLATE_INJECTION],
  ['thymeleaf fragment', '~{fragment :: main}', CODE.FILE_INCLUSION],
  ['ognl expression', '%{1+1}', CODE.TEMPLATE_INJECTION]
];

for (const [name, payload, code] of foreignDialectPayloads) {
  test('audit blocks foreign dialect payload ' + name, () => {
    const report = auditTemplate(payload, 'audit');
    assert.equal(report.safe, false, codesText(report));
    assertHasCode(report, code);
  });
}

test('audit rejects zero width format characters in identifiers', () => {
  const payload = '{{ x.constr' + String.fromCharCode(0x200b) + 'uctor }}';
  const report = auditTemplate(payload, 'audit');
  assert.equal(report.safe, false);
  assertHasCode(report, CODE.CONTROL_CHARACTER);
});

test('audit rejects non BMP Unicode format characters', () => {
  const payload = '{{ x.constr' + String.fromCodePoint(0xe0001) + 'uctor }}';
  const report = auditTemplate(payload, 'audit');
  assert.equal(report.safe, false);
  assertHasCode(report, CODE.CONTROL_CHARACTER);
});

const unicodeEvasionPayloads = [
  ['fullwidth delimiters', '｛｛7*7｝｝'],
  ['fullwidth constructor', '{{ x.ｃｏｎｓｔｒｕｃｔｏｒ }}'],
  ['identifier unicode escape', '{{ x.constru\\u0063tor }}'],
  ['identifier hex escape', '{{ x.constru\\x63tor }}'],
  ['nested delimiter token split', '{{ x.constr{#x#}uctor }}']
];

for (const [name, payload] of unicodeEvasionPayloads) {
  test('audit detects Unicode or delimiter evasion ' + name, () => {
    const report = auditTemplate(payload, 'audit');
    assert.equal(report.safe, false, codesText(report));
    assertHasCode(report, CODE.OBFUSCATED_ACCESS);
  });
}

const runtimeEscapeTerms = [
  ['global', CODE.SANDBOX_ESCAPE],
  ['module', CODE.SANDBOX_ESCAPE],
  ['exports', CODE.SANDBOX_ESCAPE]
];

for (const [term, code] of runtimeEscapeTerms) {
  test('audit detects runtime escape term ' + term, () => {
    const report = auditTemplate('{{ x.' + term + ' }}', 'audit');
    assert.equal(report.safe, false);
    assertHasCode(report, code);
  });
}

test('audit blocks velocity foreach directive regression payload', () => {
  const report = auditTemplate('#foreach($x in $items)$x#end', 'audit');
  assert.equal(report.safe, false);
  assertHasCode(report, CODE.DANGEROUS_DIRECTIVE);
});

test('audit rejects zero width format characters in prototype identifiers', () => {
  const payload = '{{ x.__pr' + String.fromCharCode(0x200c) + 'oto__ }}';
  const report = auditTemplate(payload, 'audit');
  assert.equal(report.safe, false);
  assertHasCode(report, CODE.CONTROL_CHARACTER);
});

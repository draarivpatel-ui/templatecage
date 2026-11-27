import test from 'node:test';
import { CODE, compileTemplate, extractTemplateVariables, renderTemplate } from '../src/index.mjs';
import { assert, expectTemplateError } from './helpers.mjs';

const interpolationCases = [
  ['simple string', '{{ name }}', { name: 'Ada' }, 'Ada'],
  ['spaced tag', '{{   name   }}', { name: 'Ada' }, 'Ada'],
  ['nested path', '{{ user.name }}', { user: { name: 'Ada' } }, 'Ada'],
  ['deep path', '{{ a.b.c.d }}', { a: { b: { c: { d: 'x' } } } }, 'x'],
  ['array index', '{{ items.0 }}', { items: ['a', 'b'] }, 'a'],
  ['array second index', '{{ items.1 }}', { items: ['a', 'b'] }, 'b'],
  ['array length', '{{ items.length }}', { items: ['a', 'b'] }, '2'],
  ['missing value', '{{ missing }}', {}, ''],
  ['missing nested value', '{{ user.missing }}', { user: {} }, ''],
  ['missing root in path', '{{ missing.value }}', {}, ''],
  ['null value', '{{ value }}', { value: null }, ''],
  ['undefined value', '{{ value }}', { value: undefined }, ''],
  ['false value', '{{ value }}', { value: false }, 'false'],
  ['true value', '{{ value }}', { value: true }, 'true'],
  ['zero value', '{{ value }}', { value: 0 }, '0'],
  ['negative value', '{{ value }}', { value: -2 }, '-2'],
  ['decimal value', '{{ value }}', { value: 1.5 }, '1.5'],
  ['bigint value', '{{ value }}', { value: 7n }, '7'],
  ['unicode value', '{{ value }}', { value: 'snowman' }, 'snowman'],
  ['underscore key', '{{ user_name }}', { user_name: 'x' }, 'x'],
  ['dollar key', '{{ user$name }}', { user$name: 'x' }, 'x'],
  ['hyphen key', '{{ user-name }}', { 'user-name': 'x' }, 'x'],
  ['static text unchanged', '<b>{{ name }}</b>', { name: 'x' }, '<b>x</b>'],
  ['two interpolations', '{{ a }}-{{ b }}', { a: 'x', b: 'y' }, 'x-y'],
  ['adjacent interpolations', '{{ a }}{{ b }}', { a: 'x', b: 'y' }, 'xy'],
  ['comment removed', 'a{{! comment }}b', {}, 'ab'],
  ['comment with markup removed', 'a{{! <b>x</b> }}b', {}, 'ab']
];

for (const [name, template, data, expected] of interpolationCases) {
  test('render interpolation ' + name, () => {
    assert.equal(renderTemplate(template, data), expected);
  });
}

const htmlEscapeCases = [
  ['&', '&amp;'],
  ['<', '&lt;'],
  ['>', '&gt;'],
  ['"', '&quot;'],
  ["'", '&#39;'],
  ['<a href="x">&\'', '&lt;a href=&quot;x&quot;&gt;&amp;&#39;']
];

for (const [input, expected] of htmlEscapeCases) {
  test('html mode escapes character ' + input, () => {
    assert.equal(renderTemplate('{{ value }}', { value: input }), expected);
  });
}

test('current root object interpolation is rejected instead of coerced', () => {
  expectTemplateError(() => renderTemplate('{{ this }}', { name: 'x' }), CODE.UNSAFE_VALUE);
});

test('html mode does not escape static template markup', () => {
  assert.equal(renderTemplate('<b>{{ value }}</b>', { value: 'x' }), '<b>x</b>');
});

test('html mode strips dangerous interpolation controls before escaping', () => {
  const input = 'a' + String.fromCharCode(0x202e) + String.fromCharCode(1) + 'b';
  assert.equal(renderTemplate('{{ value }}', { value: input }), 'ab');
});

const filterCases = [
  ['upper', '{{ value | upper }}', { value: 'aBc' }, 'ABC'],
  ['lower', '{{ value | lower }}', { value: 'aBc' }, 'abc'],
  ['trim', '{{ value | trim }}', { value: '  x  ' }, 'x'],
  ['filter chain', '{{ value | trim | upper }}', { value: '  ab  ' }, 'AB'],
  ['default string', '{{ value | default:\'fallback\' }}', {}, 'fallback'],
  ['default double quoted', '{{ value | default:"fallback" }}', {}, 'fallback'],
  ['default number', '{{ value | default:42 }}', {}, '42'],
  ['default boolean', '{{ value | default:true }}', {}, 'true'],
  ['default null', '{{ value | default:null }}', {}, ''],
  ['default does not replace zero', '{{ value | default:2 }}', { value: 0 }, '0'],
  ['default does not replace false', '{{ value | default:2 }}', { value: false }, 'false'],
  ['default replaces empty string', '{{ value | default:\'x\' }}', { value: '' }, 'x'],
  ['default escaped string', '{{ value | default:\'it\\\'s\' }}', {}, 'it&#39;s'],
  ['truncate ascii', '{{ value | truncate:3 }}', { value: 'abcdef' }, 'abc'],
  ['truncate zero', '{{ value | truncate:0 }}', { value: 'abcdef' }, ''],
  ['truncate unicode', '{{ value | truncate:2 }}', { value: 'a☃b' }, 'a☃'],
  ['truncate shorter input', '{{ value | truncate:9 }}', { value: 'abc' }, 'abc'],
  ['escapeHtml explicit', '{{ value | escapeHtml }}', { value: '<x>' }, '&lt;x&gt;'],
  ['escapeHtml not double escaped', '{{ value | escapeHtml }}', { value: '&' }, '&amp;'],
  ['escapeUrl', '{{ value | escapeUrl }}', { value: 'a b&x' }, 'a%20b%26x'],
  ['escapeUrl unicode', '{{ value | escapeUrl }}', { value: '☃' }, '%E2%98%83'],
  ['upper then default order', '{{ value | upper | default:\'x\' }}', { value: 'ab' }, 'AB'],
  ['default then upper order', '{{ value | default:\'x\' | upper }}', {}, 'X']
];

for (const [name, template, data, expected] of filterCases) {
  test('render filter ' + name, () => {
    assert.equal(renderTemplate(template, data), expected);
  });
}

const truthyValues = [
  ['true', true],
  ['nonempty string', 'x'],
  ['number one', 1],
  ['negative number', -1],
  ['nonempty array', [1]],
  ['plain object', {}],
  ['bigint', 1n]
];

for (const [name, value] of truthyValues) {
  test('if renders for truthy ' + name, () => {
    assert.equal(renderTemplate('{{#if value}}yes{{else}}no{{/if}}', { value }), 'yes');
  });
  test('unless suppresses for truthy ' + name, () => {
    assert.equal(renderTemplate('{{#unless value}}hidden{{else}}shown{{/unless}}', { value }), 'shown');
  });
}

const falsyValues = [
  ['false', false],
  ['empty string', ''],
  ['zero', 0],
  ['null', null],
  ['undefined', undefined],
  ['empty array', []]
];

for (const [name, value] of falsyValues) {
  test('if else renders for falsy ' + name, () => {
    assert.equal(renderTemplate('{{#if value}}yes{{else}}no{{/if}}', { value }), 'no');
  });
  test('unless renders for falsy ' + name, () => {
    assert.equal(renderTemplate('{{#unless value}}hidden{{else}}shown{{/unless}}', { value }), 'hidden');
  });
}

test('missing conditional path is falsy', () => {
  assert.equal(renderTemplate('{{#if missing}}yes{{else}}no{{/if}}', {}), 'no');
});

test('nested conditionals render', () => {
  const template = '{{#if a}}{{#if b}}both{{else}}a only{{/if}}{{else}}none{{/if}}';
  assert.equal(renderTemplate(template, { a: true, b: true }), 'both');
  assert.equal(renderTemplate(template, { a: true, b: false }), 'a only');
  assert.equal(renderTemplate(template, { a: false, b: true }), 'none');
});

const loopCases = [
  ['primitive items', '{{#each items}}{{this}}{{/each}}', { items: ['a', 'b'] }, 'ab'],
  ['object properties', '{{#each users}}{{this.name}};{{/each}}', { users: [{ name: 'a' }, { name: 'b' }] }, 'a;b;'],
  ['current dot', '{{#each items}}{{ . }}{{/each}}', { items: [1, 2] }, '12'],
  ['index metadata', '{{#each items}}{{ @index }}{{/each}}', { items: ['a', 'b'] }, '01'],
  ['first metadata', '{{#each items}}{{ @first }}{{/each}}', { items: ['a', 'b'] }, 'truefalse'],
  ['last metadata', '{{#each items}}{{ @last }}{{/each}}', { items: ['a', 'b'] }, 'falsetrue'],
  ['length metadata', '{{#each items}}{{ @length }}{{/each}}', { items: ['a', 'b'] }, '22'],
  ['outer fallback', '{{#each users}}{{ suffix }}{{/each}}', { users: [{}], suffix: 'x' }, 'x'],
  ['inner shadows outer', '{{#each users}}{{ name }}{{/each}}', { users: [{ name: 'inner' }], name: 'outer' }, 'inner'],
  ['nested arrays', '{{#each rows}}{{#each this}}{{this}}{{/each}};{{/each}}', { rows: [['a', 'b'], ['c']] }, 'ab;c;'],
  ['nested object arrays', '{{#each rows}}{{#each this.cells}}{{this}}{{/each}}{{/each}}', { rows: [{ cells: [1, 2] }] }, '12'],
  ['missing loop empty', '{{#each missing}}x{{/each}}', {}, ''],
  ['null loop empty', '{{#each items}}x{{/each}}', { items: null }, ''],
  ['object loop empty', '{{#each items}}x{{/each}}', { items: { a: 1 } }, ''],
  ['string loop empty', '{{#each items}}x{{/each}}', { items: 'abc' }, ''],
  ['loop filter', '{{#each items}}{{this | upper}}{{/each}}', { items: ['a', 'b'] }, 'AB'],
  ['loop html escapes', '{{#each items}}{{this}}{{/each}}', { items: ['<', '&'] }, '&lt;&amp;'],
  ['loop item own undefined shadows fallback', '{{#each users}}{{name}}{{/each}}', { users: [{ name: undefined }], name: 'outer' }, '']
];

for (const [name, template, data, expected] of loopCases) {
  test('render loop ' + name, () => {
    assert.equal(renderTemplate(template, data), expected);
  });
}

test('loop iteration count is global across nested loops', () => {
  const template = '{{#each rows}}{{#each rows}}x{{/each}}{{/each}}';
  expectTemplateError(() => renderTemplate(template, { rows: [1, 2, 3] }, { maxIterations: 8, maxLoopDepth: 2 }), CODE.ITERATION_LIMIT);
});

test('loop maxIterations exact boundary passes', () => {
  assert.equal(renderTemplate('{{#each items}}x{{/each}}', { items: [1, 2, 3] }, { maxIterations: 3 }), 'xxx');
});

test('loop maxIterations plus one fails', () => {
  expectTemplateError(() => renderTemplate('{{#each items}}x{{/each}}', { items: [1, 2, 3] }, { maxIterations: 2 }), CODE.ITERATION_LIMIT);
});

test('output byte cap exact boundary passes', () => {
  assert.equal(renderTemplate('{{#each items}}x{{/each}}', { items: [1, 2, 3] }, { maxOutputBytes: 3 }), 'xxx');
});

test('output byte cap plus one fails', () => {
  expectTemplateError(() => renderTemplate('{{#each items}}x{{/each}}', { items: [1, 2, 3] }, { maxOutputBytes: 2 }), CODE.OUTPUT_LIMIT);
});

test('output byte cap counts UTF-8 bytes', () => {
  expectTemplateError(() => renderTemplate('{{ value }}', { value: '☃' }, { maxOutputBytes: 2 }), CODE.OUTPUT_LIMIT);
  assert.equal(renderTemplate('{{ value }}', { value: '☃' }, { maxOutputBytes: 3 }), '☃');
});

test('text mode leaves ordinary text unescaped', () => {
  assert.equal(renderTemplate('{{ value }}', { value: '<x>&' }, { mode: 'text' }), '<x>&');
});

test('text mode strips dangerous interpolation characters', () => {
  const value = 'a' + String.fromCharCode(0x1b) + String.fromCharCode(0x202e) + 'b';
  assert.equal(renderTemplate('{{ value }}', { value }, { mode: 'text' }), 'ab');
});

const jsonCases = [
  ['string', 'a"b', '"a\\"b"'],
  ['newline string', 'a\nb', '"a\\nb"'],
  ['true', true, 'true'],
  ['false', false, 'false'],
  ['zero', 0, '0'],
  ['decimal', 1.5, '1.5'],
  ['null', null, 'null'],
  ['undefined', undefined, 'null']
];

for (const [name, value, expected] of jsonCases) {
  test('json mode renders primitive ' + name, () => {
    assert.equal(renderTemplate('"value": {{ value }}', { value }, { mode: 'json' }), '"value": ' + expected);
  });
}

test('json mode renders nonfinite number as null', () => {
  assert.equal(renderTemplate('{{ value }}', { value: Number.POSITIVE_INFINITY }, { mode: 'json' }), 'null');
});

test('json mode rejects bigint', () => {
  expectTemplateError(() => renderTemplate('{{ value }}', { value: 1n }, { mode: 'json' }), CODE.UNSAFE_VALUE);
});

test('object interpolation is rejected instead of coerced', () => {
  const value = { toString() { return 'bad'; } };
  expectTemplateError(() => renderTemplate('{{ value }}', { value }), CODE.UNSAFE_VALUE);
});

test('array interpolation is rejected instead of joined', () => {
  expectTemplateError(() => renderTemplate('{{ value }}', { value: [1, 2] }), CODE.UNSAFE_VALUE);
});

test('symbol interpolation is rejected', () => {
  expectTemplateError(() => renderTemplate('{{ value }}', { value: Symbol('x') }), CODE.UNSAFE_VALUE);
});

const compileErrorCases = [
  ['foreign statement', '{% if x %}x{% endif %}', CODE.UNSUPPORTED_TAG],
  ['foreign comment', '{# x #}', CODE.UNSUPPORTED_TAG],
  ['foreign ejs', '<%= x %>', CODE.UNSUPPORTED_TAG],
  ['foreign javascript', '${x}', CODE.UNSUPPORTED_TAG],
  ['foreign pug', '#{x}', CODE.UNSUPPORTED_TAG],
  ['triple raw', '{{{x}}}', CODE.RAW_HTML],
  ['ampersand raw', '{{&x}}', CODE.RAW_HTML],
  ['partial', '{{> x}}', CODE.FILE_INCLUSION],
  ['layout', '{{< x}}', CODE.FILE_INCLUSION],
  ['unclosed', '{{ x', CODE.UNCLOSED_TAG],
  ['empty tag', '{{}}', CODE.INVALID_TEMPLATE],
  ['whitespace tag', '{{   }}', CODE.INVALID_TEMPLATE],
  ['unknown section', '{{#with x}}x{{/with}}', CODE.UNSUPPORTED_TAG],
  ['mismatched close', '{{#if x}}x{{/each}}', CODE.UNBALANCED_TAG],
  ['close without open', '{{/if}}', CODE.UNBALANCED_TAG],
  ['unclosed section', '{{#if x}}x', CODE.UNBALANCED_TAG],
  ['else in loop', '{{#each x}}{{else}}{{/each}}', CODE.UNBALANCED_TAG],
  ['double else', '{{#if x}}a{{else}}b{{else}}c{{/if}}', CODE.UNBALANCED_TAG],
  ['operator expression', '{{7*7}}', CODE.UNSAFE_EXPRESSION],
  ['bracket expression', '{{ x["y"] }}', CODE.UNSAFE_EXPRESSION],
  ['function expression', '{{ x() }}', CODE.UNSAFE_EXPRESSION],
  ['unknown filter', '{{ x | system }}', CODE.UNSAFE_FILTER],
  ['missing truncate argument', '{{ x | truncate }}', CODE.UNSAFE_EXPRESSION],
  ['argument on upper', '{{ x | upper:1 }}', CODE.UNSAFE_EXPRESSION],
  ['malformed filter name', '{{ x | bad-name }}', CODE.UNSAFE_EXPRESSION],
  ['bad path character', '{{ x/y }}', CODE.UNSAFE_EXPRESSION],
  ['dunder path', '{{ x.__class__ }}', CODE.PROTOTYPE_ACCESS]
];

for (const [name, template, code] of compileErrorCases) {
  test('compile rejects ' + name, () => {
    expectTemplateError(() => compileTemplate(template), code);
  });
}

test('compile maxTags exact boundary passes', () => {
  assert.equal(renderTemplate('{{a}}{{b}}', { a: 'x', b: 'y' }, { maxTags: 2 }), 'xy');
});

test('compile maxTags plus one fails', () => {
  expectTemplateError(() => compileTemplate('{{a}}{{b}}{{c}}', { maxTags: 2 }), CODE.TOO_MANY_TAGS);
});

test('compile maxExpressionLength fails', () => {
  expectTemplateError(() => compileTemplate('{{ verylongname }}', { maxExpressionLength: 5 }), CODE.EXPRESSION_TOO_LONG);
});

test('compile maxBytes counts UTF-8 bytes', () => {
  expectTemplateError(() => compileTemplate('☃☃', { maxBytes: 5 }), CODE.INPUT_TOO_LONG);
});

test('compile maxNestingDepth fails', () => {
  expectTemplateError(() => compileTemplate('{{#if a}}{{#if b}}x{{/if}}{{/if}}', { maxNestingDepth: 1 }), CODE.NESTING_TOO_DEEP);
});

test('compile maxLoopDepth fails', () => {
  expectTemplateError(() => compileTemplate('{{#each a}}{{#each b}}x{{/each}}{{/each}}', { maxLoopDepth: 1 }), CODE.LOOP_TOO_DEEP);
});

test('compile rejects NUL input', () => {
  expectTemplateError(() => compileTemplate('a' + String.fromCharCode(0) + 'b'), CODE.CONTROL_CHARACTER);
});

test('compile rejects bidi input', () => {
  expectTemplateError(() => compileTemplate('a' + String.fromCharCode(0x202e) + 'b'), CODE.BIDI_CONTROL);
});

test('compile rejects unpaired surrogate input', () => {
  expectTemplateError(() => compileTemplate('a' + String.fromCharCode(0xd800) + 'b'), CODE.UNPAIRED_SURROGATE);
});

test('compile rejects non string input', () => {
  expectTemplateError(() => compileTemplate(null), CODE.INVALID_INPUT);
});

test('render rejects array root data', () => {
  expectTemplateError(() => renderTemplate('{{x}}', []), CODE.INVALID_DATA);
});

test('render rejects null root data', () => {
  expectTemplateError(() => renderTemplate('{{x}}', null), CODE.INVALID_DATA);
});

const variableTemplates = [
  ['{{name}}', ['name']],
  ['{{ user.name | upper }}', ['user.name']],
  ['{{#if user.ok}}{{user.name}}{{/if}}', ['user.name', 'user.ok']],
  ['{{#each users}}{{this.name}}{{ @index }}{{/each}}', ['@index', 'this.name', 'users']],
  ['{{! comment }}{{b}}{{a}}', ['a', 'b']]
];

for (const [template, expected] of variableTemplates) {
  test('extract variables ' + template, () => {
    assert.deepEqual(extractTemplateVariables(template), expected);
  });
}

test('compiled template is frozen', () => {
  const compiled = compileTemplate('Hello {{name}}');
  assert.equal(Object.isFrozen(compiled), true);
  assert.equal(Object.isFrozen(compiled.instructions), true);
  assert.equal(Object.isFrozen(compiled.variables), true);
  assert.throws(() => {
    compiled.variables.push('x');
  }, TypeError);
});

test('compiled template can render repeatedly', () => {
  const compiled = compileTemplate('Hello {{name}}');
  assert.equal(renderTemplate(compiled, { name: 'a' }), 'Hello a');
  assert.equal(renderTemplate(compiled, { name: 'b' }), 'Hello b');
});

test('render does not mutate or freeze caller data', () => {
  const data = { user: { name: 'a' }, items: [1] };
  renderTemplate('{{user.name}}{{#each items}}{{this}}{{/each}}', data);
  assert.equal(Object.isFrozen(data), false);
  assert.equal(Object.isFrozen(data.user), false);
  assert.equal(Object.isFrozen(data.items), false);
  assert.equal(data.user.name, 'a');
});

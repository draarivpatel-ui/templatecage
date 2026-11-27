# templatecage

Zero-dependency Server-Side Template Injection auditing and safe sandboxed data-only template rendering for Node.js.

`templatecage` is a deterministic offline security library. It does not read files, open sockets, resolve names, execute template code, use `eval`, or use the `Function` constructor. It has two layers:

1. A conservative multi-dialect SSTI auditor for untrusted template text.
2. A small safe renderer for applications that need bounded interpolation, conditionals, and loops without exposing JavaScript execution.

The renderer is designed for email builders, webhook payload templates, notification systems, PDF and HTML generators, and AI prompt assembly where the data shape is controlled but template text or individual values may be hostile.

## Install

```sh
npm install templatecage
```

Requires Node.js 18 or newer. There are no runtime dependencies and no development dependencies.

## Quick start

```js
import { auditTemplate, compileTemplate, renderTemplate } from 'templatecage';

const report = auditTemplate('{{ user.name }}', 'audit');
console.log(report.safe); // true for a simple data lookup

const attack = auditTemplate("{{ ''.__class__.__mro__ }}", 'audit');
console.log(attack.safe); // false
console.log(attack.findings[0].code); // TEMPLATECAGE_PROTOTYPE_ACCESS

const compiled = compileTemplate('Hello {{ user.name | upper }}!');
console.log(renderTemplate(compiled, {
  user: { name: '<Ada>' }
}));
// Hello &lt;ADA&gt;!
```

CommonJS works too.

```js
const { renderTemplate } = require('templatecage');
console.log(renderTemplate('Hello {{ name }}', { name: '<world>' }));
```

## SSTI auditor

`auditTemplate(template, options)` scans template source iteratively. It recognizes these delimiter families:

| Delimiter family | Examples |
| --- | --- |
| Mustache, Handlebars, Jinja, Twig, Liquid, Nunjucks, Go | `{{ value }}`, `{{{ raw }}}` |
| Jinja, Twig, Liquid, Nunjucks statements and comments | `{% include "x" %}`, `{# comment #}` |
| EJS | `<%= value %>`, `<%- raw %>`, `<% code %>` |
| JavaScript template interpolation | `${ process.env }` |
| Pug, Jade, and Ruby style interpolation | `#{ value }`, `!{ raw }` |
| FreeMarker | `<#assign x = 1>`, `<#include "x">`, `<@macro />` |
| Velocity | `#set($x = 1)`, `#parse("x")` |
| Thymeleaf and OGNL | `*{ value }`, `@{/x}`, `~{fragment}`, `%{ expr }` |
| Smarty | `{php}...{/php}`, `{include ...}`, `{$value}` |

The scanner detects:

- JavaScript and Node escape chains involving `constructor`, `prototype`, `__proto__`, `globalThis`, `process`, `mainModule`, `require`, dynamic `import`, `Function`, `eval`, `Reflect`, `Proxy`, `child_process`, `fs`, and `Buffer`
- Handlebars escape primitives such as `lookup`, dangerous `with` usage, and prototype getter or setter members
- Python and Jinja object graph escapes involving `__class__`, `__mro__`, `__base__`, `__bases__`, `__subclasses__`, `__globals__`, `__builtins__`, and `__import__`
- Flask and framework globals such as `request`, `config`, `url_for`, `get_flashed_messages`, `cycler`, `joiner`, `namespace`, `lipsum`, and `self`
- Jinja `attr(...)` and `|attr` indirection
- process execution modules and primitives such as `subprocess` and `os.popen`
- string concatenation, identifier escapes, nested delimiter splitting, compatibility Unicode normalization, and hexadecimal or Unicode escape obfuscation such as `['con' + 'structor']`, `"\x63onstructor"`, `"\u0063onstructor"`, and `attr('__cla'~'ss__')`
- file inclusion, template inheritance, imports, macros, raw blocks, assignments, and recursion-prone partials
- raw HTML output through triple mustache, `{{& value }}`, `<%- value %>`, `|safe`, and disabled autoescaping
- arithmetic and operator-only probes such as `{{7*7}}`, including whitespace-control forms that can hide directive structure
- unclosed delimiters, excessive tag counts, excessive expression lengths, deep nesting, nested loops, control characters, NUL bytes, bidi controls, invisible Unicode format characters, Unicode line separators, and unpaired surrogates

The audit layer is deliberately conservative because one template string can be interpreted by more than one downstream engine. A simple data lookup in one dialect can be an executable expression in another. Use the safe renderer when you need a guaranteed data-only interpretation instead of merely auditing text for a known engine.

```js
import { auditTemplate, validateTemplate } from 'templatecage';

const report = auditTemplate(template, 'audit');
if (!report.safe) {
  console.log(report.findings);
}

validateTemplate(template, 'strict'); // throws TemplateCageError on the first blocking finding
```

`isSafeTemplate(template, options)` is the boolean convenience form. `validateTemplate` returns the frozen audit report when input is safe and throws a typed `TemplateCageError` otherwise.

## Safe renderer

`compileTemplate` and `renderTemplate` implement a strict Mustache-inspired subset:

```text
{{ user.name }}
{{ user.name | upper | escapeHtml }}
{{ user.nickname | default:'Anonymous' }}
{{ user.bio | truncate:80 }}
{{#if user.active}}active{{else}}inactive{{/if}}
{{#unless user.hidden}}visible{{/unless}}
{{#each users}}{{ @index }} {{ this.name }}{{/each}}
```

Whitespace is flexible. Loop metadata paths are `@index`, `@first`, `@last`, and `@length`. `this` and `.` refer to the innermost loop value.

The renderer supports only these allowlisted filters:

| Filter | Behavior |
| --- | --- |
| `upper` | Unicode uppercase conversion for a primitive string value |
| `lower` | Unicode lowercase conversion for a primitive string value |
| `trim` | remove leading and trailing whitespace |
| `default:<literal>` | use a quoted string, number, boolean, or null literal when the value is missing, null, or an empty string |
| `truncate:<length>` | truncate by Unicode code points to a bounded integer length |
| `escapeHtml` | explicitly HTML escape once and suppress duplicate automatic escaping |
| `escapeUrl` | apply `encodeURIComponent` to a primitive string value |

There are no method calls, helper calls, arbitrary filters, bracket lookups, arithmetic operators, partials, includes, template inheritance, raw output tags, or dynamic code paths.

### Prototype and data isolation

Property lookup is own-property and enumerable-data only. The renderer never intentionally walks the prototype chain. Traversal is limited to plain objects, null-prototype objects, and arrays; class instances, dates, and other non-plain objects are opaque data containers rather than property sources. Paths cannot name `__proto__`, `constructor`, `prototype`, `toString`, `valueOf`, object getter or setter members, Python dunder members, Node or runtime escape objects such as `process`, `require`, `module`, `exports`, `Function`, or `eval`, or other double-underscore object members.

Values are read through own property descriptors. Getter properties are rejected without invocation. Function values are rejected without invocation. Proxy objects are rejected before property access where Node can identify them. Only primitive strings, finite numbers, booleans, and bigints render in HTML and text modes. JSON mode renders strings, finite numbers, booleans, and null as JSON values. Objects are never coerced through user-controlled `toString` or `valueOf` methods.

Inherited properties and prototype pollution do not become visible to templates:

```js
Object.prototype.polluted = 'bad';
renderTemplate('{{ user.polluted }}', { user: {} }); // empty string
```

### Automatic output encoding

Policy modes are context aware:

- `html` escapes `&`, `<`, `>`, double quote, single quote, and backtick in interpolated values.
- `text` removes dangerous control, bidi, Unicode separator, and surrogate characters from interpolated values.
- `json` serializes strings, finite numbers, booleans, and null as JSON values, so a template can write `"message": {{ message }}`.

Static template text is not rewritten. Put static markup in the template intentionally and rely on automatic escaping for untrusted interpolation.

### Resource bounds

Compilation and rendering enforce independent bounds:

- `maxBytes` for UTF-8 template input
- `maxTags` for delimited template tags
- `maxExpressionLength` for one tag body
- `maxNestingDepth` for all nested sections
- `maxLoopDepth` for nested loops
- `maxIterations` for total loop iterations across a render
- `maxOutputBytes` for rendered UTF-8 output
- `maxFindings` for audit reports

The iteration cap is global, not per loop. Nested loops cannot multiply work or output without reaching the same render budget. `maxFindings: 0` fails closed.

## Policies and presets

```js
import { createTemplatePolicy, getPolicy } from 'templatecage';

const strict = getPolicy('strict');
const custom = createTemplatePolicy({
  policy: 'strict',
  maxIterations: 50,
  maxOutputBytes: 16384
});
```

Presets:

| Preset | Intended use |
| --- | --- |
| `strict` | data-only interpolation plus bounded conditionals and loops |
| `email` | HTML email and HTML document rendering with larger bounded inputs |
| `notification` | plain text bounded interpolation with loops disabled |
| `audit` | broad multi-dialect SSTI scanning without data-only enforcement |

Policy objects are deeply frozen. Audit reports, findings, compiled templates, and variable lists are frozen or freshly generated container objects. Caller-owned data objects are never frozen or mutated.

## Compiled template integrity

`compileTemplate` returns an immutable compiled object tracked in an internal `WeakSet`. `renderTemplate` accepts either a template string or one of these compiled objects. A forged object with copied properties is rejected with `TEMPLATECAGE_TEMPLATE_INTEGRITY`.

```js
const compiled = compileTemplate('Hello {{ name }}');
renderTemplate(compiled, { name: 'Ada' });
renderTemplate({ kind: 'templatecage-compiled-template' }, {}); // throws
```

## CLI

```sh
templatecage audit template.txt --policy audit --json
templatecage render template.txt --data '{"user":{"name":"Ada"}}'
templatecage extract-vars template.txt --json
```

The first positional argument is the template itself. When omitted, the CLI reads standard input with a strict UTF-8 decoder and a one MiB cap. Exactly one terminal LF or CRLF is removed. Other whitespace is preserved. Terminal output neutralizes ANSI control bytes, C0 and C1 controls, bidi controls, invisible format characters, and Unicode line separators.

Exit code `0` means success or safe. Exit code `1` means unsafe input or a processing failure. Exit code `2` means CLI usage error.

## API summary

- `auditTemplate(template, options)`
- `isSafeTemplate(template, options)`
- `validateTemplate(template, options)`
- `compileTemplate(template, options)`
- `renderTemplate(templateOrCompiled, data, options)`
- `extractTemplateVariables(templateOrCompiled, options)`
- `createTemplatePolicy(options)`
- `getPolicy(name)`

All API errors are typed `TemplateCageError` instances with stable `TEMPLATECAGE_*` codes, a frozen `detail` object, and an optional numeric `offset`. TypeScript declarations are included.

## Security boundary

The auditor is a detection and policy layer. It is intentionally conservative and can reject constructs that are valid in a specific trusted template engine. It does not prove that an arbitrary third-party engine sandbox is correct. Treat positive audit results as a reason to reject or quarantine the template.

The renderer is the positive enforcement boundary. It does not evaluate JavaScript or template-engine code and is suitable when a bounded data-only language is sufficient. Applications should still use the correct output mode for their context. HTML mode is not a complete sanitizer for arbitrary HTML templates and does not make static attacker-controlled markup safe. Do not place untrusted values inside script, style, URL, or event handler contexts without a context-specific encoder in addition to this library.

`text` mode is not a terminal control filter for static template text. The CLI neutralizes its own terminal output, and the renderer removes dangerous characters from interpolated data.

The library is deterministic and offline. It does not perform network lookups. It cannot protect a downstream system that later evaluates the rendered output as another template.

## Examples

Run the examples from a source checkout:

```sh
node examples/audit.mjs
node examples/render-email.mjs
node examples/custom-policy.mjs
```

## License

MIT. See `LICENSE`.

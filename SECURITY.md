# Security policy

## Reporting a vulnerability

Do not open a public issue for a vulnerability. Use a private GitHub Security Advisory on the repository security tab.

Include the smallest template and data input that reproduces the issue, the expected result, the actual result, the Node.js version, and whether the concern is in the auditor, renderer, CLI, packaging, or type declarations.

## Scope

In scope:

- SSTI detection bypasses with a concrete payload
- Renderer access to inherited, getter, function, proxy, or prototype-chain values
- `eval`, `Function`, helper execution, method execution, file inclusion, or partial execution paths
- Output escaping bypasses
- Iteration, nesting, input size, output size, or audit finding bound bypasses
- Prototype pollution caused by library behavior
- Compiled-template integrity bypasses
- CLI input decoding or terminal neutralization failures

Out of scope:

- Vulnerabilities in a third-party template engine not caused by this library
- Static HTML intentionally placed in a template by the application
- Applications that evaluate rendered output again as a template
- Denial of service attacks that require resources outside the documented input and output bounds

## Security model

The auditor is conservative detection. The renderer is the enforcement boundary. The renderer uses no dynamic code execution, no arbitrary method calls, own-property-only lookup, primitive-only output conversion, bounded loops, bounded nesting, and bounded output.

## Supported versions

Only the latest published minor version receives security fixes.

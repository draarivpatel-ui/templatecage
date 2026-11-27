# Contributing

This package is intentionally zero-dependency at runtime. `fast-check` is the only development dependency and is used only for property-based fuzz tests.

## Required checks

Run these before submitting a change:

```sh
npm test
node scripts/build-cjs.mjs --check
node scripts/check-types.mjs
node scripts/cli-smoke.mjs
npm pack --dry-run
```

The test suite must remain deterministic and must not use the network, clocks, randomness, external services, or machine-specific paths.

## Security invariants

- Never introduce `eval`, the `Function` constructor, template helpers, arbitrary method calls, or dynamic property lookup in the renderer.
- Property reads must remain own-property descriptor reads.
- Getters, functions, proxies, and object coercion must not execute attacker-controlled behavior.
- Every input, nesting, iteration, output, and report bound must remain fail-closed.
- The generated CommonJS file is produced by `node scripts/build-cjs.mjs` and must not be edited directly.
- Public API changes require matching `types/index.d.ts` and fixture updates.

## Style

Use plain JavaScript, small iterative routines, ASCII punctuation in documentation, and stable typed error codes. Do not use recursive template parsing or rendering routines.

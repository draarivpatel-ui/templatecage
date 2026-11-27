import test from 'node:test';
import { CODE, compileTemplate, extractTemplateVariables, renderTemplate } from '../src/index.mjs';
import { assert, expectTemplateError } from './helpers.mjs';

const blockedSegments = [
  '__proto__',
  'constructor',
  'prototype',
  'toString',
  'valueOf',
  'hasOwnProperty',
  'isPrototypeOf',
  'propertyIsEnumerable',
  'toLocaleString',
  '__defineGetter__',
  '__lookupGetter__',
  '__defineSetter__',
  '__lookupSetter__',
  '__class__',
  '__dict__',
  '__globals__',
  '__builtins__',
  '__import__',
  '__anything__',
  '__x',
  'x__'
];

for (const segment of blockedSegments) {
  test('compile blocks forbidden path segment ' + segment, () => {
    expectTemplateError(() => compileTemplate('{{ user.' + segment + ' }}'), CODE.PROTOTYPE_ACCESS);
  });
}

for (const segment of blockedSegments.slice(0, 12)) {
  test('compile blocks forbidden first path segment ' + segment, () => {
    expectTemplateError(() => compileTemplate('{{ ' + segment + ' }}'), CODE.PROTOTYPE_ACCESS);
  });
}

test('inherited data property is not visible', () => {
  const prototype = { secret: 'bad' };
  const user = Object.create(prototype);
  assert.equal(renderTemplate('{{ user.secret }}', { user }), '');
});

test('inherited getter is not visible or invoked', () => {
  let invoked = false;
  const prototype = {};
  Object.defineProperty(prototype, 'secret', {
    get() {
      invoked = true;
      return 'bad';
    }
  });
  const user = Object.create(prototype);
  assert.equal(renderTemplate('{{ user.secret }}', { user }), '');
  assert.equal(invoked, false);
});

test('Object prototype pollution is not visible', () => {
  Object.prototype.templatecagePollutionTest = 'bad';
  try {
    assert.equal(renderTemplate('{{ user.templatecagePollutionTest }}', { user: {} }), '');
  } finally {
    delete Object.prototype.templatecagePollutionTest;
  }
});

test('Array prototype pollution is not visible', () => {
  Array.prototype.templatecageArrayPollutionTest = 'bad';
  try {
    assert.equal(renderTemplate('{{ items.templatecageArrayPollutionTest }}', { items: [] }), '');
  } finally {
    delete Array.prototype.templatecageArrayPollutionTest;
  }
});

test('own getter is rejected without invocation', () => {
  let invoked = false;
  const user = {};
  Object.defineProperty(user, 'name', {
    get() {
      invoked = true;
      return 'bad';
    }
  });
  expectTemplateError(() => renderTemplate('{{ user.name }}', { user }), CODE.UNSAFE_VALUE);
  assert.equal(invoked, false);
});

test('nested own getter is rejected without invocation', () => {
  let invoked = false;
  const profile = {};
  Object.defineProperty(profile, 'name', {
    get() {
      invoked = true;
      return 'bad';
    }
  });
  expectTemplateError(() => renderTemplate('{{ user.profile.name }}', { user: { profile } }), CODE.UNSAFE_VALUE);
  assert.equal(invoked, false);
});

test('array element getter is rejected without invocation', () => {
  let invoked = false;
  const items = [0];
  Object.defineProperty(items, '0', {
    get() {
      invoked = true;
      return 'bad';
    }
  });
  expectTemplateError(() => renderTemplate('{{#each items}}{{this}}{{/each}}', { items }), CODE.UNSAFE_VALUE);
  assert.equal(invoked, false);
});

test('array index path getter is rejected without invocation', () => {
  let invoked = false;
  const items = [0];
  Object.defineProperty(items, '0', {
    get() {
      invoked = true;
      return 'bad';
    }
  });
  expectTemplateError(() => renderTemplate('{{ items.0 }}', { items }), CODE.UNSAFE_VALUE);
  assert.equal(invoked, false);
});

test('own function value is rejected without invocation', () => {
  let invoked = false;
  function fn() {
    invoked = true;
    return 'bad';
  }
  expectTemplateError(() => renderTemplate('{{ user.fn }}', { user: { fn } }), CODE.UNSAFE_VALUE);
  assert.equal(invoked, false);
});

test('nested function value is rejected without invocation', () => {
  let invoked = false;
  const user = {
    profile: {
      fn() {
        invoked = true;
        return 'bad';
      }
    }
  };
  expectTemplateError(() => renderTemplate('{{ user.profile.fn }}', { user }), CODE.UNSAFE_VALUE);
  assert.equal(invoked, false);
});

test('object toString is never invoked for interpolation', () => {
  let invoked = false;
  const value = {
    toString() {
      invoked = true;
      return 'bad';
    }
  };
  expectTemplateError(() => renderTemplate('{{ value }}', { value }), CODE.UNSAFE_VALUE);
  assert.equal(invoked, false);
});

test('object valueOf is never invoked for interpolation', () => {
  let invoked = false;
  const value = {
    valueOf() {
      invoked = true;
      return 1;
    }
  };
  expectTemplateError(() => renderTemplate('{{ value }}', { value }), CODE.UNSAFE_VALUE);
  assert.equal(invoked, false);
});

test('proxy root data is rejected before traps run', () => {
  let trapped = false;
  const data = new Proxy({}, {
    getOwnPropertyDescriptor() {
      trapped = true;
      return undefined;
    },
    get() {
      trapped = true;
      return 'bad';
    }
  });
  expectTemplateError(() => renderTemplate('{{ name }}', data), CODE.INVALID_DATA);
  assert.equal(trapped, false);
});

test('nested proxy object is rejected before traps run', () => {
  let trapped = false;
  const user = new Proxy({}, {
    getOwnPropertyDescriptor() {
      trapped = true;
      return undefined;
    },
    get() {
      trapped = true;
      return 'bad';
    }
  });
  expectTemplateError(() => renderTemplate('{{ user.name }}', { user }), CODE.UNSAFE_VALUE);
  assert.equal(trapped, false);
});

test('proxy array is rejected before iteration traps run', () => {
  let trapped = false;
  const items = new Proxy([1], {
    get() {
      trapped = true;
      return undefined;
    }
  });
  expectTemplateError(() => renderTemplate('{{#each items}}x{{/each}}', { items }), CODE.UNSAFE_VALUE);
  assert.equal(trapped, false);
});

test('null prototype data objects render own values', () => {
  const user = Object.create(null);
  user.name = 'Ada';
  assert.equal(renderTemplate('{{ user.name }}', { user }), 'Ada');
});

test('frozen data objects render own values', () => {
  const user = Object.freeze({ name: 'Ada' });
  assert.equal(renderTemplate('{{ user.name }}', { user }), 'Ada');
});

test('own constructor property cannot be read even when data-like', () => {
  const user = Object.create(null);
  user.constructor = 'safe data value';
  expectTemplateError(() => compileTemplate('{{ user.constructor }}'), CODE.PROTOTYPE_ACCESS);
});

test('own toString property cannot be read even when data-like', () => {
  const user = Object.create(null);
  user.toString = 'safe data value';
  expectTemplateError(() => compileTemplate('{{ user.toString }}'), CODE.PROTOTYPE_ACCESS);
});

test('sparse array hole renders as missing value', () => {
  const items = [,];
  assert.equal(renderTemplate('{{#each items}}{{this}}{{/each}}', { items }), '');
});

test('loop metadata cannot escape to prototype properties', () => {
  const items = [1];
  assert.equal(renderTemplate('{{#each items}}{{ @length }}{{/each}}', { items }), '1');
});

const forgedTemplates = [
  ['plain object', {}],
  ['kind only', { kind: 'templatecage-compiled-template' }],
  ['null', null],
  ['string object', new String('{{x}}')],
  ['array', []]
];

for (const [name, forged] of forgedTemplates) {
  test('forged compiled template rejected ' + name, () => {
    expectTemplateError(() => renderTemplate(forged, {}), CODE.TEMPLATE_INTEGRITY);
  });
}

test('copied compiled template shape is rejected', () => {
  const compiled = compileTemplate('Hello {{name}}');
  const copy = {
    kind: compiled.kind,
    policy: compiled.policy,
    inputBytes: compiled.inputBytes,
    instructions: compiled.instructions,
    variables: compiled.variables
  };
  expectTemplateError(() => renderTemplate(copy, { name: 'x' }), CODE.TEMPLATE_INTEGRITY);
});

test('extract variables rejects forged compiled object', () => {
  expectTemplateError(() => extractTemplateVariables({ kind: 'templatecage-compiled-template' }), CODE.TEMPLATE_INTEGRITY);
});

test('compiled template cannot be expanded by mutation', () => {
  const compiled = compileTemplate('Hello');
  assert.throws(() => {
    compiled.instructions.push({ op: 'text', value: 'bad' });
  }, TypeError);
  assert.equal(renderTemplate(compiled, {}), 'Hello');
});

test('nested loop output bomb is capped', () => {
  const rows = Array.from({ length: 20 }, () => 1);
  const template = '{{#each rows}}{{#each rows}}xxxxxxxxxx{{/each}}{{/each}}';
  expectTemplateError(() => renderTemplate(template, { rows }, { maxLoopDepth: 2, maxIterations: 500, maxOutputBytes: 1000 }), CODE.OUTPUT_LIMIT);
});

test('deep nested loop bomb is rejected at compile time', () => {
  const template = '{{#each a}}{{#each b}}{{#each c}}x{{/each}}{{/each}}{{/each}}';
  expectTemplateError(() => compileTemplate(template, { maxLoopDepth: 2 }), CODE.LOOP_TOO_DEEP);
});

for (const depth of [1, 2, 3]) {
  test('loop depth boundary accepted up to policy ' + depth, () => {
    let template = '';
    for (let index = 0; index < depth; index += 1) template += '{{#each a}}';
    template += 'x';
    for (let index = 0; index < depth; index += 1) template += '{{/each}}';
    assert.equal(renderTemplate(template, { a: [1] }, { maxLoopDepth: depth, maxIterations: 10 }), 'x');
  });
}

test('huge static output is capped', () => {
  expectTemplateError(() => renderTemplate('x'.repeat(100), {}, { maxOutputBytes: 10 }), CODE.OUTPUT_LIMIT);
});

test('huge input is rejected before compilation', () => {
  expectTemplateError(() => compileTemplate('x'.repeat(100), { maxBytes: 10 }), CODE.INPUT_TOO_LONG);
});

test('filter argument containing pipe is one literal', () => {
  assert.equal(renderTemplate('{{ value | default:\'a|b\' }}', {}), 'a|b');
});

test('filter argument cannot smuggle executable syntax', () => {
  expectTemplateError(() => compileTemplate('{{ value | default:process.exit() }}'), CODE.UNSAFE_EXPRESSION);
});

test('truncate argument above supported bound is rejected', () => {
  expectTemplateError(() => compileTemplate('{{ value | truncate:100001 }}'), CODE.INVALID_TEMPLATE);
});

test('negative truncate argument is rejected', () => {
  expectTemplateError(() => compileTemplate('{{ value | truncate:-1 }}'), CODE.INVALID_TEMPLATE);
});

test('fractional truncate argument is rejected', () => {
  expectTemplateError(() => compileTemplate('{{ value | truncate:1.5 }}'), CODE.INVALID_TEMPLATE);
});

test('interpolated ANSI escape is removed in html mode', () => {
  const value = 'a' + String.fromCharCode(27) + '[31mb';
  assert.equal(renderTemplate('{{ value }}', { value }), 'a[31mb');
});

test('interpolated unpaired surrogate is removed', () => {
  const value = 'a' + String.fromCharCode(0xd800) + 'b';
  assert.equal(renderTemplate('{{ value }}', { value }), 'ab');
});

test('interpolated bidi override is removed in json mode before serialization', () => {
  const value = 'a' + String.fromCharCode(0x202e) + 'b';
  assert.equal(renderTemplate('{{ value }}', { value }, { mode: 'json' }), '"ab"');
});

test('renderer does not pollute object prototype', () => {
  renderTemplate('{{ user.name }}', { user: { name: 'x' } });
  assert.equal({}.polluted, undefined);
});

test('render data object identity and contents remain unchanged', () => {
  const user = { name: 'Ada' };
  const data = { user };
  renderTemplate('{{ user.name }}', data);
  assert.equal(data.user, user);
  assert.deepEqual(data, { user: { name: 'Ada' } });
});


test('proxy object in conditional is rejected before traps run', () => {
  let trapped = false;
  const value = new Proxy({}, {
    get() {
      trapped = true;
      return undefined;
    }
  });
  expectTemplateError(() => renderTemplate('{{#if value}}yes{{else}}no{{/if}}', { value }), CODE.UNSAFE_VALUE);
  assert.equal(trapped, false);
});

test('conditional getter is rejected without invocation', () => {
  let invoked = false;
  const user = {};
  Object.defineProperty(user, 'ok', {
    get() {
      invoked = true;
      return true;
    }
  });
  expectTemplateError(() => renderTemplate('{{#if user.ok}}x{{/if}}', { user }), CODE.UNSAFE_VALUE);
  assert.equal(invoked, false);
});

test('loop source getter is rejected without invocation', () => {
  let invoked = false;
  const user = {};
  Object.defineProperty(user, 'items', {
    get() {
      invoked = true;
      return [1];
    }
  });
  expectTemplateError(() => renderTemplate('{{#each user.items}}x{{/each}}', { user }), CODE.UNSAFE_VALUE);
  assert.equal(invoked, false);
});

test('conditional object value uses no coercion', () => {
  const value = {
    valueOf() {
      throw new Error('must not run');
    }
  };
  assert.equal(renderTemplate('{{#if value}}yes{{else}}no{{/if}}', { value }), 'yes');
});

test('filter object value is rejected before filter application', () => {
  const value = {
    toString() {
      throw new Error('must not run');
    }
  };
  expectTemplateError(() => renderTemplate('{{ value | upper }}', { value }), CODE.UNSAFE_VALUE);
});

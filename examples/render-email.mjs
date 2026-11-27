import { compileTemplate, renderTemplate } from 'templatecage';

const compiled = compileTemplate('<h1>Hello {{ user.name }}</h1><p>Plan: {{ user.plan | default:\'free\' | upper }}</p>', 'email');

const output = renderTemplate(compiled, {
  user: {
    name: '<Ada Lovelace>'
  }
});

console.log(output);

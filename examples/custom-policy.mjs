import { createTemplatePolicy, extractTemplateVariables, renderTemplate } from 'templatecage';

const policy = createTemplatePolicy({
  policy: 'notification',
  maxOutputBytes: 4096
});

const template = 'Deployment {{ service }} finished for {{ environment | upper }}';
console.log(renderTemplate(template, {
  service: 'api',
  environment: 'production'
}, policy));

console.log(extractTemplateVariables(template, policy).join(','));

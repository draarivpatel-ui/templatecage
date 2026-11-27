import { auditTemplate } from 'templatecage';

const samples = [
  'Hello {{ user.name }}',
  "{{ ''.__class__.__mro__ }}",
  '{% include "secret.txt" %}',
  '{{ user.bio | safe }}'
];

for (const sample of samples) {
  const report = auditTemplate(sample, 'audit');
  console.log(JSON.stringify({
    template: sample,
    safe: report.safe,
    first: report.findings[0] ? report.findings[0].code : null
  }));
}

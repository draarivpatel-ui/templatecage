/* templatecage public API. */

import { CODE, TEMPLATECAGE_ERROR_CODES, TEMPLATECAGE_SEVERITY, TemplateCageError } from './errors.mjs';
import { SAFE_FILTER_NAMES, TEMPLATE_POLICY_PRESETS, createTemplatePolicy, getPolicy } from './policy.mjs';
import { auditTemplate, isSafeTemplate, validateTemplate } from './auditor.mjs';
import { compileTemplate, extractTemplateVariables, renderTemplate } from './renderer.mjs';

export const TEMPLATECAGE_VERSION = '1.0.0';

const templatecage = Object.freeze({
  TEMPLATECAGE_VERSION,
  TEMPLATECAGE_ERROR_CODES,
  TEMPLATECAGE_SEVERITY,
  CODE,
  TemplateCageError,
  SAFE_FILTER_NAMES,
  TEMPLATE_POLICY_PRESETS,
  createTemplatePolicy,
  getPolicy,
  auditTemplate,
  isSafeTemplate,
  validateTemplate,
  compileTemplate,
  renderTemplate,
  extractTemplateVariables
});

export {
  CODE,
  TEMPLATECAGE_ERROR_CODES,
  TEMPLATECAGE_SEVERITY,
  TemplateCageError,
  SAFE_FILTER_NAMES,
  TEMPLATE_POLICY_PRESETS,
  createTemplatePolicy,
  getPolicy,
  auditTemplate,
  isSafeTemplate,
  validateTemplate,
  compileTemplate,
  renderTemplate,
  extractTemplateVariables
};

export default templatecage;

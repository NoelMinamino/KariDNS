// The route table of /api/v1 (planning 4).  Paths are relative to /api/v1.  auth: 'none' needs no credential; the rest needs a session or a token.  preTotp: a
// session that has not done its TOTP step yet may call it.  sessionOnly: a token may not (it would make tokens that make tokens).

import * as auth from './handlers/auth.js';
import * as admin from './handlers/admin.js';
import * as zones from './handlers/zones.js';
import * as write from './handlers/write.js';
import * as versions from './handlers/versions.js';
import * as templates from './handlers/templates.js';
import { IMPORT_MS } from './http.js';
import { ZONE_TEXT_LIMIT as ZIP } from './changes.js';           // a zone text travels in a JSON string: 16 MiB, received within 5 minutes (planning 8.2)

export const ROUTES = [
  { method: 'GET', path: '/health', auth: 'none', handler: zones.health },
  { method: 'GET', path: '/version', handler: zones.version },

  { method: 'POST', path: '/auth/login', auth: 'none', bodyLimit: 16384, handler: auth.login },
  { method: 'POST', path: '/auth/logout', preTotp: true, sessionOnly: true, handler: auth.logout },
  { method: 'GET', path: '/auth/me', preTotp: true, handler: auth.me },
  { method: 'POST', path: '/auth/totp', preTotp: true, sessionOnly: true, handler: auth.totp },
  { method: 'POST', path: '/auth/password', sessionOnly: true, handler: auth.password },

  { method: 'GET', path: '/tokens', handler: auth.tokensList },
  { method: 'POST', path: '/tokens', sessionOnly: true, handler: auth.tokenCreate },
  { method: 'DELETE', path: '/tokens/:id', handler: auth.tokenRevoke },

  { method: 'GET', path: '/principals', handler: admin.principalsList },
  { method: 'POST', path: '/principals', handler: admin.principalCreate },
  { method: 'GET', path: '/principals/:id', handler: admin.principalGet },
  { method: 'PATCH', path: '/principals/:id', handler: admin.principalUpdate },
  { method: 'DELETE', path: '/principals/:id', handler: admin.principalDelete },
  { method: 'PUT', path: '/principals/:id/password', handler: admin.principalPassword },
  { method: 'POST', path: '/principals/:id/credentials', handler: admin.principalCredentials },
  { method: 'GET', path: '/principals/:id/members', handler: admin.membersList },
  { method: 'POST', path: '/principals/:id/members', handler: admin.memberAdd },
  { method: 'DELETE', path: '/principals/:id/members/:mid', handler: admin.memberRemove },

  { method: 'GET', path: '/rr-policies', handler: admin.policiesList },
  { method: 'POST', path: '/rr-policies', handler: admin.policyCreate },
  { method: 'GET', path: '/rr-policies/:id', handler: admin.policyGet },
  { method: 'PATCH', path: '/rr-policies/:id', handler: admin.policyUpdate },
  { method: 'DELETE', path: '/rr-policies/:id', handler: admin.policyDelete },

  { method: 'GET', path: '/grants', handler: admin.grantsList },
  { method: 'POST', path: '/grants', handler: admin.grantCreate },
  { method: 'DELETE', path: '/grants/:id', handler: admin.grantDelete },

  { method: 'GET', path: '/datasets', handler: zones.datasets },
  { method: 'GET', path: '/datasets/:ds/zones', handler: zones.zonesList },
  { method: 'GET', path: '/datasets/:ds/zones/:zone', handler: zones.zoneGet },
  { method: 'GET', path: '/datasets/:ds/zones/:zone/rrsets', handler: zones.rrsetsList },
  { method: 'GET', path: '/datasets/:ds/zones/:zone/export', handler: zones.zoneExport },

  { method: 'POST', path: '/datasets/:ds/zones', bodyLimit: ZIP, readTimeoutMs: IMPORT_MS, handler: write.zoneCreate },
  { method: 'PATCH', path: '/datasets/:ds/zones/:zone', handler: write.zonePatch },
  { method: 'DELETE', path: '/datasets/:ds/zones/:zone', handler: write.zoneDelete },
  { method: 'PATCH', path: '/datasets/:ds/zones/:zone/rrsets', handler: write.rrsetsPatch },
  { method: 'POST', path: '/datasets/:ds/zones/:zone/import', bodyLimit: ZIP, readTimeoutMs: IMPORT_MS, handler: write.importZone },
  { method: 'POST', path: '/datasets/:ds/zones/:zone/reload', handler: write.reloadZone },
  { method: 'POST', path: '/datasets/:ds/reload', handler: write.reloadAll },
  { method: 'GET', path: '/datasets/:ds/zones/:zone/metadata', handler: write.metadataList },
  { method: 'PUT', path: '/datasets/:ds/zones/:zone/metadata/:kind', handler: write.metadataPut },
  { method: 'DELETE', path: '/datasets/:ds/zones/:zone/metadata/:kind', handler: write.metadataDelete },
  { method: 'GET', path: '/datasets/:ds/zones/:zone/dnssec', handler: write.dnssecGet },
  { method: 'POST', path: '/datasets/:ds/zones/:zone/dnssec/requests', handler: write.dnssecRequest },

  { method: 'GET', path: '/datasets/:ds/zones/:zone/versions', handler: versions.list },
  { method: 'GET', path: '/datasets/:ds/zones/:zone/versions/:n', handler: versions.get },
  { method: 'GET', path: '/datasets/:ds/zones/:zone/versions/:n/diff', handler: versions.diff },
  { method: 'POST', path: '/datasets/:ds/zones/:zone/versions/:n/rollback', handler: versions.rollback },
  { method: 'POST', path: '/datasets/:ds/zones/:zone/apply-template', handler: templates.applyTemplate },

  { method: 'GET', path: '/templates', handler: templates.list },
  { method: 'POST', path: '/templates', handler: templates.create },
  { method: 'GET', path: '/templates/:id', handler: templates.get },
  { method: 'PATCH', path: '/templates/:id', handler: templates.update },
  { method: 'DELETE', path: '/templates/:id', handler: templates.remove },
  { method: 'POST', path: '/templates/:id/validate', handler: templates.validate },

  { method: 'GET', path: '/audit', handler: zones.auditList },
  { method: 'GET', path: '/servers', handler: zones.serversList },
];

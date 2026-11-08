// The argv of the programs the API runs (planning 2.1): karidns-zone, karicheck, karictl.  Pure functions: the settings in, an array of words out.  No word is
// built from text that was not validated (zone names: names.js; the principal's name and the comment are checked by the validators of the request), and none
// goes through a shell.

import { canonicalZone } from './names.js';

// the database words of karidns-zone: never the configuration of the server, only what the API's own file says.  PostgreSQL: the CHECK role (it reads a whole
// zone; the API role under row level security sees a part of it for a subdomain master).  The commit run is made with the API's own role ('api').
export function dbArgs(settings, dataset, as = 'check') {
  if (settings.database === 'sqlite3') return ['--no-config', '--sqlite3', settings['sqlite-file']];
  return ['--no-config', '--conninfo-file', settings[as === 'api' ? 'api-conninfo-file' : 'check-conninfo-file'], '--schema', dataset.schema];
}

export const exportArgv = (settings, dataset, zone) => ['export', ...dbArgs(settings, dataset), canonicalZone(zone)];

export const typesArgv = () => ['--types-list', '--json'];

// The source of a run: the change file or a zone text, both on standard input (docs/karidns-zone.md "apply").  create: a new zone of this type.
function sourceArgs({ text, deleteOthers, create, zoneType }) {
  const a = text ? ['--zone-file', '-'] : ['--changes', '-'];
  if (deleteOthers && text && !create) a.push('--delete-others');
  if (create) a.push('--create', '--type', zoneType);
  return a;
}

// The check run: the whole change as a dry run in a trusted session (the check role), at no principal; it prints the generation and the diff and writes nothing.
// spec: { zone, text, deleteOthers, create, zoneType }
export const checkArgv = (settings, dataset, spec) => ['apply', '--dry-run', '--json', ...dbArgs(settings, dataset, 'check'), ...sourceArgs(spec), canonicalZone(spec.zone)];

// The commit run: as the API's role (row level security checks every row again), for the principal and the change set, against the generation the check run saw
// (not for a new zone).  spec adds: generation, principal ({ id, name }), changeSet, kind (the version row), rollbackOf, comment, reload (PostgreSQL: the reload
// request is committed with the data)
export function commitArgv(settings, dataset, spec) {
  const a = ['apply', '--json', ...dbArgs(settings, dataset, 'api'), ...sourceArgs(spec)];
  if (spec.create) a.push('--readback', 'zone');
  else a.push('--expect-generation', String(spec.generation), '--readback', 'changed', '--version-kind', spec.kind ?? 'edit');
  if (spec.rollbackOf) a.push('--rollback-of', String(spec.rollbackOf));
  a.push('--principal', String(spec.principal.id), '--principal-name', spec.principal.name, '--change-set', spec.changeSet);
  if (spec.comment) a.push('--comment', spec.comment);
  if (spec.reload && settings.database === 'pg') a.push('--reload');
  a.push(canonicalZone(spec.zone));
  return a;
}

// karictl with the restricted key of the API (allow-commands { reload-zone; }): its own configuration file; the zone is named, and a zone in views is reloaded
// in each view (karictl: "reload <zone> <view>")
export function reloadArgv(settings, zone, view) {
  return ['-f', settings['karictl-config'], 'reload', canonicalZone(zone), ...(view ? [view] : [])];
}

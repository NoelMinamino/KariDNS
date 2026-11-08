// The argv of the programs the API runs (planning 2.1): karidns-zone, karicheck, karictl.  Pure functions: the settings in, an array of words out.  No word is
// built from text that was not validated (zone names: names.js), and none goes through a shell.

import { canonicalZone } from './names.js';

// the database words of karidns-zone: never the configuration of the server, only what the API's own file says.  PostgreSQL: the CHECK role (it reads a whole
// zone; the API role under row level security sees a part of it for a subdomain master)
export function dbArgs(settings, dataset) {
  if (settings.database === 'sqlite3') return ['--no-config', '--sqlite3', settings['sqlite-file']];
  return ['--no-config', '--conninfo-file', settings['check-conninfo-file'], '--schema', dataset.schema];
}

export const exportArgv = (settings, dataset, zone) => ['export', ...dbArgs(settings, dataset), canonicalZone(zone)];

export const typesArgv = () => ['--types-list', '--json'];

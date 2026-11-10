// The release number of a component: the "version" of its package.json, which `make set-version` (tools/set_version.sh) keeps equal to the file
// VERSION of the source tree and the packages install next to lib/ (docs/RELEASING.md).  Read once, when the module is loaded.

import fs from 'node:fs';

export function packageVersion(url, read = fs.readFileSync) {
  const v = JSON.parse(read(url, 'utf8')).version;
  if (typeof v !== 'string' || !/^\d+\.\d+\.\d+$/.test(v)) throw new Error(`${url}: no version x.y.z in package.json`);
  return v;
}

// The state the handlers share: the configuration (read again on SIGHUP), the datasets, the database, the logger, the rate limiters, the tools and the
// key of the TOTP secrets.  One App per process.

import { Buckets } from './ratelimit.js';
import { hashPassword } from './crypto.js';
import { datasetList } from './config.js';

export const VERSION = '0.6.0';

export class App {
  // config: { settings, datasets }; backend: db.js; log: the logger; run: runChild; key: the Buffer that wraps TOTP secrets
  constructor({ config, backend, log, run, key, now = () => Date.now() }) {
    this.backend = backend;
    this.log = log;
    this.run = run;
    this.key = key;
    this.now = now;
    this.versions = {};                    // filled by the startup checks: the tools' versions, for /version
    this.dummy = null;
    this.pending = new Set();              // background work in flight (a touch of a session), so shutdown can wait for it
    this.healthTimeoutMs = 3000;           // how long /health waits for the database
    this.setConfig(config);
  }

  // (also called on SIGHUP: the settings that are read per request change; the database, the datasets and the listen address do not)
  setConfig(config) {
    this.config = config;
    this.settings = config.settings;
    this.datasets = datasetList(config);
    this.dsByName = new Map(this.datasets.map((d) => [d.name, d]));
    const s = this.settings;
    const old = this.buckets;
    // the counters survive a reload when the rates did not change
    const same = old && old.rates === `${s['rate-login']}/${s['rate-api']}/${s['rate-write']}`;
    this.buckets = same ? old : {
      rates: `${s['rate-login']}/${s['rate-api']}/${s['rate-write']}`,
      loginIp: new Buckets({ rate: s['rate-login'] / 60, burst: s['rate-login'], now: this.now }),
      loginUser: new Buckets({ rate: s['rate-login'] / 60, burst: s['rate-login'], now: this.now }),
      api: new Buckets({ rate: s['rate-api'], burst: s['rate-api'] * 2, now: this.now }),
      write: new Buckets({ rate: s['rate-write'], burst: s['rate-write'] * 2, now: this.now }),
    };
  }

  // a hash that no password matches, computed once at the cost of the real ones: a login for a name that does not exist (or cannot log in) verifies against it, so
  // the time does not tell which names exist
  dummyHash() {
    this.dummy ??= hashPassword('no password is this one', { ln: this.settings['scrypt-ln'] });
    return this.dummy;
  }

  // work that must not delay the response: errors are logged, never thrown
  background(fn) {
    const p = Promise.resolve().then(fn).catch((e) => this.log.warn(`background work failed: ${e.message}`)).finally(() => this.pending.delete(p));
    this.pending.add(p);
  }

  async drain() {
    while (this.pending.size) await Promise.all([...this.pending]);
  }

  dataset(name) {
    return this.dsByName.get(name);
  }

  // the dataset a grant's data_schema belongs to ('' = the SQLite3 file)
  datasetOfSchema(schema) {
    return this.datasets.find((d) => d.schema === schema);
  }
}

// wd.mjs: a small W3C WebDriver client for the browser tests (planning 8.2, F-9): geckodriver started by us, Firefox headless with a fresh profile that does not talk
// to the network, and the few commands the scenarios need, over the global fetch.  No npm package.  Everything the browser writes (profile, downloads, geckodriver's
// log) is inside `dir`.

import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

const ELEMENT = 'element-6066-11e4-a52e-4f735466cecf';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// a profile that makes no request outside the machine (updates, telemetry, safe browsing, captive portal checks, remote settings, prefetch are off)
export const quietPrefs = (downloadDir) => ({
  'app.update.enabled': false, 'app.update.auto': false, 'app.update.checkInstallTime': false,
  'app.normandy.enabled': false, 'browser.shell.checkDefaultBrowser': false, 'browser.startup.page': 0, 'browser.startup.homepage': 'about:blank',
  'browser.newtabpage.enabled': false, 'browser.aboutwelcome.enabled': false, 'startup.homepage_welcome_url': '', 'startup.homepage_welcome_url.additional': '',
  'datareporting.healthreport.uploadEnabled': false, 'datareporting.policy.dataSubmissionEnabled': false, 'toolkit.telemetry.enabled': false,
  'toolkit.telemetry.unified': false, 'toolkit.telemetry.archive.enabled': false, 'toolkit.telemetry.server': 'http://127.0.0.1:9/',
  'browser.safebrowsing.malware.enabled': false, 'browser.safebrowsing.phishing.enabled': false, 'browser.safebrowsing.downloads.enabled': false,
  'browser.safebrowsing.provider.google.updateURL': '', 'browser.safebrowsing.provider.google4.updateURL': '',
  'network.captive-portal-service.enabled': false, 'network.connectivity-service.enabled': false,
  'services.settings.server': 'http://127.0.0.1:9/v1', 'extensions.update.enabled': false, 'extensions.getAddons.cache.enabled': false,
  'browser.region.update.enabled': false, 'browser.search.update': false, 'browser.search.region': 'US', 'browser.urlbar.suggest.searches': false,
  'network.prefetch-next': false, 'network.dns.disablePrefetch': true, 'network.http.speculative-parallel-limit': 0, 'network.predictor.enabled': false,
  'network.proxy.type': 0, 'media.peerconnection.enabled': false, 'dom.webnotifications.enabled': false, 'permissions.default.desktop-notification': 2,
  'browser.contentblocking.report.lockwise.enabled': false, 'browser.discovery.enabled': false, 'extensions.pocket.enabled': false,
  // few processes and little memory (measured on the build host: these cut 8 processes and 3.1 GiB of resident size, shared pages counted once for every process, to 5 and 2.0
  // GiB): one content process for everything, no process for media, graphics, the network or extensions, no preloading, no session history to keep
  'media.rdd-process.enabled': false, 'media.utility-process.enabled': false, 'network.process.enabled': false, 'layers.gpu-process.enabled': false,
  'extensions.webextensions.remote': false, 'browser.tabs.remote.separatePrivilegedContentProcess': false, 'browser.tabs.remote.separatedMozillaDomains': '',
  'dom.ipc.processCount.webIsolated': 1, 'fission.webContentIsolationStrategy': 0, 'gfx.webrender.software': true, 'webgl.disabled': true,
  'browser.startup.preXulSkeletonUI': false, 'browser.urlbar.quicksuggest.enabled': false, 'browser.urlbar.suggest.quicksuggest.nonsponsored': false,
  'browser.urlbar.suggest.quicksuggest.sponsored': false,
  'dom.ipc.processCount': 1, 'dom.ipc.processPrelaunch.fission.number': 0, 'dom.ipc.processPrelaunch.enabled': false, 'browser.sessionstore.max_tabs_undo': 0,
  'browser.sessionhistory.max_total_viewers': 0, 'browser.cache.memory.capacity': 8192, 'browser.cache.disk.enable': false, 'gfx.canvas.accelerated': false,
  'browser.download.folderList': 2, 'browser.download.dir': downloadDir, 'browser.download.useDownloadDir': true, 'browser.download.manager.showWhenStarting': false,
  'browser.helperApps.neverAsk.saveToDisk': 'text/plain,application/octet-stream',
  'intl.accept_languages': 'en-US, en',
});

export class WebDriverError extends Error {
  constructor(status, body) {
    super(`${body?.value?.error ?? 'webdriver error'}: ${String(body?.value?.message ?? '').split('\n')[0]}`);
    this.status = status;
    this.error = body?.value?.error;
  }
}

// The page re-renders under a test (a list that arrives after its form, a view that is redrawn after a save): an element found a moment ago can be gone when it is used
// ("stale element reference").  Run fn again (it finds its elements anew) until it does not hit that, up to 5 s.  Any other error is thrown at once.
export const retryStale = async (fn, tries = 50) => {
  for (let i = 1; ; i++) {
    try { return await fn(); } catch (e) {
      if (e?.error !== 'stale element reference' || i >= tries) throw e;
      await new Promise((r) => setTimeout(r, 100));
    }
  }
};

export class Element {
  constructor(b, id) { this.b = b; this.id = id; }
  cmd(method, p, body) { return this.b.cmd(method, `/element/${this.id}${p}`, body); }
  click() { return this.cmd('POST', '/click', {}); }
  clear() { return this.cmd('POST', '/clear', {}); }
  type(text) { return this.cmd('POST', '/value', { text }); }
  text() { return this.cmd('GET', '/text'); }
  attr(name) { return this.cmd('GET', `/attribute/${name}`); }
  prop(name) { return this.cmd('GET', `/property/${name}`); }
  displayed() { return this.cmd('GET', '/displayed'); }
  enabled() { return this.cmd('GET', '/enabled'); }
  tag() { return this.cmd('GET', '/name'); }
  async $(css) { return this.b.wrap(await this.cmd('POST', '/element', { using: 'css selector', value: css })); }
  async $$(css) { return (await this.cmd('POST', '/elements', { using: 'css selector', value: css })).map((e) => this.b.wrap(e)); }
}

export class Browser {
  constructor(base, sessionId) { this.base = base; this.sid = sessionId; }

  async cmd(method, p, body) {
    const res = await fetch(`${this.base}/session/${this.sid}${p}`, { method, headers: body === undefined ? {} : { 'Content-Type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) });
    const j = await res.json().catch(() => null);
    if (!res.ok) throw new WebDriverError(res.status, j);
    return j?.value;
  }

  wrap(v) { return new Element(this, v[ELEMENT]); }
  get(url) { return this.cmd('POST', '/url', { url }); }
  url() { return this.cmd('GET', '/url'); }
  title() { return this.cmd('GET', '/title'); }
  refresh() { return this.cmd('POST', '/refresh', {}); }
  async $(css) { return this.wrap(await this.cmd('POST', '/element', { using: 'css selector', value: css })); }
  async $$(css) { return (await this.cmd('POST', '/elements', { using: 'css selector', value: css })).map((e) => this.wrap(e)); }
  async exists(css) { return (await this.$$(css)).length > 0; }

  // runs fn(...args) in the page and returns what it returns (JSON); fn is serialized, so it may not use variables of this file
  exec(fn, ...args) { return this.cmd('POST', '/execute/sync', { script: `return (${fn.toString()}).apply(null, arguments)`, args }); }
  // an async function: the page waits for its promise
  execAsync(fn, ...args) {
    return this.cmd('POST', '/execute/async', { script: `const done = arguments[arguments.length - 1]; Promise.resolve((${fn.toString()}).apply(null, Array.prototype.slice.call(arguments, 0, -1))).then(done, (e) => done({ __error: String(e) }))`, args });
  }

  // polls fn() until it returns something truthy (an error in it counts as "not yet"); a timeout is an Error with the message and the last error
  async waitFor(fn, { timeout = 10000, message = 'a condition' } = {}) {
    const end = Date.now() + timeout;
    let last;
    for (;;) {
      try {
        const v = await fn();
        if (v) return v;
      } catch (e) { last = e; }
      if (Date.now() > end) throw new Error(`timeout waiting for ${message}${last ? ` (${last.message})` : ''}`);
      await sleep(100);
    }
  }

  waitCss(css, o = {}) { return this.waitFor(async () => { const e = await this.$(css); return (await e.displayed()) ? e : null; }, { message: `${css} to be shown`, ...o }); }
  waitGone(css, o = {}) { return this.waitFor(async () => !(await this.exists(css)), { message: `${css} to go`, ...o }); }
  waitText(css, re, o = {}) {
    return this.waitFor(async () => { const t = await (await this.$(css)).text(); return re.test(t) ? t : null; }, { message: `${css} to match ${re}`, ...o });
  }

  // key presses on the focused element (Tab, Enter, ...): the W3C actions; names are the Unicode private-use codes of the specification
  async keys(...keys) {
    const actions = keys.flatMap((k) => [{ type: 'keyDown', value: k }, { type: 'keyUp', value: k }]);
    await this.cmd('POST', '/actions', { actions: [{ type: 'key', id: 'kbd', actions }] });
    await this.cmd('DELETE', '/actions');
  }

  async screenshot(file) { fs.writeFileSync(file, Buffer.from(await this.cmd('GET', '/screenshot'), 'base64')); }
  async newTab() { const h = (await this.cmd('POST', '/window/new', { type: 'tab' })).handle; await this.cmd('POST', '/window', { handle: h }); return h; }
  handles() { return this.cmd('GET', '/window/handles'); }
  switchTo(handle) { return this.cmd('POST', '/window', { handle }); }
  closeTab() { return this.cmd('DELETE', '/window'); }
  async quit() { try { await fetch(`${this.base}/session/${this.sid}`, { method: 'DELETE' }); } catch { /* the driver is gone already */ } }
}

export const NAMED_KEYS = { Tab: '', Enter: '', Space: '', Escape: '', ArrowDown: '', ArrowUp: '', Shift: '', Backspace: '' };

// starts geckodriver (path `driver`) and then Firefox (path `firefox`) headless; -> { browser, stop() }.  `dir` holds everything: the driver's log, the profile
// geckodriver makes (TMPDIR), the downloads.
export async function startBrowser({ driver, firefox, dir, port, extraPrefs = {}, width = 1280, height = 900 }) {
  const downloads = path.join(dir, 'downloads');
  const tmp = path.join(dir, 'tmp');
  fs.mkdirSync(downloads, { recursive: true });
  fs.mkdirSync(tmp, { recursive: true });
  const log = fs.openSync(path.join(dir, 'geckodriver.log'), 'a');
  const env = { ...process.env, TMPDIR: tmp, HOME: path.join(dir, 'home'), MOZ_HEADLESS: '1', MOZ_DISABLE_AUTO_SAFE_MODE: '1', MOZ_CRASHREPORTER_DISABLE: '1' };
  fs.mkdirSync(env.HOME, { recursive: true });
  const proc = spawn(driver, ['--port', String(port), '--host', '127.0.0.1', '--binary', firefox, '--marionette-port', '0', '--log', 'warn'], { env, stdio: ['ignore', log, log] });
  const stop = async (browser) => {
    if (browser) await browser.quit();
    proc.kill('SIGTERM');
    await new Promise((r) => { const t = setTimeout(() => { proc.kill('SIGKILL'); r(); }, 3000); proc.once('exit', () => { clearTimeout(t); r(); }); });
    try { fs.closeSync(log); } catch { /* closed */ }
  };
  const base = `http://127.0.0.1:${port}`;
  for (let i = 0; ; i++) {
    try { if ((await fetch(`${base}/status`)).ok) break; } catch { /* not listening yet */ }
    if (i > 100 || proc.exitCode !== null) { await stop(); throw new Error('geckodriver did not start (see geckodriver.log)'); }
    await sleep(100);
  }
  const caps = { browserName: 'firefox', acceptInsecureCerts: false, 'moz:firefoxOptions': { args: ['-headless'], prefs: { ...quietPrefs(downloads), ...extraPrefs } } };
  const res = await fetch(`${base}/session`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ capabilities: { alwaysMatch: caps } }) });
  const j = await res.json();
  if (!res.ok) { await stop(); throw new WebDriverError(res.status, j); }
  const browser = new Browser(base, j.value.sessionId);
  await browser.cmd('POST', '/window/rect', { width, height }).catch(() => {});
  await browser.cmd('POST', '/timeouts', { script: 30000, pageLoad: 30000, implicit: 0 });
  return { browser, downloads, stop: () => stop(browser), pid: proc.pid };
}
